use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::actions::Action;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectRecord {
    pub generation: u64,
    pub kind: String,
    pub key: String,
    pub hidden: bool,
    pub props: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JoinMaps {
    pub visible_customers: HashSet<String>,
    pub order_customer: HashMap<String, String>,
    pub shipment_order_amount: HashMap<String, (String, i64)>,
}

impl JoinMaps {
    pub fn hop_count(&self) -> usize {
        let mut reachable = HashSet::new();
        for (order_id, _) in self.shipment_order_amount.values() {
            if let Some(customer_id) = self.order_customer.get(order_id) {
                if self.visible_customers.contains(customer_id) {
                    reachable.insert(customer_id.clone());
                }
            }
        }
        reachable.len()
    }

    pub fn sum_amount(&self) -> i64 {
        let mut total = 0i64;
        for (order_id, amount) in self.shipment_order_amount.values() {
            if let Some(customer_id) = self.order_customer.get(order_id) {
                if self.visible_customers.contains(customer_id) {
                    total += amount;
                }
            }
        }
        total
    }
}

pub struct Store {
    log: PathBuf,
    objects: HashMap<(String, String), ObjectRecord>,
    joins: JoinMaps,
}

impl Store {
    pub fn create(log: &Path) -> Result<Self, String> {
        if let Some(parent) = log.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        File::create(log).map_err(|e| e.to_string())?;
        Ok(Self {
            log: log.to_path_buf(),
            objects: HashMap::new(),
            joins: JoinMaps::default(),
        })
    }

    pub fn open(log: &Path) -> Result<Self, String> {
        let mut store = Self {
            log: log.to_path_buf(),
            objects: HashMap::new(),
            joins: JoinMaps::default(),
        };
        let file = File::open(log).map_err(|e| e.to_string())?;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|e| e.to_string())?;
            if line.is_empty() {
                continue;
            }
            let record: ObjectRecord = serde_json::from_str(&line).map_err(|e| e.to_string())?;
            store.apply_record(record);
        }
        Ok(store)
    }

    pub fn apply_record(&mut self, record: ObjectRecord) {
        let id = (record.kind.clone(), record.key.clone());
        if let Some(old) = self.objects.remove(&id) {
            self.unindex(&old);
        }
        self.index(&record);
        self.objects.insert(id, record);
    }

    pub fn append(&mut self, mut record: ObjectRecord) -> Result<(), String> {
        let id = (record.kind.clone(), record.key.clone());
        if let Some(existing) = self.objects.get(&id) {
            record.generation = existing.generation.max(1) + 1;
        } else if record.generation == 0 {
            record.generation = 1;
        }
        self.write_log(&record)?;
        self.apply_record(record);
        Ok(())
    }

    pub fn apply_action(&mut self, action: Action) -> Result<(), String> {
        self.append(ObjectRecord {
            generation: 0,
            kind: action.kind,
            key: action.key,
            hidden: false,
            props: action.props,
        })
    }

    pub fn joins(&self) -> &JoinMaps {
        &self.joins
    }

    pub fn visible_of_kind(&self, kind: &str) -> Vec<&ObjectRecord> {
        self.objects
            .values()
            .filter(|record| record.kind == kind && !record.hidden)
            .collect()
    }

    pub fn replace_kind(&mut self, kind: &str, records: Vec<ObjectRecord>) -> Result<(), String> {
        let keep: Vec<ObjectRecord> = self
            .objects
            .values()
            .filter(|record| record.kind != kind)
            .cloned()
            .collect();
        File::create(&self.log).map_err(|e| e.to_string())?;
        self.objects.clear();
        self.joins = JoinMaps::default();
        for record in keep.into_iter().chain(records) {
            self.append(record)?;
        }
        Ok(())
    }

    fn write_log(&self, record: &ObjectRecord) -> Result<(), String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .map_err(|e| e.to_string())?;
        let mut out = BufWriter::new(file);
        serde_json::to_writer(&mut out, record).map_err(|e| e.to_string())?;
        out.write_all(b"\n").map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())
    }

    fn unindex(&mut self, record: &ObjectRecord) {
        match record.kind.as_str() {
            "Customer" => {
                self.joins.visible_customers.remove(&record.key);
            }
            "Order" => {
                self.joins.order_customer.remove(&record.key);
            }
            "Shipment" => {
                self.joins.shipment_order_amount.remove(&record.key);
            }
            _ => {}
        }
    }

    fn index(&mut self, record: &ObjectRecord) {
        if record.hidden {
            return;
        }
        match record.kind.as_str() {
            "Customer" => {
                self.joins.visible_customers.insert(record.key.clone());
            }
            "Order" => {
                if let Some(customer_id) = record.props.get("customer_id") {
                    self.joins
                        .order_customer
                        .insert(record.key.clone(), customer_id.clone());
                }
            }
            "Shipment" => {
                if let (Some(order_id), Some(amount)) = (
                    record.props.get("order_id"),
                    record.props.get("amount").and_then(|raw| raw.parse().ok()),
                ) {
                    self.joins
                        .shipment_order_amount
                        .insert(record.key.clone(), (order_id.clone(), amount));
                }
            }
            _ => {}
        }
    }
}
