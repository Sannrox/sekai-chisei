use crate::store::{ObjectRecord, Store};

pub struct BatchIngest;

impl BatchIngest {
    pub fn run(store: &mut Store, records: Vec<ObjectRecord>) -> Result<(), String> {
        for record in records {
            store.append(record)?;
        }
        Ok(())
    }
}

pub struct StreamIngest {
    pending: Vec<ObjectRecord>,
}

impl StreamIngest {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    pub fn push(&mut self, record: ObjectRecord) -> Result<(), String> {
        self.pending.push(record);
        Ok(())
    }

    pub fn flush_into(&mut self, store: &mut Store) -> Result<(), String> {
        let records = std::mem::take(&mut self.pending);
        BatchIngest::run(store, records)
    }
}

impl Default for StreamIngest {
    fn default() -> Self {
        Self::new()
    }
}
