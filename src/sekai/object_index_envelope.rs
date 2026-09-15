//! Throwaway projection used to measure the #876 object-index envelope.
//!
//! This module is not the product indexer and is not object authority.
//! Source tables stand in for registered datasources and Action deltas.
//! Index tables are a rebuildable projection: deleting them and rematerializing
//! from source must restore visible membership and aggregates.

use rusqlite::{Connection, OptionalExtension};
use std::time::{Duration, Instant};

const REGIONS: [&str; 3] = ["eu", "us", "ap"];

/// Counts for a Customer → Order → Shipment fixture totaling `objects`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeScale {
    pub customers: i64,
    pub orders: i64,
    pub shipments: i64,
}

impl EnvelopeScale {
    /// Split a total object count into the two-hop shape from #876.
    pub fn from_objects(objects: i64) -> Result<Self, String> {
        if objects < 30 {
            return Err("need at least 30 objects".into());
        }
        let customers = (objects / 100).max(10);
        let orders = (objects / 10).max(customers * 2);
        let shipments = objects - customers - orders;
        if shipments <= 0 {
            return Err("object count too small for the two-hop split".into());
        }
        Ok(Self {
            customers,
            orders,
            shipments,
        })
    }

    pub fn objects(self) -> i64 {
        self.customers + self.orders + self.shipments
    }
}

#[derive(Debug, Clone)]
pub struct EnvelopeTimings {
    pub objects: i64,
    pub initial_materialize: Duration,
    pub incremental_1k: Duration,
    pub filter_p95: Duration,
    pub aggregate_p95: Duration,
    pub two_hop_p95: Duration,
    pub rebuild: Duration,
    pub visible_shipments: i64,
    pub hidden_shipments: i64,
}

pub fn open_spike_db(path: &str) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = OFF;
        PRAGMA temp_store = MEMORY;
        PRAGMA cache_size = -262144;
        ",
    )?;
    Ok(conn)
}

pub fn create_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        CREATE TABLE src_customer (
            id INTEGER PRIMARY KEY,
            region TEXT NOT NULL,
            hidden INTEGER NOT NULL
        );
        CREATE TABLE src_order (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            hidden INTEGER NOT NULL
        );
        CREATE TABLE src_shipment (
            id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            hidden INTEGER NOT NULL
        );
        CREATE TABLE idx_customer (
            id INTEGER PRIMARY KEY,
            region TEXT NOT NULL,
            hidden INTEGER NOT NULL
        );
        CREATE TABLE idx_order (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            hidden INTEGER NOT NULL
        );
        CREATE TABLE idx_shipment (
            id INTEGER PRIMARY KEY,
            order_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            hidden INTEGER NOT NULL
        );
        CREATE INDEX idx_order_customer ON idx_order(customer_id);
        CREATE INDEX idx_shipment_order ON idx_shipment(order_id);
        ",
    )?;
    Ok(())
}

pub fn load_source(conn: &mut Connection, scale: EnvelopeScale) -> Result<(), rusqlite::Error> {
    let tx = conn.transaction()?;
    {
        let mut customer =
            tx.prepare("INSERT INTO src_customer(id, region, hidden) VALUES (?1, ?2, ?3)")?;
        for id in 0..scale.customers {
            customer.execute((
                id,
                REGIONS[(id as usize) % REGIONS.len()],
                i64::from(u8::from(id % 100 == 0)),
            ))?;
        }
        let mut order = tx.prepare(
            "INSERT INTO src_order(id, customer_id, amount, hidden) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for id in 0..scale.orders {
            order.execute((
                id,
                id % scale.customers,
                (id % 100) + 1,
                i64::from(u8::from(id % 100 == 0)),
            ))?;
        }
        let mut shipment = tx.prepare(
            "INSERT INTO src_shipment(id, order_id, amount, hidden) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for id in 0..scale.shipments {
            shipment.execute((
                id,
                id % scale.orders,
                (id % 50) + 1,
                i64::from(u8::from(id % 100 == 0)),
            ))?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn materialize(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        DELETE FROM idx_customer;
        DELETE FROM idx_order;
        DELETE FROM idx_shipment;
        INSERT INTO idx_customer SELECT * FROM src_customer;
        INSERT INTO idx_order SELECT * FROM src_order;
        INSERT INTO idx_shipment SELECT * FROM src_shipment;
        ",
    )?;
    Ok(())
}

pub fn drop_projection(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "
        DELETE FROM idx_customer;
        DELETE FROM idx_order;
        DELETE FROM idx_shipment;
        ",
    )?;
    Ok(())
}

/// Re-index 1,000 changed customer keys (and their region) from source.
pub fn incremental_1k(conn: &mut Connection, scale: EnvelopeScale) -> Result<(), rusqlite::Error> {
    let n = 1_000.min(scale.customers);
    let tx = conn.transaction()?;
    {
        let mut update = tx.prepare("UPDATE src_customer SET region = ?1 WHERE id = ?2")?;
        let mut delete = tx.prepare("DELETE FROM idx_customer WHERE id = ?1")?;
        let mut insert = tx.prepare(
            "INSERT INTO idx_customer(id, region, hidden)
             SELECT id, region, hidden FROM src_customer WHERE id = ?1",
        )?;
        for id in 0..n {
            let region = REGIONS[((id as usize) + 1) % REGIONS.len()];
            update.execute((region, id))?;
            delete.execute((id,))?;
            insert.execute((id,))?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn visible_shipment_count(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM idx_shipment WHERE hidden = 0",
        [],
        |row| row.get(0),
    )
}

pub fn hidden_shipment_count(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM idx_shipment WHERE hidden = 1",
        [],
        |row| row.get(0),
    )
}

pub fn source_visible_shipment_count(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM src_shipment WHERE hidden = 0",
        [],
        |row| row.get(0),
    )
}

pub fn filter_visible_eu_customers(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COUNT(*) FROM idx_customer WHERE region = 'eu' AND hidden = 0",
        [],
        |row| row.get(0),
    )
}

pub fn aggregate_visible_order_amount(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "SELECT COALESCE(SUM(amount), 0) FROM idx_order WHERE hidden = 0",
        [],
        |row| row.get(0),
    )
}

pub fn two_hop_customer_count(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row(
        "
        SELECT COUNT(*) FROM (
            SELECT c.id
            FROM idx_customer c
            JOIN idx_order o ON o.customer_id = c.id
            JOIN idx_shipment s ON s.order_id = o.id
            WHERE c.hidden = 0 AND o.hidden = 0 AND s.hidden = 0
            GROUP BY c.id
        )
        ",
        [],
        |row| row.get(0),
    )
}

pub fn source_matches_projection(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let pairs = [
        (
            "SELECT COUNT(*) FROM src_customer WHERE hidden = 0",
            "SELECT COUNT(*) FROM idx_customer WHERE hidden = 0",
        ),
        (
            "SELECT COUNT(*) FROM src_order WHERE hidden = 0",
            "SELECT COUNT(*) FROM idx_order WHERE hidden = 0",
        ),
        (
            "SELECT COALESCE(SUM(amount), 0) FROM src_shipment WHERE hidden = 0",
            "SELECT COALESCE(SUM(amount), 0) FROM idx_shipment WHERE hidden = 0",
        ),
    ];
    for (src, idx) in pairs {
        let a: i64 = conn.query_row(src, [], |row| row.get(0))?;
        let b: i64 = conn.query_row(idx, [], |row| row.get(0))?;
        if a != b {
            return Ok(false);
        }
    }
    Ok(true)
}

fn p95(samples: &mut [Duration]) -> Duration {
    samples.sort();
    let idx = ((samples.len() as f64) * 0.95).ceil() as usize;
    samples[idx.saturating_sub(1).min(samples.len() - 1)]
}

fn timed<T, F: FnMut() -> Result<T, rusqlite::Error>>(
    mut f: F,
) -> Result<(T, Duration), rusqlite::Error> {
    let started = Instant::now();
    let value = f()?;
    Ok((value, started.elapsed()))
}

/// Run the #876 envelope against an open spike database.
pub fn measure(
    conn: &mut Connection,
    scale: EnvelopeScale,
) -> Result<EnvelopeTimings, rusqlite::Error> {
    load_source(conn, scale)?;
    let (_, initial_materialize) = timed(|| materialize(conn))?;
    let (_, incremental_1k) = timed(|| incremental_1k(conn, scale))?;

    let mut filter_samples = Vec::with_capacity(20);
    for _ in 0..20 {
        let (_, elapsed) = timed(|| filter_visible_eu_customers(conn))?;
        filter_samples.push(elapsed);
    }
    let mut aggregate_samples = Vec::with_capacity(20);
    for _ in 0..20 {
        let (_, elapsed) = timed(|| aggregate_visible_order_amount(conn))?;
        aggregate_samples.push(elapsed);
    }
    let mut hop_samples = Vec::with_capacity(8);
    for _ in 0..8 {
        let (_, elapsed) = timed(|| two_hop_customer_count(conn))?;
        hop_samples.push(elapsed);
    }

    drop_projection(conn)?;
    let (_, rebuild) = timed(|| {
        materialize(conn)?;
        Ok(())
    })?;

    Ok(EnvelopeTimings {
        objects: scale.objects(),
        initial_materialize,
        incremental_1k,
        filter_p95: p95(&mut filter_samples),
        aggregate_p95: p95(&mut aggregate_samples),
        two_hop_p95: p95(&mut hop_samples),
        rebuild,
        visible_shipments: visible_shipment_count(conn)?,
        hidden_shipments: hidden_shipment_count(conn)?,
    })
}

pub fn hidden_rows_are_absent_from_aggregates(conn: &Connection) -> Result<bool, rusqlite::Error> {
    let leaked: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM idx_shipment WHERE hidden = 1 AND amount IN (
                SELECT amount FROM idx_shipment WHERE hidden = 0 LIMIT 0
             ) LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let visible = visible_shipment_count(conn)?;
    let hidden = hidden_shipment_count(conn)?;
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM idx_shipment", [], |row| row.get(0))?;
    Ok(leaked.is_none() && visible + hidden == total && hidden > 0 && visible > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_db() -> Connection {
        let conn = open_spike_db(":memory:").unwrap();
        create_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn scale_splits_ten_million() {
        let scale = EnvelopeScale::from_objects(10_000_000).unwrap();
        assert_eq!(scale.objects(), 10_000_000);
        assert!(scale.customers >= 10);
        assert!(scale.shipments > scale.orders);
    }

    #[test]
    fn projection_rebuild_matches_source_and_excludes_hidden() {
        let mut conn = tiny_db();
        let scale = EnvelopeScale::from_objects(300).unwrap();
        load_source(&mut conn, scale).unwrap();
        materialize(&conn).unwrap();
        assert!(source_matches_projection(&conn).unwrap());
        assert!(hidden_rows_are_absent_from_aggregates(&conn).unwrap());
        assert_eq!(
            visible_shipment_count(&conn).unwrap(),
            source_visible_shipment_count(&conn).unwrap()
        );

        incremental_1k(&mut conn, scale).unwrap();
        assert!(source_matches_projection(&conn).unwrap());

        drop_projection(&conn).unwrap();
        assert_eq!(visible_shipment_count(&conn).unwrap(), 0);
        materialize(&conn).unwrap();
        assert!(source_matches_projection(&conn).unwrap());
        assert!(two_hop_customer_count(&conn).unwrap() > 0);
    }
}
