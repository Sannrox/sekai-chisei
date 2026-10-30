//! Write-only UTF-8 Parquet dialect for governed export (#1696).
//!
//! Columns are optional PLAIN `BYTE_ARRAY` (UTF-8). A withheld property is
//! null. Compression, typed columns, and Arrow stay out of this crate so the
//! Apache Parquet library never enters core.

use std::collections::HashMap;

mod read;
mod thrift;
mod write;

pub use read::decode;
pub use thrift::DecodeError;
pub use write::{Encoder, Flush};

pub const MAGIC: [u8; 4] = *b"PAR1";
pub const ROW_GROUP_ROWS: usize = 256;
pub const CREATED_BY: &str = "sekai-parquet-export";

/// One export row. A missing map key is a null cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRow {
    pub id: String,
    pub values: HashMap<String, String>,
}

/// A decoded table: selected columns in order, then the rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub columns: Vec<String>,
    pub id_column: bool,
    pub rows: Vec<ExportRow>,
}

/// Writes `rows` as a complete Parquet file.
pub fn encode(columns: &[String], id_column: bool, rows: &[ExportRow]) -> Vec<u8> {
    let mut encoder = Encoder::new(columns.to_vec(), id_column);
    let mut file = Encoder::header();
    for row in rows {
        if let Some(flush) = encoder.push(&row.id, &row.values) {
            file.extend(flush.bytes);
        }
    }
    file.extend(encoder.finish().bytes);
    file
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::Field;

    fn row(id: &str, values: &[(&str, &str)]) -> ExportRow {
        ExportRow {
            id: id.into(),
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn fixture_round_trips_through_an_independent_reader() {
        let columns = vec!["title".into(), "secret".into()];
        let rows = vec![
            row("t-1", &[("title", "a, \"b\"\nc")]),
            row("t-2", &[("title", "ok"), ("secret", "hidden")]),
        ];
        let file = encode(&columns, true, &rows);
        assert!(file.starts_with(&MAGIC));
        assert!(file.ends_with(&MAGIC));

        let table = decode(&file).expect("dialect reader");
        assert_eq!(table.columns, columns);
        assert!(table.id_column);
        assert_eq!(table.rows[0].id, "t-1");
        assert_eq!(
            table.rows[0].values.get("title").map(String::as_str),
            Some("a, \"b\"\nc")
        );
        assert!(!table.rows[0].values.contains_key("secret"));
        assert_eq!(
            table.rows[1].values.get("secret").map(String::as_str),
            Some("hidden")
        );

        let reader = SerializedFileReader::new(bytes::Bytes::from(file.clone()))
            .expect("independent parquet reader");
        let metadata = reader.metadata().file_metadata();
        assert_eq!(metadata.num_rows(), 2);
        let schema = metadata.schema_descr();
        let names: Vec<&str> = schema
            .columns()
            .iter()
            .map(|column| column.name())
            .collect();
        assert_eq!(names, ["id", "title", "secret"]);
        let iter = reader.get_row_iter(None).expect("row iter");
        let mut independent = Vec::new();
        for row in iter {
            let row = row.expect("row");
            let mut id = String::new();
            let mut values = HashMap::new();
            for (name, field) in row.get_column_iter() {
                let text = match field {
                    Field::Str(text) => Some(text.clone()),
                    Field::Bytes(bytes) => Some(String::from_utf8(bytes.data().to_vec()).unwrap()),
                    Field::Null => None,
                    other => panic!("unexpected {name}: {other:?}"),
                };
                let Some(text) = text else {
                    continue;
                };
                if name == "id" {
                    id = text;
                } else {
                    values.insert(name.clone(), text);
                }
            }
            independent.push(ExportRow { id, values });
        }
        assert_eq!(independent, table.rows);
    }

    #[test]
    fn empty_export_is_still_a_parquet_file() {
        let file = encode(&["title".into()], false, &[]);
        let table = decode(&file).unwrap();
        assert!(table.rows.is_empty());
        SerializedFileReader::new(bytes::Bytes::from(file)).unwrap();
    }

    #[test]
    fn a_full_row_group_of_null_cells_still_decodes() {
        let columns = vec!["secret".into()];
        let rows: Vec<ExportRow> = (0..ROW_GROUP_ROWS)
            .map(|n| row(&format!("r-{n}"), &[]))
            .collect();
        let file = encode(&columns, true, &rows);
        let table = decode(&file).expect("sparse optional column");
        assert_eq!(table.rows.len(), ROW_GROUP_ROWS);
        assert_eq!(table.rows[0].id, "r-0");
        assert!(!table.rows[0].values.contains_key("secret"));
        assert_eq!(
            table.rows[ROW_GROUP_ROWS - 1].id,
            format!("r-{}", ROW_GROUP_ROWS - 1)
        );
        SerializedFileReader::new(bytes::Bytes::from(file)).unwrap();
    }

    #[test]
    fn a_dataset_column_named_id_stays_optional() {
        let columns = vec!["id".into(), "title".into()];
        let rows = vec![row("", &[("id", "user-1"), ("title", "a")])];
        let file = encode(&columns, false, &rows);
        let table = decode(&file).expect("dialect reader");
        assert!(!table.id_column);
        assert_eq!(table.columns, columns);
        assert_eq!(table.rows[0].id, "");
        assert_eq!(
            table.rows[0].values.get("id").map(String::as_str),
            Some("user-1")
        );
        assert_eq!(
            table.rows[0].values.get("title").map(String::as_str),
            Some("a")
        );

        let reader = SerializedFileReader::new(bytes::Bytes::from(file)).unwrap();
        let schema = reader.metadata().file_metadata().schema_descr();
        assert_eq!(schema.column(0).name(), "id");
        assert!(schema.column(0).self_type().is_optional());
    }

    #[test]
    fn row_groups_flush_at_the_export_batch() {
        let columns = vec!["n".into()];
        let rows: Vec<ExportRow> = (0..(ROW_GROUP_ROWS + 3))
            .map(|n| row("", &[("n", &n.to_string())]))
            .collect();
        let file = encode(&columns, false, &rows);
        let table = decode(&file).unwrap();
        assert_eq!(table.rows.len(), ROW_GROUP_ROWS + 3);
        let reader = SerializedFileReader::new(bytes::Bytes::from(file)).unwrap();
        assert_eq!(reader.metadata().num_row_groups(), 2);
    }
}
