use std::sync::Arc;

use parquet::basic::Compression;
use parquet::column::writer::ColumnWriter;
use parquet::data_type::ByteArray;
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use serde_json::json;

use super::*;

/// A Parquet object with an id, an amount and an optional flag per row,
/// compressed with `compression`.
pub(crate) fn orders(rows: &[(&str, i64, Option<bool>)], compression: Compression) -> Vec<u8> {
    let schema = parse_message_type(
        "message orders { REQUIRED BYTE_ARRAY id (UTF8); REQUIRED INT64 amount; OPTIONAL BOOLEAN paid; }",
    )
    .unwrap();
    let properties = WriterProperties::builder()
        .set_compression(compression)
        .build();
    let mut writer =
        SerializedFileWriter::new(Vec::new(), Arc::new(schema), Arc::new(properties)).unwrap();
    let mut group = writer.next_row_group().unwrap();
    let mut column = group.next_column().unwrap().unwrap();
    if let ColumnWriter::ByteArrayColumnWriter(writer) = column.untyped() {
        let ids: Vec<ByteArray> = rows.iter().map(|row| ByteArray::from(row.0)).collect();
        writer.write_batch(&ids, None, None).unwrap();
    }
    column.close().unwrap();
    let mut column = group.next_column().unwrap().unwrap();
    if let ColumnWriter::Int64ColumnWriter(writer) = column.untyped() {
        let amounts: Vec<i64> = rows.iter().map(|row| row.1).collect();
        writer.write_batch(&amounts, None, None).unwrap();
    }
    column.close().unwrap();
    let mut column = group.next_column().unwrap().unwrap();
    if let ColumnWriter::BoolColumnWriter(writer) = column.untyped() {
        let paid: Vec<bool> = rows.iter().filter_map(|row| row.2).collect();
        let levels: Vec<i16> = rows.iter().map(|row| i16::from(row.2.is_some())).collect();
        writer.write_batch(&paid, Some(&levels), None).unwrap();
    }
    column.close().unwrap();
    group.close().unwrap();
    writer.into_inner().unwrap()
}

#[test]
fn csv_rows_carry_every_column_as_text() {
    let rows = parse(
        Format::Csv,
        "\u{feff}id,note\n1,\"say \"\"hi\"\", ok\"\n2,\n".as_bytes(),
        10,
    )
    .unwrap();
    assert_eq!(
        Value::Array(rows.into_iter().map(Value::Object).collect()),
        json!([{"id": "1", "note": "say \"hi\", ok"}, {"id": "2", "note": ""}])
    );
}

#[test]
fn malformed_csv_is_refused() {
    for (bytes, refusal) in [
        (&b"id,note\n1,\"open"[..], Refusal::Malformed),
        (b"id,note\n1\n", Refusal::Malformed),
        (b"id,id\n1,2\n", Refusal::Malformed),
        (b"id,\n1,2\n", Refusal::Malformed),
        (b"", Refusal::Malformed),
        (b"id\n\xF6\n", Refusal::NotUtf8),
        (b"id\n1\n2\n3\n", Refusal::TooManyRows),
    ] {
        assert_eq!(parse(Format::Csv, bytes, 2), Err(refusal), "{bytes:?}");
    }
}

#[test]
fn parquet_rows_keep_their_types_under_every_enabled_codec() {
    for compression in [
        Compression::UNCOMPRESSED,
        Compression::SNAPPY,
        Compression::LZ4_RAW,
        Compression::GZIP(Default::default()),
    ] {
        let bytes = orders(&[("a", 7, Some(true)), ("b", -1, None)], compression);
        let rows = parse(Format::Parquet, &bytes, 10).unwrap();
        assert_eq!(
            Value::Array(rows.into_iter().map(Value::Object).collect()),
            json!([
                {"id": "a", "amount": 7, "paid": true},
                {"id": "b", "amount": -1, "paid": null},
            ]),
            "{compression:?}"
        );
    }
}

#[test]
fn parquet_past_the_row_cap_or_not_parquet_is_refused() {
    let bytes = orders(&[("a", 1, None), ("b", 2, None)], Compression::SNAPPY);
    assert_eq!(parse(Format::Parquet, &bytes, 1), Err(Refusal::TooManyRows));
    assert_eq!(
        parse(Format::Parquet, &bytes[..bytes.len() - 1], 10),
        Err(Refusal::Malformed)
    );
    assert_eq!(
        parse(Format::Parquet, b"id\n1\n", 10),
        Err(Refusal::Malformed)
    );
}
