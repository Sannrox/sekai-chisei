//! PLAIN optional-UTF8 row groups and the Parquet footer.

use std::collections::HashMap;

use crate::thrift::{CompactWriter, T_BIN, T_I32, T_STRUCT};
use crate::{CREATED_BY, MAGIC, ROW_GROUP_ROWS};

const TYPE_BYTE_ARRAY: i32 = 6;
const REPETITION_REQUIRED: i32 = 0;
const REPETITION_OPTIONAL: i32 = 1;
const CONVERTED_UTF8: i32 = 0;
const ENCODING_PLAIN: i32 = 0;
const ENCODING_RLE: i32 = 3;
const CODEC_UNCOMPRESSED: i32 = 0;
const PAGE_DATA: i32 = 0;

/// Bytes flushed from the encoder, with the number of rows they contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flush {
    pub bytes: Vec<u8>,
    pub rows: u64,
}

pub struct Encoder {
    columns: Vec<String>,
    id_column: bool,
    offset: u64,
    buffered: Vec<Vec<Option<String>>>,
    groups: Vec<RowGroupMeta>,
    total_rows: i64,
}

struct RowGroupMeta {
    num_rows: i64,
    total_byte_size: i64,
    columns: Vec<ColumnMeta>,
}

struct ColumnMeta {
    file_offset: i64,
    num_values: i64,
    size: i64,
    data_page_offset: i64,
}

impl Encoder {
    pub fn new(columns: Vec<String>, id_column: bool) -> Self {
        Self {
            columns,
            id_column,
            offset: MAGIC.len() as u64,
            buffered: Vec::with_capacity(ROW_GROUP_ROWS),
            groups: Vec::new(),
            total_rows: 0,
        }
    }

    pub fn header() -> Vec<u8> {
        MAGIC.to_vec()
    }

    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    pub fn id_column(&self) -> bool {
        self.id_column
    }

    pub fn push(&mut self, id: &str, values: &HashMap<String, String>) -> Option<Flush> {
        self.buffered.push(self.cells(id, values));
        if self.buffered.len() == ROW_GROUP_ROWS {
            let rows = self.buffered.len() as u64;
            Some(Flush {
                bytes: self.flush_group(),
                rows,
            })
        } else {
            None
        }
    }

    pub fn finish(&mut self) -> Flush {
        let rows = self.buffered.len() as u64;
        let mut bytes = if rows == 0 {
            Vec::new()
        } else {
            self.flush_group()
        };
        bytes.extend(self.footer());
        Flush { bytes, rows }
    }

    fn cells(&self, id: &str, values: &HashMap<String, String>) -> Vec<Option<String>> {
        let mut cells = Vec::with_capacity(self.columns.len() + usize::from(self.id_column));
        if self.id_column {
            cells.push(Some(id.to_string()));
        }
        for column in &self.columns {
            cells.push(values.get(column).cloned());
        }
        cells
    }

    fn flush_group(&mut self) -> Vec<u8> {
        let rows = std::mem::take(&mut self.buffered);
        let num_rows = rows.len() as i64;
        let mut bytes = Vec::new();
        let mut columns = Vec::new();
        let width = self.columns.len() + usize::from(self.id_column);
        for index in 0..width {
            let required = self.id_column && index == 0;
            let values: Vec<Option<&[u8]>> = rows
                .iter()
                .map(|row| row[index].as_deref().map(str::as_bytes))
                .collect();
            let chunk = encode_column(&values, required);
            let file_offset = (self.offset + bytes.len() as u64) as i64;
            columns.push(ColumnMeta {
                file_offset,
                num_values: num_rows,
                size: chunk.len() as i64,
                data_page_offset: file_offset,
            });
            bytes.extend(chunk);
        }
        self.offset += bytes.len() as u64;
        self.total_rows += num_rows;
        self.groups.push(RowGroupMeta {
            num_rows,
            total_byte_size: bytes.len() as i64,
            columns,
        });
        bytes
    }

    fn footer(&self) -> Vec<u8> {
        let names = self.schema_names();
        let metadata = write_file_metadata(&names, self.id_column, self.total_rows, &self.groups);
        let mut footer = metadata;
        footer.extend((footer.len() as u32).to_le_bytes());
        footer.extend(MAGIC);
        footer
    }

    fn schema_names(&self) -> Vec<String> {
        let mut names = Vec::with_capacity(self.columns.len() + usize::from(self.id_column));
        if self.id_column {
            names.push("id".into());
        }
        names.extend(self.columns.iter().cloned());
        names
    }
}

fn write_file_metadata(
    names: &[String],
    id_column: bool,
    total_rows: i64,
    groups: &[RowGroupMeta],
) -> Vec<u8> {
    let mut meta = CompactWriter::new();
    meta.begin_struct();
    meta.write_i32_field(1, 1);
    meta.begin_list_field(2, T_STRUCT, names.len() + 1);
    meta.begin_struct();
    meta.write_i32_field(3, REPETITION_REQUIRED);
    meta.write_str_field(4, "schema");
    meta.write_i32_field(5, names.len() as i32);
    meta.end_struct();
    for (index, name) in names.iter().enumerate() {
        meta.begin_struct();
        meta.write_i32_field(1, TYPE_BYTE_ARRAY);
        meta.write_i32_field(
            3,
            if id_column && index == 0 {
                REPETITION_REQUIRED
            } else {
                REPETITION_OPTIONAL
            },
        );
        meta.write_str_field(4, name);
        meta.write_i32_field(6, CONVERTED_UTF8);
        meta.end_struct();
    }
    meta.write_i64_field(3, total_rows);
    meta.begin_list_field(4, T_STRUCT, groups.len());
    for group in groups {
        meta.begin_struct();
        meta.begin_list_field(1, T_STRUCT, group.columns.len());
        for (index, column) in group.columns.iter().enumerate() {
            meta.begin_struct();
            meta.write_i64_field(2, column.file_offset);
            meta.write_struct_field(3, |w| {
                w.write_i32_field(1, TYPE_BYTE_ARRAY);
                w.begin_list_field(2, T_I32, 2);
                write_list_i32(w, ENCODING_RLE);
                write_list_i32(w, ENCODING_PLAIN);
                w.write_list_field(3, T_BIN, 1, |w| {
                    let name = names[index].as_bytes();
                    crate::thrift::write_varint(&mut w.buf, name.len() as u64);
                    w.buf.extend_from_slice(name);
                });
                w.write_i32_field(4, CODEC_UNCOMPRESSED);
                w.write_i64_field(5, column.num_values);
                w.write_i64_field(6, column.size);
                w.write_i64_field(7, column.size);
                w.write_i64_field(9, column.data_page_offset);
            });
            meta.end_struct();
        }
        meta.write_i64_field(2, group.total_byte_size);
        meta.write_i64_field(3, group.num_rows);
        meta.end_struct();
    }
    meta.write_str_field(6, CREATED_BY);
    meta.end_struct();
    meta.buf
}

fn write_list_i32(w: &mut CompactWriter, value: i32) {
    crate::thrift::write_varint(&mut w.buf, ((value << 1) ^ (value >> 31)) as u32 as u64);
}

fn encode_column(values: &[Option<&[u8]>], required: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if !required {
        body.extend(encode_definition_levels(values));
    }
    for value in values.iter().flatten() {
        body.extend((value.len() as u32).to_le_bytes());
        body.extend_from_slice(value);
    }
    let mut page = page_header(values.len() as i32, body.len() as i32);
    page.extend(body);
    page
}

fn encode_definition_levels(values: &[Option<&[u8]>]) -> Vec<u8> {
    let levels: Vec<u8> = values
        .iter()
        .map(|value| u8::from(value.is_some()))
        .collect();
    if levels.is_empty() {
        return (0u32).to_le_bytes().to_vec();
    }
    if levels.iter().all(|level| *level == levels[0]) {
        return rle_run(levels.len() as u64, levels[0]);
    }
    bitpack_run(&levels)
}

fn rle_run(count: u64, value: u8) -> Vec<u8> {
    let mut body = Vec::new();
    crate::thrift::write_varint(&mut body, count << 1);
    body.push(value);
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

fn bitpack_run(levels: &[u8]) -> Vec<u8> {
    let groups = levels.len().div_ceil(8);
    let mut body = Vec::new();
    crate::thrift::write_varint(&mut body, ((groups as u64) << 1) | 1);
    for group in 0..groups {
        let mut byte = 0u8;
        for bit in 0..8 {
            let index = group * 8 + bit;
            if index < levels.len() && levels[index] != 0 {
                byte |= 1 << bit;
            }
        }
        body.push(byte);
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend((body.len() as u32).to_le_bytes());
    out.extend(body);
    out
}

fn page_header(num_values: i32, body_len: i32) -> Vec<u8> {
    let mut header = CompactWriter::new();
    header.begin_struct();
    header.write_i32_field(1, PAGE_DATA);
    header.write_i32_field(2, body_len);
    header.write_i32_field(3, body_len);
    header.write_struct_field(5, |w| {
        w.write_i32_field(1, num_values);
        w.write_i32_field(2, ENCODING_PLAIN);
        w.write_i32_field(3, ENCODING_RLE);
        w.write_i32_field(4, ENCODING_RLE);
    });
    header.end_struct();
    header.buf
}
