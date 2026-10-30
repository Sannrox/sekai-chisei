//! Dialect reader for files this crate writes.

use std::collections::HashMap;

use crate::thrift::{CompactReader, DecodeError, T_BIN, T_I32, T_I64, T_LIST, T_STRUCT};
use crate::{MAGIC, Table};

struct FileMeta {
    leaves: Vec<Leaf>,
    groups: Vec<RowGroup>,
}

struct Leaf {
    name: String,
    required: bool,
}

struct RowGroup {
    num_rows: i64,
    columns: Vec<ColumnChunk>,
}

struct ColumnChunk {
    data_page_offset: i64,
    num_values: i64,
}

pub fn decode(bytes: &[u8]) -> Result<Table, DecodeError> {
    if bytes.len() < 12 || bytes.get(..4) != Some(&MAGIC[..]) || !bytes.ends_with(&MAGIC) {
        return Err(DecodeError("not a parquet file"));
    }
    let len_at = bytes.len() - 8;
    let meta_len = u32::from_le_bytes(bytes[len_at..len_at + 4].try_into().unwrap()) as usize;
    let meta_start = len_at
        .checked_sub(meta_len)
        .ok_or(DecodeError("truncated footer"))?;
    if meta_start < 4 {
        return Err(DecodeError("truncated footer"));
    }
    let meta = parse_file_metadata(&bytes[meta_start..len_at])?;
    let id_column = meta
        .leaves
        .first()
        .is_some_and(|leaf| leaf.name == "id" && leaf.required);
    let mut rows = Vec::new();
    for group in &meta.groups {
        let num_rows = bound_count(group.num_rows, count_cap(bytes.len()))?;
        if group.columns.len() != meta.leaves.len() {
            return Err(DecodeError("column count"));
        }
        let mut columns: Vec<Vec<Option<String>>> = Vec::new();
        for (index, chunk) in group.columns.iter().enumerate() {
            let offset =
                usize::try_from(chunk.data_page_offset).map_err(|_| DecodeError("page offset"))?;
            let page = bytes.get(offset..).ok_or(DecodeError("page offset"))?;
            let num_values = bound_count(chunk.num_values, count_cap(bytes.len()))?;
            if num_values != num_rows {
                return Err(DecodeError("page row count"));
            }
            columns.push(read_column(page, num_values, meta.leaves[index].required)?);
        }
        for row_index in 0..num_rows {
            let mut id = String::new();
            let mut values = HashMap::new();
            for (col_index, leaf) in meta.leaves.iter().enumerate() {
                let cell = columns
                    .get(col_index)
                    .and_then(|column| column.get(row_index))
                    .cloned()
                    .flatten();
                if id_column && col_index == 0 {
                    id = cell.clone().unwrap_or_default();
                    continue;
                }
                if let Some(value) = cell {
                    values.insert(leaf.name.clone(), value);
                }
            }
            rows.push(crate::ExportRow { id, values });
        }
    }
    Ok(Table {
        columns: if id_column {
            meta.leaves
                .into_iter()
                .skip(1)
                .map(|leaf| leaf.name)
                .collect()
        } else {
            meta.leaves.into_iter().map(|leaf| leaf.name).collect()
        },
        id_column,
        rows,
    })
}

fn bound_count(claimed: i64, cap: usize) -> Result<usize, DecodeError> {
    let n = usize::try_from(claimed).map_err(|_| DecodeError("count exceeds input"))?;
    if n > cap {
        Err(DecodeError("count exceeds input"))
    } else {
        Ok(n)
    }
}

/// Sparse optional pages can store more rows than they have bytes. Eight times
/// the sample is enough for this dialect and still bounds TraceExport.
fn count_cap(input_len: usize) -> usize {
    input_len.saturating_mul(8)
}

fn parse_file_metadata(bytes: &[u8]) -> Result<FileMeta, DecodeError> {
    let mut reader = CompactReader::new(bytes);
    reader.begin_struct();
    let mut leaves = Vec::new();
    let mut groups = Vec::new();
    while let Some((id, ty)) = reader.next_field()? {
        match (id, ty) {
            (2, T_LIST) => {
                let (elem, len) = reader.read_list_header()?;
                if elem != T_STRUCT {
                    return Err(DecodeError("schema list"));
                }
                for index in 0..len {
                    reader.begin_struct();
                    let mut name = String::new();
                    let mut required = false;
                    let mut saw_repetition = false;
                    while let Some((field, field_ty)) = reader.next_field()? {
                        match (field, field_ty) {
                            (3, T_I32) => {
                                required = reader.read_i32()? == 0;
                                saw_repetition = true;
                            }
                            (4, T_BIN) => name = reader.read_str()?.to_string(),
                            (_, field_ty) => reader.skip_value(field_ty)?,
                        }
                    }
                    reader.end_struct()?;
                    if index > 0 {
                        if !saw_repetition {
                            return Err(DecodeError("schema repetition"));
                        }
                        leaves.push(Leaf { name, required });
                    }
                }
            }
            (4, T_LIST) => {
                let (elem, len) = reader.read_list_header()?;
                if elem != T_STRUCT {
                    return Err(DecodeError("row group list"));
                }
                for _ in 0..len {
                    groups.push(parse_row_group(&mut reader)?);
                }
            }
            (_, ty) => reader.skip_value(ty)?,
        }
    }
    reader.end_struct()?;
    Ok(FileMeta { leaves, groups })
}

fn parse_row_group(reader: &mut CompactReader<'_>) -> Result<RowGroup, DecodeError> {
    reader.begin_struct();
    let mut columns = Vec::new();
    let mut num_rows = 0i64;
    while let Some((id, ty)) = reader.next_field()? {
        match (id, ty) {
            (1, T_LIST) => {
                let (elem, len) = reader.read_list_header()?;
                if elem != T_STRUCT {
                    return Err(DecodeError("column list"));
                }
                for _ in 0..len {
                    columns.push(parse_column_chunk(reader)?);
                }
            }
            (3, T_I64) => num_rows = reader.read_i64()?,
            (_, ty) => reader.skip_value(ty)?,
        }
    }
    reader.end_struct()?;
    Ok(RowGroup { num_rows, columns })
}

fn parse_column_chunk(reader: &mut CompactReader<'_>) -> Result<ColumnChunk, DecodeError> {
    reader.begin_struct();
    let mut data_page_offset = 0i64;
    let mut num_values = 0i64;
    while let Some((id, ty)) = reader.next_field()? {
        match (id, ty) {
            (3, T_STRUCT) => {
                reader.begin_struct();
                while let Some((field, field_ty)) = reader.next_field()? {
                    match (field, field_ty) {
                        (5, T_I64) => num_values = reader.read_i64()?,
                        (9, T_I64) => data_page_offset = reader.read_i64()?,
                        (_, field_ty) => reader.skip_value(field_ty)?,
                    }
                }
                reader.end_struct()?;
            }
            (_, ty) => reader.skip_value(ty)?,
        }
    }
    reader.end_struct()?;
    Ok(ColumnChunk {
        data_page_offset,
        num_values,
    })
}

fn read_column(
    bytes: &[u8],
    num_values: usize,
    required: bool,
) -> Result<Vec<Option<String>>, DecodeError> {
    let mut reader = CompactReader::new(bytes);
    reader.begin_struct();
    let mut body_len = 0i32;
    let mut values = 0i32;
    while let Some((id, ty)) = reader.next_field()? {
        match (id, ty) {
            (2, T_I32) | (3, T_I32) => body_len = reader.read_i32()?,
            (5, T_STRUCT) => {
                reader.begin_struct();
                while let Some((field, field_ty)) = reader.next_field()? {
                    if field == 1 && field_ty == T_I32 {
                        values = reader.read_i32()?;
                    } else {
                        reader.skip_value(field_ty)?;
                    }
                }
                reader.end_struct()?;
            }
            (_, ty) => reader.skip_value(ty)?,
        }
    }
    reader.end_struct()?;
    if bound_count(i64::from(values), count_cap(bytes.len()))? != num_values {
        return Err(DecodeError("page row count"));
    }
    let header_len = reader.position();
    let body_len = bound_count(i64::from(body_len), bytes.len().saturating_sub(header_len))?;
    let body = bytes
        .get(header_len..header_len + body_len)
        .ok_or(DecodeError("page body"))?;
    decode_page_body(body, num_values, required)
}

fn decode_page_body(
    body: &[u8],
    num_values: usize,
    required: bool,
) -> Result<Vec<Option<String>>, DecodeError> {
    let (present, mut rest) = if required {
        (vec![true; num_values], body)
    } else {
        let (levels, rest) = read_definition_levels(body, num_values)?;
        (levels, rest)
    };
    let mut cells = Vec::with_capacity(num_values);
    for is_present in present {
        if !is_present {
            cells.push(None);
            continue;
        }
        let len_bytes = rest.get(..4).ok_or(DecodeError("value length"))?;
        let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        rest = rest.get(4..).ok_or(DecodeError("value length"))?;
        let data = rest.get(..len).ok_or(DecodeError("value bytes"))?;
        rest = rest.get(len..).ok_or(DecodeError("value bytes"))?;
        cells.push(Some(
            std::str::from_utf8(data)
                .map_err(|_| DecodeError("value is not utf-8"))?
                .to_string(),
        ));
    }
    Ok(cells)
}

fn read_definition_levels(
    body: &[u8],
    num_values: usize,
) -> Result<(Vec<bool>, &[u8]), DecodeError> {
    let len = u32::from_le_bytes(
        body.get(..4)
            .ok_or(DecodeError("level length"))?
            .try_into()
            .unwrap(),
    ) as usize;
    if len > body.len().saturating_sub(4) {
        return Err(DecodeError("count exceeds input"));
    }
    let encoded = body.get(4..4 + len).ok_or(DecodeError("level bytes"))?;
    let rest = body.get(4 + len..).ok_or(DecodeError("level bytes"))?;
    Ok((decode_levels(encoded, num_values)?, rest))
}

fn decode_levels(mut encoded: &[u8], num_values: usize) -> Result<Vec<bool>, DecodeError> {
    let mut levels = Vec::with_capacity(num_values);
    while levels.len() < num_values {
        let (header, next) = read_uleb128(encoded)?;
        encoded = next;
        if header & 1 == 0 {
            let count = (header >> 1) as usize;
            let value = *encoded.first().ok_or(DecodeError("rle value"))?;
            encoded = &encoded[1..];
            for _ in 0..count {
                if levels.len() == num_values {
                    break;
                }
                levels.push(value != 0);
            }
        } else {
            let groups = (header >> 1) as usize;
            for _ in 0..groups {
                let byte = *encoded.first().ok_or(DecodeError("bitpack"))?;
                encoded = &encoded[1..];
                for bit in 0..8 {
                    if levels.len() == num_values {
                        break;
                    }
                    levels.push(byte & (1 << bit) != 0);
                }
            }
        }
    }
    Ok(levels)
}

fn read_uleb128(data: &[u8]) -> Result<(u64, &[u8]), DecodeError> {
    let mut result = 0u64;
    let mut shift = 0;
    for (index, byte) in data.iter().copied().enumerate() {
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((result, &data[index + 1..]));
        }
        shift += 7;
        if shift > 63 {
            return Err(DecodeError("varint overflow"));
        }
    }
    Err(DecodeError("truncated varint"))
}
