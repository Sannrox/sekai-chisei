//! Thrift compact protocol, only the subset Parquet footers and page headers use.

pub const T_STOP: u8 = 0;
pub const T_TRUE: u8 = 1;
pub const T_FALSE: u8 = 2;
pub const T_I8: u8 = 3;
pub const T_I16: u8 = 4;
pub const T_I32: u8 = 5;
pub const T_I64: u8 = 6;
pub const T_DOUBLE: u8 = 7;
pub const T_BIN: u8 = 8;
pub const T_LIST: u8 = 9;
pub const T_SET: u8 = 10;
pub const T_MAP: u8 = 11;
pub const T_STRUCT: u8 = 12;

pub struct CompactWriter {
    pub buf: Vec<u8>,
    last_id: i16,
    stack: Vec<i16>,
}

impl CompactWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            last_id: 0,
            stack: Vec::new(),
        }
    }

    pub fn begin_struct(&mut self) {
        self.stack.push(self.last_id);
        self.last_id = 0;
    }

    pub fn end_struct(&mut self) {
        self.buf.push(T_STOP);
        self.last_id = self.stack.pop().unwrap_or(0);
    }

    fn field_header(&mut self, id: i16, ty: u8) {
        let delta = id - self.last_id;
        if (1..=14).contains(&delta) {
            self.buf.push(((delta as u8) << 4) | ty);
        } else {
            self.buf.push(ty);
            write_varint(&mut self.buf, zigzag_i16(id));
        }
        self.last_id = id;
    }

    pub fn write_i32_field(&mut self, id: i16, value: i32) {
        self.field_header(id, T_I32);
        write_varint(&mut self.buf, zigzag_i32(value));
    }

    pub fn write_i64_field(&mut self, id: i16, value: i64) {
        self.field_header(id, T_I64);
        write_varint(&mut self.buf, zigzag_i64(value));
    }

    pub fn write_bin_field(&mut self, id: i16, bytes: &[u8]) {
        self.field_header(id, T_BIN);
        write_varint(&mut self.buf, bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_str_field(&mut self, id: i16, value: &str) {
        self.write_bin_field(id, value.as_bytes());
    }

    pub fn begin_list_field(&mut self, id: i16, elem: u8, len: usize) {
        self.field_header(id, T_LIST);
        if len <= 14 {
            self.buf.push(((len as u8) << 4) | elem);
        } else {
            self.buf.push(0xF0 | elem);
            write_varint(&mut self.buf, len as u64);
        }
    }

    pub fn write_list_field<F>(&mut self, id: i16, elem: u8, len: usize, mut write_elem: F)
    where
        F: FnMut(&mut Self),
    {
        self.begin_list_field(id, elem, len);
        for _ in 0..len {
            write_elem(self);
        }
    }

    pub fn write_struct_field<F>(&mut self, id: i16, write_body: F)
    where
        F: FnOnce(&mut Self),
    {
        self.field_header(id, T_STRUCT);
        self.begin_struct();
        write_body(self);
        self.end_struct();
    }
}

pub struct CompactReader<'a> {
    data: &'a [u8],
    pos: usize,
    last_id: i16,
    stack: Vec<i16>,
}

#[derive(Debug)]
pub struct DecodeError(pub &'static str);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for DecodeError {}

impl<'a> CompactReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            last_id: 0,
            stack: Vec::new(),
        }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn begin_struct(&mut self) {
        self.stack.push(self.last_id);
        self.last_id = 0;
    }

    pub fn end_struct(&mut self) -> Result<(), DecodeError> {
        self.last_id = self.stack.pop().ok_or(DecodeError("struct stack"))?;
        Ok(())
    }

    pub fn next_field(&mut self) -> Result<Option<(i16, u8)>, DecodeError> {
        let header = self.read_u8()?;
        if header == T_STOP {
            return Ok(None);
        }
        let ty = header & 0x0f;
        let delta = header >> 4;
        let id = if delta == 0 {
            unzigzag_i16(self.read_varint()?)
        } else {
            self.last_id + i16::from(delta)
        };
        self.last_id = id;
        Ok(Some((id, ty)))
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn bound_len(&self, len: usize) -> Result<usize, DecodeError> {
        if len > self.remaining() {
            Err(DecodeError("count exceeds input"))
        } else {
            Ok(len)
        }
    }

    pub fn skip_value(&mut self, ty: u8) -> Result<(), DecodeError> {
        self.skip_value_at(ty, 0)
    }

    fn skip_value_at(&mut self, ty: u8, depth: u32) -> Result<(), DecodeError> {
        if depth > 32 {
            return Err(DecodeError("thrift nesting"));
        }
        match ty {
            T_TRUE | T_FALSE => Ok(()),
            T_I8 => {
                self.read_u8()?;
                Ok(())
            }
            T_I16 | T_I32 | T_I64 => {
                self.read_varint()?;
                Ok(())
            }
            T_DOUBLE => {
                self.read_exact(8)?;
                Ok(())
            }
            T_BIN => {
                let n = usize::try_from(self.read_varint()?)
                    .map_err(|_| DecodeError("count exceeds input"))?;
                let n = self.bound_len(n)?;
                self.read_exact(n)?;
                Ok(())
            }
            T_LIST | T_SET => {
                let (elem, len) = self.read_list_header()?;
                for _ in 0..len {
                    self.skip_value_at(elem, depth + 1)?;
                }
                Ok(())
            }
            T_MAP => {
                let header = self.read_u8()?;
                let key_ty = header >> 4;
                let val_ty = header & 0x0f;
                let len = if header == 0 {
                    0
                } else {
                    usize::try_from(self.read_varint()?)
                        .map_err(|_| DecodeError("count exceeds input"))?
                };
                let len = self.bound_len(len)?;
                for _ in 0..len {
                    self.skip_value_at(key_ty, depth + 1)?;
                    self.skip_value_at(val_ty, depth + 1)?;
                }
                Ok(())
            }
            T_STRUCT => {
                self.begin_struct();
                while let Some((_, field_ty)) = self.next_field()? {
                    self.skip_value_at(field_ty, depth + 1)?;
                }
                self.end_struct()
            }
            _ => Err(DecodeError("unknown thrift type")),
        }
    }

    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        Ok(unzigzag_i32(self.read_varint()?))
    }

    pub fn read_i64(&mut self) -> Result<i64, DecodeError> {
        Ok(unzigzag_i64(self.read_varint()?))
    }

    pub fn read_bin(&mut self) -> Result<&'a [u8], DecodeError> {
        let n =
            usize::try_from(self.read_varint()?).map_err(|_| DecodeError("count exceeds input"))?;
        let n = self.bound_len(n)?;
        self.read_exact(n)
    }

    pub fn read_str(&mut self) -> Result<&'a str, DecodeError> {
        std::str::from_utf8(self.read_bin()?).map_err(|_| DecodeError("string is not utf-8"))
    }

    pub fn read_list_header(&mut self) -> Result<(u8, usize), DecodeError> {
        let header = self.read_u8()?;
        let elem = header & 0x0f;
        let mut len = usize::from(header >> 4);
        if len == 15 {
            len = usize::try_from(self.read_varint()?)
                .map_err(|_| DecodeError("count exceeds input"))?;
        }
        Ok((elem, self.bound_len(len)?))
    }

    fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let byte = *self.data.get(self.pos).ok_or(DecodeError("truncated"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError("truncated"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(DecodeError("truncated"))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.read_u8()?;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 63 {
                return Err(DecodeError("varint overflow"));
            }
        }
    }
}

pub fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn zigzag_i16(value: i16) -> u64 {
    i32::from((value << 1) ^ (value >> 15)) as u16 as u64
}

fn zigzag_i32(value: i32) -> u64 {
    ((value << 1) ^ (value >> 31)) as u32 as u64
}

fn zigzag_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag_i16(value: u64) -> i16 {
    let value = value as u16;
    ((value >> 1) as i16) ^ -((value & 1) as i16)
}

fn unzigzag_i32(value: u64) -> i32 {
    let value = value as u32;
    ((value >> 1) as i32) ^ -((value & 1) as i32)
}

fn unzigzag_i64(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_rejects_a_list_longer_than_the_input() {
        // Compact list of T_TRUE whose claimed length is a 3-byte varint, with
        // no remaining payload. Skipping must fail closed instead of looping.
        let mut reader = CompactReader::new(&[0xf1, 0x80, 0x80, 0x08]);
        let err = reader.skip_value(T_LIST).unwrap_err();
        assert_eq!(err.0, "count exceeds input");
    }

    #[test]
    fn skip_rejects_nested_structs_deeper_than_the_bound() {
        let mut nested = Vec::new();
        for _ in 0..40 {
            nested.push((1 << 4) | T_STRUCT);
        }
        nested.extend(std::iter::repeat_n(T_STOP, 41));
        let mut reader = CompactReader::new(&nested);
        let err = reader.skip_value(T_STRUCT).unwrap_err();
        assert_eq!(err.0, "thrift nesting");
    }
}
