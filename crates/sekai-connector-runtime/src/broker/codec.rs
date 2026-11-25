//! Decompression of record batches: gzip, snappy (raw, or in the xerial
//! block framing producers write), lz4 frames and zstd, all pure Rust.
//! Each batch may expand to at most [`MAX_BATCH_BYTES`]; a batch past it
//! is refused, so one record cannot exhaust the runtime's memory.

use std::io::{self, Read};

use bytes::Bytes;
use kafka_protocol::records::Compression;

/// The most one batch may expand to.
pub const MAX_BATCH_BYTES: usize = 64 << 20;

/// The xerial framing's magic; the header continues with two 4-byte
/// version fields before the length-prefixed blocks.
const XERIAL_MAGIC: &[u8] = b"\x82SNAPPY\0";
const XERIAL_HEADER_BYTES: usize = 16;

/// Takes the compressed records of one batch and returns them expanded.
pub fn decompress(compressed: &mut Bytes, compression: Compression) -> io::Result<Bytes> {
    let input = std::mem::take(compressed);
    let mut out = Vec::new();
    match compression {
        Compression::None => return Ok(input),
        Compression::Gzip => read_capped(flate2::read::GzDecoder::new(&input[..]), &mut out)?,
        Compression::Snappy => snappy(&input, &mut out)?,
        Compression::Lz4 => read_capped(lz4_flex::frame::FrameDecoder::new(&input[..]), &mut out)?,
        Compression::Zstd => read_capped(
            ruzstd::decoding::StreamingDecoder::new(&input[..]).map_err(io::Error::other)?,
            &mut out,
        )?,
    }
    Ok(out.into())
}

fn read_capped(reader: impl Read, out: &mut Vec<u8>) -> io::Result<()> {
    reader.take(MAX_BATCH_BYTES as u64 + 1).read_to_end(out)?;
    if out.len() > MAX_BATCH_BYTES {
        return Err(too_large());
    }
    Ok(())
}

fn snappy(input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    let mut decoder = snap::raw::Decoder::new();
    if !input.starts_with(XERIAL_MAGIC) {
        return snappy_block(&mut decoder, input, out);
    }
    let mut rest = input.get(XERIAL_HEADER_BYTES..).ok_or_else(truncated)?;
    while let Some((length, tail)) = rest.split_first_chunk::<4>() {
        let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| truncated())?;
        let block = tail.get(..length).ok_or_else(truncated)?;
        snappy_block(&mut decoder, block, out)?;
        rest = &tail[length..];
    }
    if rest.is_empty() {
        Ok(())
    } else {
        Err(truncated())
    }
}

fn snappy_block(
    decoder: &mut snap::raw::Decoder,
    block: &[u8],
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let length = snap::raw::decompress_len(block).map_err(io::Error::other)?;
    let start = out.len();
    if start + length > MAX_BATCH_BYTES {
        return Err(too_large());
    }
    out.resize(start + length, 0);
    decoder
        .decompress(block, &mut out[start..])
        .map_err(io::Error::other)?;
    Ok(())
}

fn too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "record batch expands past the limit",
    )
}

fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "truncated snappy framing")
}
