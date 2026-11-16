//! Strict hexadecimal decoding for untrusted input (webhook signatures,
//! export bundles, federation keys). Callers check the decoded length.

use std::fmt;

/// Why a string is not hexadecimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidHex {
    OddLength,
    NotHexDigit,
}

impl fmt::Display for InvalidHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OddLength => "hex string must have even length",
            Self::NotHexDigit => "hex string must contain only ASCII hexadecimal digits",
        })
    }
}

impl std::error::Error for InvalidHex {}

impl From<InvalidHex> for String {
    fn from(error: InvalidHex) -> Self {
        error.to_string()
    }
}

/// Decodes pairs of ASCII hex digits (either case). Works on bytes, so any
/// other character, including a multi-byte one, is an error and never a panic.
pub fn decode(input: &str) -> Result<Vec<u8>, InvalidHex> {
    let (pairs, rest) = input.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(InvalidHex::OddLength);
    }
    pairs
        .iter()
        .map(|[high, low]| Ok((nibble(*high)? << 4) | nibble(*low)?))
        .collect()
}

fn nibble(byte: u8) -> Result<u8, InvalidHex> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(InvalidHex::NotHexDigit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ascii_hex_in_either_case() {
        assert_eq!(decode("00aFff").unwrap(), [0x00, 0xaf, 0xff]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn refuses_everything_else_without_panicking() {
        assert_eq!(decode("abc"), Err(InvalidHex::OddLength));
        assert_eq!(decode("aéb"), Err(InvalidHex::NotHexDigit));
        assert_eq!(decode("aé1"), Err(InvalidHex::NotHexDigit));
        assert_eq!(decode("+f"), Err(InvalidHex::NotHexDigit));
        assert_eq!(decode(" f"), Err(InvalidHex::NotHexDigit));
    }
}
