#![allow(clippy::should_implement_trait)]

//! Canonical CBOR encoding for AAFP (RFC-0002 §8, RFC 8949 §4.2.3).
//!
//! This module provides a focused canonical CBOR encoder/decoder that
//! implements length-first core deterministic encoding with integer keys.
//! It is designed specifically for AAFP protocol structures and ensures
//! byte-exact encoding for signature verification interoperability.
//!
//! ## Key Rules (RFC-0002 §8.1)
//!
//! 1. Map keys sorted by length-first canonical byte ordering
//! 2. Integers use shortest encoding
//! 3. No indefinite-length arrays or maps
//! 4. Text strings use definite-length UTF-8
//! 5. All CBOR maps use integer keys (exception: metadata map uses string keys)

use thiserror::Error;

// CBOR major types (RFC 8949 §3)
const MT_UNSIGNED: u8 = 0; // Major type 0: unsigned integer
const MT_NEGATIVE: u8 = 1; // Major type 1: negative integer
const MT_BYTE_STRING: u8 = 2; // Major type 2: byte string
const MT_TEXT_STRING: u8 = 3; // Major type 3: text string
const MT_ARRAY: u8 = 4; // Major type 4: array
const MT_MAP: u8 = 5; // Major type 5: map
const MT_TAG: u8 = 6; // Major type 6: tag
const MT_SIMPLE: u8 = 7; // Major type 7: simple/float

// Additional info values
const AI_ONE_BYTE: u8 = 24; // Next 1 byte is value
const AI_TWO_BYTES: u8 = 25; // Next 2 bytes are value
const AI_FOUR_BYTES: u8 = 26; // Next 4 bytes are value
const AI_EIGHT_BYTES: u8 = 27; // Next 8 bytes are value
const AI_BREAK: u8 = 31; // Break code for indefinite

// Simple values
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
const SIMPLE_UNDEFINED: u8 = 23;

/// CBOR value types used in AAFP structures.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// An unsigned integer value.
    Unsigned(u64),
    /// A negative integer value.
    Negative(i64),
    /// A byte string value.
    ByteString(Vec<u8>),
    /// A UTF-8 text string value.
    TextString(String),
    /// An array of CBOR values.
    Array(Vec<Value>),
    /// Map with integer keys (canonical AAFP maps).
    IntMap(Vec<(i64, Value)>),
    /// Map with string keys (for CapabilityDescriptor metadata).
    StrMap(Vec<(String, Value)>),
    /// A boolean value.
    Bool(bool),
    /// A null value.
    Null,
}

impl Value {
    /// Create an unsigned integer `Value` from a `u64`.
    pub fn from_u64(v: u64) -> Self {
        Self::Unsigned(v)
    }

    /// Create a byte string `Value` from a byte vector.
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self::ByteString(b)
    }

    /// Create a text string `Value` from any string-like input.
    pub fn from_str(s: impl Into<String>) -> Self {
        Self::TextString(s.into())
    }

    /// Create a boolean `Value`.
    pub fn from_bool(b: bool) -> Self {
        Self::Bool(b)
    }

    /// Create a null `Value`.
    pub fn null() -> Self {
        Self::Null
    }
}

/// Errors during CBOR encoding/decoding.
#[derive(Debug, Error)]
pub enum CborError {
    #[error("unexpected end of input at offset {0}")]
    /// The input ended before a complete CBOR value could be read.
    UnexpectedEof(usize),
    #[error("invalid CBOR at offset {offset}: {message}")]
    /// The CBOR data is invalid at the given offset.
    Invalid {
        /// Byte offset where the invalid data was encountered.
        offset: usize,
        /// Human-readable description of the problem.
        message: String,
    },
    #[error("unsupported CBOR feature at offset {offset}: {feature}")]
    /// An unsupported CBOR feature was encountered at the given offset.
    Unsupported {
        /// Byte offset where the unsupported feature was encountered.
        offset: usize,
        /// Name or description of the unsupported feature.
        feature: String,
    },
    #[error("integer key out of range: {0}")]
    /// An integer map key is outside the representable range.
    KeyOutOfRange(i64),
}

/// Encode a CBOR value using canonical (deterministic) encoding.
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    encode_value(&mut buf, value)?;
    Ok(buf)
}

/// Decode a CBOR value from bytes. Returns (value, bytes_consumed).
pub fn decode(data: &[u8]) -> Result<(Value, usize), CborError> {
    let mut pos = 0;
    let value = decode_value(data, &mut pos)?;
    Ok((value, pos))
}

/// Check that a byte buffer is valid canonical CBOR (RFC 8949 §4.2.3).
///
/// This is a convenience function that decodes the CBOR and verifies
/// that it conforms to length-first deterministic encoding requirements.
/// It rejects:
/// - Non-shortest integer encodings
/// - Indefinite-length arrays and maps
/// - Duplicate map keys
/// - Trailing bytes after the top-level value
///
/// Returns `Ok(())` if the encoding is canonical, or an error describing
/// the violation.
pub fn check_canonical(data: &[u8]) -> Result<(), CborError> {
    let (_value, consumed) = decode(data)?;
    if consumed != data.len() {
        return Err(CborError::Invalid {
            offset: consumed,
            message: format!(
                "trailing bytes after CBOR value: consumed {} of {} bytes",
                consumed,
                data.len()
            ),
        });
    }
    Ok(())
}

fn encode_header(buf: &mut Vec<u8>, major: u8, value: u64) {
    if value <= 23 {
        buf.push((major << 5) | value as u8);
    } else if value <= 255 {
        buf.push((major << 5) | AI_ONE_BYTE);
        buf.push(value as u8);
    } else if value <= 65535 {
        buf.push((major << 5) | AI_TWO_BYTES);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFFFFFF {
        buf.push((major << 5) | AI_FOUR_BYTES);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | AI_EIGHT_BYTES);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_value(buf: &mut Vec<u8>, value: &Value) -> Result<(), CborError> {
    match value {
        Value::Unsigned(n) => {
            encode_header(buf, MT_UNSIGNED, *n);
        }
        Value::Negative(n) => {
            // Negative integers: CBOR encodes -1 as 0x20, -2 as 0x21, etc.
            // For n < 0, the encoded value is (-n - 1) as unsigned.
            let encoded = (-1i64 - n) as u64;
            encode_header(buf, MT_NEGATIVE, encoded);
        }
        Value::ByteString(b) => {
            encode_header(buf, MT_BYTE_STRING, b.len() as u64);
            buf.extend_from_slice(b);
        }
        Value::TextString(s) => {
            let bytes = s.as_bytes();
            encode_header(buf, MT_TEXT_STRING, bytes.len() as u64);
            buf.extend_from_slice(bytes);
        }
        Value::Array(arr) => {
            encode_header(buf, MT_ARRAY, arr.len() as u64);
            for item in arr {
                encode_value(buf, item)?;
            }
        }
        Value::IntMap(entries) => {
            // Sort keys by length-first canonical byte ordering
            let sorted = sort_int_keys(entries);
            encode_header(buf, MT_MAP, sorted.len() as u64);
            for (key, val) in sorted {
                encode_int_key(buf, key);
                encode_value(buf, val)?;
            }
        }
        Value::StrMap(entries) => {
            // Sort string keys by length-first canonical byte ordering
            let sorted = sort_str_keys(entries);
            encode_header(buf, MT_MAP, sorted.len() as u64);
            for (key, val) in sorted {
                let bytes = key.as_bytes();
                encode_header(buf, MT_TEXT_STRING, bytes.len() as u64);
                buf.extend_from_slice(bytes);
                encode_value(buf, val)?;
            }
        }
        Value::Bool(true) => {
            buf.push((MT_SIMPLE << 5) | SIMPLE_TRUE);
        }
        Value::Bool(false) => {
            buf.push((MT_SIMPLE << 5) | SIMPLE_FALSE);
        }
        Value::Null => {
            buf.push((MT_SIMPLE << 5) | SIMPLE_NULL);
        }
    }
    Ok(())
}

/// Encode an integer key directly (for canonical sorting).
fn encode_int_key(buf: &mut Vec<u8>, key: i64) {
    if key >= 0 {
        encode_header(buf, MT_UNSIGNED, key as u64);
    } else {
        let encoded = (-1i64 - key) as u64;
        encode_header(buf, MT_NEGATIVE, encoded);
    }
}

/// Get the CBOR encoding of an integer key (for sorting).
fn int_key_encoding(key: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_int_key(&mut buf, key);
    buf
}

/// Sort integer keys by length-first canonical byte ordering (RFC 8949 §4.2.3).
fn sort_int_keys(entries: &[(i64, Value)]) -> Vec<(i64, &Value)> {
    let mut indexed: Vec<(Vec<u8>, i64, &Value)> = entries
        .iter()
        .map(|(k, v)| (int_key_encoding(*k), *k, v))
        .collect();
    // Sort by (length, bytewise) — length-first ordering
    indexed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    indexed.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// Sort string keys by length-first canonical byte ordering.
fn sort_str_keys(entries: &[(String, Value)]) -> Vec<(String, &Value)> {
    let mut indexed: Vec<(Vec<u8>, String, &Value)> = entries
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), k.clone(), v))
        .collect();
    // For text strings, the CBOR encoding includes the header.
    // But for sorting, RFC 8949 §4.2.3 says to sort by the encoding of the key.
    // The key encoding is: header + UTF-8 bytes.
    // Since the header depends on length, and shorter strings have shorter
    // headers, sorting by (length of UTF-8 bytes, then bytewise) is equivalent
    // to sorting by the full CBOR encoding for strings of the same length range.
    // Actually, RFC 8949 §4.2.3 says sort by the "bytewise representation of
    // the key" which is the full CBOR encoding.
    // Let's sort by the full CBOR encoding.
    indexed.sort_by(|a, b| {
        let enc_a = text_key_encoding(&a.1);
        let enc_b = text_key_encoding(&b.1);
        enc_a.cmp(&enc_b)
    });
    indexed.into_iter().map(|(_, k, v)| (k, v)).collect()
}

/// Get the CBOR encoding of a text string key (for sorting).
fn text_key_encoding(s: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let bytes = s.as_bytes();
    encode_header(&mut buf, MT_TEXT_STRING, bytes.len() as u64);
    buf.extend_from_slice(bytes);
    buf
}

fn decode_value(data: &[u8], pos: &mut usize) -> Result<Value, CborError> {
    if *pos >= data.len() {
        return Err(CborError::UnexpectedEof(*pos));
    }

    let initial_byte = data[*pos];
    let major = initial_byte >> 5;
    let ai = initial_byte & 0x1F;

    *pos += 1;

    // Read the argument value
    let arg = read_argument(data, pos, ai)?;

    match major {
        MT_UNSIGNED => Ok(Value::Unsigned(arg)),
        MT_NEGATIVE => {
            // Negative: value is -1 - arg
            if arg > i64::MAX as u64 {
                return Err(CborError::Invalid {
                    offset: *pos,
                    message: format!("negative integer out of range: {arg}"),
                });
            }
            Ok(Value::Negative(-1i64 - arg as i64))
        }
        MT_BYTE_STRING => {
            let len = arg as usize;
            let end = (*pos).checked_add(len).ok_or_else(|| CborError::Invalid {
                offset: *pos,
                message: "byte string length overflow".to_string(),
            })?;
            if end > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let bytes = data[*pos..end].to_vec();
            *pos = end;
            Ok(Value::ByteString(bytes))
        }
        MT_TEXT_STRING => {
            let len = arg as usize;
            let end = (*pos).checked_add(len).ok_or_else(|| CborError::Invalid {
                offset: *pos,
                message: "text string length overflow".to_string(),
            })?;
            if end > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let bytes = &data[*pos..end];
            *pos = end;
            let s = std::str::from_utf8(bytes).map_err(|e| CborError::Invalid {
                offset: *pos,
                message: format!("invalid UTF-8: {e}"),
            })?;
            Ok(Value::TextString(s.to_string()))
        }
        MT_ARRAY => {
            let len = arg as usize;
            // Prevent OOM from absurdly large length claims
            if len > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(decode_value(data, pos)?);
            }
            Ok(Value::Array(arr))
        }
        MT_MAP => {
            let len = arg as usize;
            // Prevent OOM from absurdly large length claims
            if len > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let mut entries: Vec<(Value, Value)> = Vec::with_capacity(len);
            for _ in 0..len {
                let key = decode_value(data, pos)?;
                let val = decode_value(data, pos)?;
                // Check for duplicate keys (canonical CBOR requires unique keys)
                if entries.iter().any(|(k, _)| k == &key) {
                    return Err(CborError::Invalid {
                        offset: *pos,
                        message: "duplicate map key".to_string(),
                    });
                }
                entries.push((key, val));
            }
            // Convert to IntMap or StrMap based on key types
            let all_int_keys = entries
                .iter()
                .all(|(k, _)| matches!(k, Value::Unsigned(_) | Value::Negative(_)));
            let all_str_keys = entries
                .iter()
                .all(|(k, _)| matches!(k, Value::TextString(_)));

            if all_int_keys {
                let int_entries: Vec<(i64, Value)> = entries
                    .into_iter()
                    .map(|(k, v)| {
                        let key = match k {
                            Value::Unsigned(n) => n as i64,
                            Value::Negative(n) => n,
                            _ => unreachable!(),
                        };
                        (key, v)
                    })
                    .collect();
                Ok(Value::IntMap(int_entries))
            } else if all_str_keys {
                let str_entries: Vec<(String, Value)> = entries
                    .into_iter()
                    .map(|(k, v)| {
                        let key = match k {
                            Value::TextString(s) => s,
                            _ => unreachable!(),
                        };
                        (key, v)
                    })
                    .collect();
                Ok(Value::StrMap(str_entries))
            } else {
                // Mixed key types — store as IntMap with a best-effort conversion
                // This shouldn't happen in AAFP structures
                Err(CborError::Unsupported {
                    offset: *pos,
                    feature: "mixed key types in map".to_string(),
                })
            }
        }
        MT_SIMPLE => match ai {
            SIMPLE_FALSE => Ok(Value::Bool(false)),
            SIMPLE_TRUE => Ok(Value::Bool(true)),
            SIMPLE_NULL => Ok(Value::Null),
            SIMPLE_UNDEFINED => Ok(Value::Null), // Treat undefined as null
            _ => Err(CborError::Unsupported {
                offset: *pos,
                feature: format!("simple value {ai}"),
            }),
        },
        MT_TAG => Err(CborError::Unsupported {
            offset: *pos,
            feature: format!("tag {arg}"),
        }),
        _ => Err(CborError::Unsupported {
            offset: *pos,
            feature: format!("major type {major}"),
        }),
    }
}

fn read_argument(data: &[u8], pos: &mut usize, ai: u8) -> Result<u64, CborError> {
    match ai {
        0..=23 => Ok(ai as u64),
        AI_ONE_BYTE => {
            if *pos >= data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let val = data[*pos] as u64;
            *pos += 1;
            // Canonical check: values 0-23 must use immediate encoding, not AI_ONE_BYTE
            if val <= 23 {
                return Err(CborError::Invalid {
                    offset: *pos - 1,
                    message: format!(
                        "non-canonical encoding: value {val} should use immediate encoding, not AI_ONE_BYTE"
                    ),
                });
            }
            Ok(val)
        }
        AI_TWO_BYTES => {
            if *pos + 2 > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let val = u16::from_be_bytes(data[*pos..*pos + 2].try_into().unwrap()) as u64;
            *pos += 2;
            // Canonical check: values 0-255 should use AI_ONE_BYTE, not AI_TWO_BYTES
            if val <= 255 {
                return Err(CborError::Invalid {
                    offset: *pos - 2,
                    message: format!(
                        "non-canonical encoding: value {val} should use shorter encoding"
                    ),
                });
            }
            Ok(val)
        }
        AI_FOUR_BYTES => {
            if *pos + 4 > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let val = u32::from_be_bytes(data[*pos..*pos + 4].try_into().unwrap()) as u64;
            *pos += 4;
            // Canonical check: values 0-65535 should use AI_TWO_BYTES, not AI_FOUR_BYTES
            if val <= 65535 {
                return Err(CborError::Invalid {
                    offset: *pos - 4,
                    message: format!(
                        "non-canonical encoding: value {val} should use shorter encoding"
                    ),
                });
            }
            Ok(val)
        }
        AI_EIGHT_BYTES => {
            if *pos + 8 > data.len() {
                return Err(CborError::UnexpectedEof(*pos));
            }
            let val = u64::from_be_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            // Canonical check: values 0-4294967295 should use AI_FOUR_BYTES, not AI_EIGHT_BYTES
            if val <= 4294967295 {
                return Err(CborError::Invalid {
                    offset: *pos - 8,
                    message: format!(
                        "non-canonical encoding: value {val} should use shorter encoding"
                    ),
                });
            }
            Ok(val)
        }
        AI_BREAK => Err(CborError::Unsupported {
            offset: *pos,
            feature: "break code (indefinite-length not allowed)".to_string(),
        }),
        _ => Err(CborError::Unsupported {
            offset: *pos,
            feature: format!("additional info {ai}"),
        }),
    }
}

/// Helper: build an IntMap from a Vec of (key, value) pairs.
/// The pairs will be sorted canonically during encoding.
pub fn int_map(entries: Vec<(i64, Value)>) -> Value {
    Value::IntMap(entries)
}

/// Helper: build a StrMap from a Vec of (key, value) pairs.
pub fn str_map(entries: Vec<(String, Value)>) -> Value {
    Value::StrMap(entries)
}

/// Helper: look up a key in an IntMap.
pub fn int_map_get(map: &Value, key: i64) -> Option<&Value> {
    match map {
        Value::IntMap(entries) => entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// Helper: look up a key in a StrMap.
pub fn str_map_get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    match map {
        Value::StrMap(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_unsigned() {
        assert_eq!(encode(&Value::Unsigned(0)).unwrap(), vec![0x00]);
        assert_eq!(encode(&Value::Unsigned(1)).unwrap(), vec![0x01]);
        assert_eq!(encode(&Value::Unsigned(23)).unwrap(), vec![0x17]);
        assert_eq!(encode(&Value::Unsigned(24)).unwrap(), vec![0x18, 0x18]);
        assert_eq!(encode(&Value::Unsigned(100)).unwrap(), vec![0x18, 0x64]);
        assert_eq!(
            encode(&Value::Unsigned(1000)).unwrap(),
            vec![0x19, 0x03, 0xE8]
        );
    }

    #[test]
    fn test_encode_negative() {
        assert_eq!(encode(&Value::Negative(-1)).unwrap(), vec![0x20]);
        assert_eq!(encode(&Value::Negative(-10)).unwrap(), vec![0x29]);
        assert_eq!(encode(&Value::Negative(-100)).unwrap(), vec![0x38, 0x63]);
    }

    #[test]
    fn test_encode_byte_string() {
        let val = Value::from_bytes(vec![0x01, 0x02, 0x03]);
        assert_eq!(encode(&val).unwrap(), vec![0x43, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_text_string() {
        let val = Value::from_str("hi");
        assert_eq!(encode(&val).unwrap(), vec![0x62, 0x68, 0x69]);
    }

    #[test]
    fn test_encode_bool_null() {
        assert_eq!(encode(&Value::Bool(true)).unwrap(), vec![0xF5]);
        assert_eq!(encode(&Value::Bool(false)).unwrap(), vec![0xF4]);
        assert_eq!(encode(&Value::Null).unwrap(), vec![0xF6]);
    }

    #[test]
    fn test_encode_array() {
        let val = Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]);
        assert_eq!(encode(&val).unwrap(), vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn test_encode_int_map_canonical_ordering() {
        // Keys should be sorted by length-first canonical byte ordering
        // Keys 1, 2, 5, 10 are all 1-byte, so sorted numerically: 1, 2, 5, 10
        let val = int_map(vec![
            (10, Value::Unsigned(100)),
            (2, Value::Unsigned(20)),
            (1, Value::Unsigned(10)),
            (5, Value::Unsigned(50)),
        ]);
        let encoded = encode(&val).unwrap();
        // Map of 4 entries: 0xA4
        // Key 1: 0x01, Value 10: 0x0A
        // Key 2: 0x02, Value 20: 0x14
        // Key 5: 0x05, Value 50: 0x18, 0x32
        // Key 10: 0x0A, Value 100: 0x18, 0x64
        assert_eq!(
            encoded,
            vec![0xA4, 0x01, 0x0A, 0x02, 0x14, 0x05, 0x18, 0x32, 0x0A, 0x18, 0x64]
        );
    }

    #[test]
    fn test_encode_int_map_mixed_lengths() {
        // Keys 1 (1-byte) and 24 (2-byte: 0x18 0x18)
        // 1-byte keys sort before 2-byte keys
        let val = int_map(vec![(24, Value::Unsigned(2)), (1, Value::Unsigned(1))]);
        let encoded = encode(&val).unwrap();
        // Key 1 (0x01) comes before key 24 (0x18, 0x18)
        assert_eq!(encoded, vec![0xA2, 0x01, 0x01, 0x18, 0x18, 0x02]);
    }

    #[test]
    fn test_decode_unsigned() {
        let (val, consumed) = decode(&[0x05]).unwrap();
        assert_eq!(val, Value::Unsigned(5));
        assert_eq!(consumed, 1);

        let (val, consumed) = decode(&[0x18, 0x64]).unwrap();
        assert_eq!(val, Value::Unsigned(100));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_byte_string() {
        let (val, _) = decode(&[0x43, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(val, Value::from_bytes(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_decode_text_string() {
        let (val, _) = decode(&[0x62, 0x68, 0x69]).unwrap();
        assert_eq!(val, Value::from_str("hi"));
    }

    #[test]
    fn test_roundtrip_int_map() {
        let original = int_map(vec![
            (1, Value::from_str("hello")),
            (2, Value::from_bytes(vec![0xDE, 0xAD])),
            (3, Value::Bool(true)),
            (10, Value::Null),
        ]);
        let encoded = encode(&original).unwrap();
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_array() {
        let original = Value::Array(vec![
            Value::Unsigned(1),
            Value::from_str("test"),
            Value::Null,
            Value::Bool(false),
        ]);
        let encoded = encode(&original).unwrap();
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_roundtrip_nested_map() {
        let inner = int_map(vec![(1, Value::Unsigned(42))]);
        let outer = int_map(vec![
            (1, Value::from_str("aafp-record-v1")),
            (2, inner.clone()),
            (
                3,
                Value::Array(vec![Value::Unsigned(1), Value::Unsigned(2)]),
            ),
        ]);
        let encoded = encode(&outer).unwrap();
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(decoded, outer);
    }

    #[test]
    fn test_int_map_get() {
        let map = int_map(vec![
            (1, Value::from_str("hello")),
            (2, Value::Unsigned(42)),
        ]);
        assert_eq!(int_map_get(&map, 1), Some(&Value::from_str("hello")));
        assert_eq!(int_map_get(&map, 2), Some(&Value::Unsigned(42)));
        assert_eq!(int_map_get(&map, 3), None);
    }

    #[test]
    fn test_canonical_encoding_is_deterministic() {
        // Same map with different insertion order should produce same bytes
        let map1 = int_map(vec![
            (3, Value::Unsigned(3)),
            (1, Value::Unsigned(1)),
            (2, Value::Unsigned(2)),
        ]);
        let map2 = int_map(vec![
            (1, Value::Unsigned(1)),
            (2, Value::Unsigned(2)),
            (3, Value::Unsigned(3)),
        ]);
        let enc1 = encode(&map1).unwrap();
        let enc2 = encode(&map2).unwrap();
        assert_eq!(enc1, enc2, "canonical encoding must be deterministic");
    }

    #[test]
    fn test_str_map_canonical_ordering() {
        let map = str_map(vec![
            ("zebra".to_string(), Value::Unsigned(1)),
            ("apple".to_string(), Value::Unsigned(2)),
            ("cat".to_string(), Value::Unsigned(3)),
        ]);
        let encoded = encode(&map).unwrap();
        let (decoded, _) = decode(&encoded).unwrap();
        // Length-first canonical ordering: "cat" (3B) < "apple" (5B) < "zebra" (5B)
        // Same-length "apple" and "zebra" sorted bytewise: "apple" < "zebra"
        if let Value::StrMap(entries) = decoded {
            assert_eq!(entries[0].0, "cat");
            assert_eq!(entries[1].0, "apple");
            assert_eq!(entries[2].0, "zebra");
        } else {
            panic!("expected StrMap");
        }
    }

    #[test]
    fn test_indefinite_length_rejected() {
        // Indefinite-length array starts with 0x9F
        let data = vec![0x9F, 0x01, 0xFF];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_empty_map() {
        let val = int_map(vec![]);
        let encoded = encode(&val).unwrap();
        assert_eq!(encoded, vec![0xA0]);
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }

    #[test]
    fn test_empty_array() {
        let val = Value::Array(vec![]);
        let encoded = encode(&val).unwrap();
        assert_eq!(encoded, vec![0x80]);
        let (decoded, _) = decode(&encoded).unwrap();
        assert_eq!(decoded, val);
    }
}
