//! AAFP frame extensions (RFC-0002 §6).
//!
//! Frame-level extensions are binary-encoded in the frame body's
//! Extension section. Each extension is self-delimiting.
//!
//! Wire format per extension:
//! ```text
//! [Type:2B][Critical:1B][Reserved:1B][DataLen:4B][Data:N]
//! ```
//!
//! Handshake-level extensions use CBOR ExtensionEntry maps
//! (see RFC-0002 §6.4). These are distinct mechanisms.

use thiserror::Error;

/// Extension header size: 8 bytes (2+1+1+4).
pub const EXT_HEADER_SIZE: usize = 8;

/// A single frame-level extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extension {
    /// Extension type identifier (see RFC-0006 registry).
    pub ext_type: u16,
    /// If true, unknown extensions of this type MUST cause frame rejection.
    pub critical: bool,
    /// Extension-type-specific data.
    pub data: Vec<u8>,
}

/// Errors during extension encoding/decoding.
#[derive(Debug, Error)]
pub enum ExtensionError {
    #[error("extension data too large: {0} bytes (max {1})")]
    DataTooLarge(usize, usize),
    #[error("incomplete extension header: need {needed}, have {have}")]
    IncompleteHeader { needed: usize, have: usize },
    #[error("incomplete extension data: need {needed}, have {have}")]
    IncompleteData { needed: usize, have: usize },
    #[error("extension length mismatch: header says {expected}, actual {actual}")]
    LengthMismatch { expected: usize, actual: usize },
}

/// Encode a list of extensions into the frame body's Extension section.
pub fn encode_extensions(exts: &[Extension]) -> Result<Vec<u8>, ExtensionError> {
    let mut buf = Vec::new();
    for ext in exts {
        if ext.data.len() > u32::MAX as usize {
            return Err(ExtensionError::DataTooLarge(ext.data.len(), u32::MAX as usize));
        }
        buf.extend_from_slice(&ext.ext_type.to_be_bytes());
        buf.push(if ext.critical { 0x01 } else { 0x00 });
        buf.push(0u8); // Reserved
        buf.extend_from_slice(&(ext.data.len() as u32).to_be_bytes());
        buf.extend_from_slice(&ext.data);
    }
    Ok(buf)
}

/// Decode extensions from the frame body's Extension section.
pub fn decode_extensions(data: &[u8]) -> Result<Vec<Extension>, ExtensionError> {
    let mut exts = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        if data.len() - pos < EXT_HEADER_SIZE {
            return Err(ExtensionError::IncompleteHeader {
                needed: EXT_HEADER_SIZE,
                have: data.len() - pos,
            });
        }

        let ext_type = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap());
        let critical = data[pos + 2] == 0x01;
        // data[pos + 3] is reserved, ignored
        let data_len = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;

        pos += EXT_HEADER_SIZE;

        if data.len() - pos < data_len {
            return Err(ExtensionError::IncompleteData {
                needed: data_len,
                have: data.len() - pos,
            });
        }

        let ext_data = data[pos..pos + data_len].to_vec();
        pos += data_len;

        exts.push(Extension {
            ext_type,
            critical,
            data: ext_data,
        });
    }

    Ok(exts)
}

/// Find the first extension of a given type. Returns None if not found.
pub fn find_extension<'a>(exts: &'a [Extension], ext_type: u16) -> Option<&'a Extension> {
    exts.iter().find(|e| e.ext_type == ext_type)
}

/// Check if any extension is critical and unknown (per RFC-0002 §6.1).
/// Returns the first unknown critical extension type, if any.
pub fn find_unknown_critical(exts: &[Extension], known_types: &[u16]) -> Option<u16> {
    exts.iter()
        .find(|e| e.critical && !known_types.contains(&e.ext_type))
        .map(|e| e.ext_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_empty() {
        let buf = encode_extensions(&[]).unwrap();
        assert!(buf.is_empty());
        let decoded = decode_extensions(&buf).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_encode_decode_single() {
        let ext = Extension {
            ext_type: 0x0001,
            critical: true,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let buf = encode_extensions(&[ext.clone()]).unwrap();
        assert_eq!(buf.len(), EXT_HEADER_SIZE + 4);

        let decoded = decode_extensions(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], ext);
    }

    #[test]
    fn test_encode_decode_multiple() {
        let exts = vec![
            Extension {
                ext_type: 0x0001,
                critical: true,
                data: vec![1, 2, 3],
            },
            Extension {
                ext_type: 0x0002,
                critical: false,
                data: vec![4, 5, 6, 7, 8],
            },
            Extension {
                ext_type: 0x0003,
                critical: false,
                data: vec![],
            },
        ];
        let buf = encode_extensions(&exts).unwrap();
        let decoded = decode_extensions(&buf).unwrap();
        assert_eq!(decoded, exts);
    }

    #[test]
    fn test_find_extension() {
        let exts = vec![
            Extension {
                ext_type: 0x0001,
                critical: false,
                data: vec![1],
            },
            Extension {
                ext_type: 0x0002,
                critical: true,
                data: vec![2],
            },
        ];
        assert!(find_extension(&exts, 0x0001).is_some());
        assert!(find_extension(&exts, 0x0002).is_some());
        assert!(find_extension(&exts, 0x0003).is_none());
    }

    #[test]
    fn test_find_unknown_critical() {
        let exts = vec![
            Extension {
                ext_type: 0x0001,
                critical: false,
                data: vec![],
            },
            Extension {
                ext_type: 0x0002,
                critical: true,
                data: vec![],
            },
        ];
        // 0x0001 is non-critical, 0x0002 is critical
        // If we only know about 0x0001, 0x0002 is unknown critical
        assert_eq!(
            find_unknown_critical(&exts, &[0x0001]),
            Some(0x0002)
        );
        // If we know both, no unknown critical
        assert_eq!(
            find_unknown_critical(&exts, &[0x0001, 0x0002]),
            None
        );
    }

    #[test]
    fn test_incomplete_header() {
        let data = [0u8; 4]; // Less than EXT_HEADER_SIZE
        assert!(matches!(
            decode_extensions(&data),
            Err(ExtensionError::IncompleteHeader { .. })
        ));
    }

    #[test]
    fn test_incomplete_data() {
        // Header says 10 bytes of data, but only 4 available
        let mut data = vec![0x00, 0x01, 0x00, 0x00]; // type=1, critical=false, reserved=0
        data.extend_from_slice(&10u32.to_be_bytes()); // data_len=10
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // only 4 bytes
        assert!(matches!(
            decode_extensions(&data),
            Err(ExtensionError::IncompleteData { .. })
        ));
    }

    #[test]
    fn test_extension_with_empty_data() {
        let ext = Extension {
            ext_type: 0xFFFF,
            critical: false,
            data: vec![],
        };
        let buf = encode_extensions(&[ext.clone()]).unwrap();
        assert_eq!(buf.len(), EXT_HEADER_SIZE);
        let decoded = decode_extensions(&buf).unwrap();
        assert_eq!(decoded[0], ext);
    }
}
