//! Coinbase scriptSig construction.
//!
//! Handles BIP34 block height encoding, extranonce placement, and arbitrary
//! data embedding within the coinbase scriptSig.
//!
//! ## ScriptSig Layout
//!
//! ```text
//! [BIP34 height] [extranonce] [extra_data]
//! ```
//!
//! The total scriptSig must be between 2 and 100 bytes (consensus rule).

use alloc::vec::Vec;
use bitcoin::script::{self, PushBytesBuf};
use bitcoin::ScriptBuf;

use crate::error::CoinbaseError;

/// Maximum coinbase scriptSig size in bytes (consensus rule).
pub const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

/// Minimum coinbase scriptSig size in bytes (consensus rule).
pub const MIN_COINBASE_SCRIPT_SIZE: usize = 2;

/// Encode a block height as a BIP34 scriptSig push.
///
/// BIP34 requires the block height to be the first item in the coinbase
/// scriptSig, encoded as a minimally-encoded script number push.
///
/// # Examples
///
/// ```
/// use rust_coinbase::script::encode_bip34_height;
///
/// let script = encode_bip34_height(500_000);
/// let bytes = script.as_bytes();
/// // Height 500000 = 0x07A120, encoded as 3-byte LE push: 03 20 a1 07
/// assert_eq!(bytes[0], 3); // push 3 bytes
/// assert_eq!(&bytes[1..4], &[0x20, 0xa1, 0x07]);
/// ```
pub fn encode_bip34_height(height: u32) -> ScriptBuf {
    // BIP34 encodes the height as a CScriptNum push.
    // We use the script::Builder::push_int which handles minimal encoding.
    // However, BIP34 specifically requires the serialized block height, not
    // just any script number. For heights 1-16 the encoding uses the direct
    // push (OP_1..OP_16) but in practice we need the CScriptNum serialization.
    //
    // Bitcoin Core uses CScript() << nHeight which serializes as:
    //   - [n_bytes] [height_bytes_le]
    // where height_bytes_le is the little-endian representation with sign bit handling.
    //
    // For height 0: serializes as [0x01, 0x00] (push 1 byte, value 0)
    // For height 1-127: [0x01, height]
    // For height 128-32767: [0x02, lo, hi] (with sign-bit extension if needed)
    // etc.
    //
    // The script::Builder::push_int does NOT produce the right encoding for
    // BIP34 because it uses OP_0/OP_1..OP_16 for small values. We need the
    // explicit CScriptNum push format.

    let height_bytes = serialize_script_num(height as i64);
    let mut push = PushBytesBuf::new();
    push.extend_from_slice(&height_bytes)
        .expect("BIP34 height encoding always fits in PushBytes");

    script::Builder::new()
        .push_slice(push.as_push_bytes())
        .into_script()
}

/// Return the byte size of the BIP34 height encoding for a given height.
///
/// This includes the push opcode byte(s) and the height data bytes.
pub fn bip34_height_size(height: u32) -> usize {
    encode_bip34_height(height).as_bytes().len()
}

/// Calculate remaining scriptSig capacity after the BIP34 height and extranonce.
///
/// Returns the number of bytes available for extra data within the 100-byte limit.
pub fn remaining_script_capacity(height: u32, extranonce_size: usize) -> usize {
    let used = bip34_height_size(height) + extranonce_size;
    MAX_COINBASE_SCRIPT_SIZE.saturating_sub(used)
}

/// Build a complete coinbase scriptSig.
///
/// Assembles the scriptSig with the layout: `[BIP34 height][extranonce][extra_data]`.
///
/// # Arguments
///
/// * `height` - Block height (BIP34 encoded as the first item).
/// * `extranonce` - Extranonce bytes (typically 4-8 bytes). Pass an empty slice
///   to reserve no extranonce space.
/// * `extra_data` - Optional arbitrary data appended after the extranonce.
///
/// # Errors
///
/// Returns [`CoinbaseError::ScriptTooLong`] if the assembled script exceeds 100 bytes,
/// or [`CoinbaseError::ScriptTooShort`] if it's less than 2 bytes.
pub fn build_coinbase_script(
    height: u32,
    extranonce: &[u8],
    extra_data: Option<&[u8]>,
) -> Result<ScriptBuf, CoinbaseError> {
    let height_script = encode_bip34_height(height);
    let extra = extra_data.unwrap_or(&[]);

    let total_size = height_script.as_bytes().len() + extranonce.len() + extra.len();

    if total_size > MAX_COINBASE_SCRIPT_SIZE {
        return Err(CoinbaseError::ScriptTooLong {
            size: total_size,
            max: MAX_COINBASE_SCRIPT_SIZE,
        });
    }

    if total_size < MIN_COINBASE_SCRIPT_SIZE {
        return Err(CoinbaseError::ScriptTooShort {
            size: total_size,
            min: MIN_COINBASE_SCRIPT_SIZE,
        });
    }

    // Build the raw script bytes directly. The extranonce and extra_data are
    // raw bytes appended after the BIP34 height push -- they are NOT wrapped
    // in additional push opcodes. This matches Bitcoin Core's behavior and
    // the Stratum protocol expectation.
    let mut raw = Vec::with_capacity(total_size);
    raw.extend_from_slice(height_script.as_bytes());
    raw.extend_from_slice(extranonce);
    raw.extend_from_slice(extra);

    Ok(ScriptBuf::from_bytes(raw))
}

/// Build a coinbase scriptSig with a zeroed extranonce placeholder.
///
/// Creates the scriptSig with `extranonce_size` zero bytes in the extranonce
/// position. This is useful for constructing a template that will later have
/// the extranonce filled in (e.g., in the Stratum split model).
pub fn build_coinbase_script_with_placeholder(
    height: u32,
    extranonce_size: usize,
    extra_data: Option<&[u8]>,
) -> Result<ScriptBuf, CoinbaseError> {
    let placeholder = alloc::vec![0u8; extranonce_size];
    build_coinbase_script(height, &placeholder, extra_data)
}

/// Serialize an integer as a Bitcoin CScriptNum (little-endian with sign bit).
///
/// This produces the data bytes (without the push opcode prefix) for a
/// minimal CScriptNum encoding, matching Bitcoin Core's serialization.
fn serialize_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return alloc::vec![0x00];
    }

    let negative = value < 0;
    let mut abs_value = if negative {
        (value as i128).unsigned_abs() as u64
    } else {
        value as u64
    };

    let mut result = Vec::new();
    while abs_value > 0 {
        result.push((abs_value & 0xff) as u8);
        abs_value >>= 8;
    }

    // If the most significant byte has the sign bit set, we need an
    // extra byte to indicate the sign.
    if let Some(last) = result.last() {
        if last & 0x80 != 0 {
            if negative {
                result.push(0x80);
            } else {
                result.push(0x00);
            }
        } else if negative {
            let len = result.len();
            result[len - 1] |= 0x80;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip34_height_0() {
        let script = encode_bip34_height(0);
        let bytes = script.as_bytes();
        // Height 0: push 1 byte, value 0x00
        assert_eq!(bytes, &[0x01, 0x00]);
    }

    #[test]
    fn test_bip34_height_1() {
        let script = encode_bip34_height(1);
        let bytes = script.as_bytes();
        assert_eq!(bytes, &[0x01, 0x01]);
    }

    #[test]
    fn test_bip34_height_127() {
        let script = encode_bip34_height(127);
        let bytes = script.as_bytes();
        assert_eq!(bytes, &[0x01, 0x7f]);
    }

    #[test]
    fn test_bip34_height_128() {
        let script = encode_bip34_height(128);
        let bytes = script.as_bytes();
        // 128 = 0x80, but 0x80 has sign bit set, so needs extra 0x00 byte
        assert_eq!(bytes, &[0x02, 0x80, 0x00]);
    }

    #[test]
    fn test_bip34_height_255() {
        let script = encode_bip34_height(255);
        let bytes = script.as_bytes();
        // 255 = 0xFF, sign bit set, needs extra byte
        assert_eq!(bytes, &[0x02, 0xff, 0x00]);
    }

    #[test]
    fn test_bip34_height_256() {
        let script = encode_bip34_height(256);
        let bytes = script.as_bytes();
        // 256 = 0x0100 LE
        assert_eq!(bytes, &[0x02, 0x00, 0x01]);
    }

    #[test]
    fn test_bip34_height_500000() {
        let script = encode_bip34_height(500_000);
        let bytes = script.as_bytes();
        // 500000 = 0x07A120, LE = [0x20, 0xA1, 0x07]
        assert_eq!(bytes, &[0x03, 0x20, 0xa1, 0x07]);
    }

    #[test]
    fn test_bip34_height_840000() {
        let script = encode_bip34_height(840_000);
        let bytes = script.as_bytes();
        // 840000 = 0x0CD140, LE = [0x40, 0xD1, 0x0C]
        assert_eq!(bytes, &[0x03, 0x40, 0xd1, 0x0c]);
    }

    #[test]
    fn test_build_script_basic() {
        let extranonce = [0x00u8; 8];
        let script = build_coinbase_script(840_000, &extranonce, None).unwrap();
        let bytes = script.as_bytes();

        // BIP34 height (4 bytes) + extranonce (8 bytes) = 12 bytes
        assert_eq!(bytes.len(), 12);
        // Starts with BIP34 height encoding
        assert_eq!(&bytes[..4], &[0x03, 0x40, 0xd1, 0x0c]);
    }

    #[test]
    fn test_build_script_with_extra_data() {
        let extranonce = [0xaa; 4];
        let extra = b"test";
        let script = build_coinbase_script(840_000, &extranonce, Some(extra)).unwrap();
        let bytes = script.as_bytes();

        assert_eq!(bytes.len(), 4 + 4 + 4); // height + extranonce + extra
        assert_eq!(&bytes[8..12], b"test");
    }

    #[test]
    fn test_build_script_too_long() {
        let extranonce = [0x00; 97]; // 97 + 4 (height) = 101 > 100
        let result = build_coinbase_script(840_000, &extranonce, None);
        assert!(matches!(
            result,
            Err(CoinbaseError::ScriptTooLong {
                size: 101,
                max: 100
            })
        ));
    }

    #[test]
    fn test_remaining_capacity() {
        let cap = remaining_script_capacity(840_000, 8);
        // 100 - 4 (height) - 8 (extranonce) = 88
        assert_eq!(cap, 88);
    }

    #[test]
    fn test_placeholder_script() {
        let script = build_coinbase_script_with_placeholder(840_000, 8, None).unwrap();
        let bytes = script.as_bytes();
        assert_eq!(bytes.len(), 12);
        // Extranonce bytes should be zeros
        assert_eq!(&bytes[4..12], &[0; 8]);
    }
}
