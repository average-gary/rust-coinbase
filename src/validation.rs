//! Coinbase transaction validation.
//!
//! Provides functions to validate coinbase transactions against consensus rules
//! and extract structured data from existing coinbase scriptSigs.

use alloc::vec::Vec;

use bitcoin::{OutPoint, Transaction};

use crate::error::CoinbaseError;
use crate::script::{MAX_COINBASE_SCRIPT_SIZE, MIN_COINBASE_SCRIPT_SIZE};

/// Validate that a transaction has valid coinbase structure.
///
/// Checks:
/// - Exactly one input
/// - Input previous_output is the null outpoint
/// - ScriptSig length is between 2 and 100 bytes
///
/// Returns a list of all validation errors found. An empty `Ok(())` means
/// the transaction passes all checks.
pub fn validate_coinbase_structure(tx: &Transaction) -> Result<(), Vec<CoinbaseError>> {
    let mut errors = Vec::new();

    if tx.input.len() != 1 {
        errors.push(CoinbaseError::InvalidCoinbaseStructure {
            reason: "coinbase transaction must have exactly one input",
        });
    }

    if let Some(input) = tx.input.first() {
        if !input.previous_output.is_null() {
            errors.push(CoinbaseError::InvalidCoinbaseStructure {
                reason: "coinbase input previous_output must be null outpoint",
            });
        }

        let script_len = input.script_sig.as_bytes().len();
        if script_len > MAX_COINBASE_SCRIPT_SIZE {
            errors.push(CoinbaseError::ScriptTooLong {
                size: script_len,
                max: MAX_COINBASE_SCRIPT_SIZE,
            });
        }
        if script_len < MIN_COINBASE_SCRIPT_SIZE {
            errors.push(CoinbaseError::ScriptTooShort {
                size: script_len,
                min: MIN_COINBASE_SCRIPT_SIZE,
            });
        }
    }

    if tx.output.is_empty() {
        errors.push(CoinbaseError::NoOutputs);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate a coinbase transaction including output amount constraints.
///
/// Performs structural validation plus checks that total output value
/// does not exceed the maximum allowed coinbase value (subsidy + fees).
pub fn validate_coinbase(
    tx: &Transaction,
    height: u32,
    total_fees: bitcoin::Amount,
) -> Result<(), Vec<CoinbaseError>> {
    let mut errors = match validate_coinbase_structure(tx) {
        Ok(()) => Vec::new(),
        Err(e) => e,
    };

    let max_value = crate::subsidy::max_coinbase_value(height, total_fees);
    let total_output: bitcoin::Amount = tx
        .output
        .iter()
        .map(|o| o.value)
        .try_fold(bitcoin::Amount::ZERO, |acc, v| acc.checked_add(v))
        .unwrap_or(bitcoin::Amount::MAX);

    if total_output > max_value {
        errors.push(CoinbaseError::OutputAmountOverflow);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Extract the BIP34 block height from a coinbase scriptSig.
///
/// The height is encoded as the first push in the scriptSig as a minimally
/// encoded CScriptNum.
///
/// # Errors
///
/// Returns [`CoinbaseError::InvalidBip34Height`] if the height cannot be decoded.
pub fn extract_bip34_height(script: &bitcoin::Script) -> Result<u32, CoinbaseError> {
    let bytes = script.as_bytes();
    if bytes.is_empty() {
        return Err(CoinbaseError::InvalidBip34Height);
    }

    // The first byte is the push length (for CScriptNum serialization)
    let push_len = bytes[0] as usize;

    // Validate push length
    if push_len == 0 || push_len > 4 {
        return Err(CoinbaseError::InvalidBip34Height);
    }

    if bytes.len() < 1 + push_len {
        return Err(CoinbaseError::InvalidBip34Height);
    }

    let data = &bytes[1..1 + push_len];
    let height = deserialize_script_num(data)?;

    if height < 0 {
        return Err(CoinbaseError::InvalidBip34Height);
    }

    Ok(height as u32)
}

/// Check whether a transaction looks like a coinbase transaction.
///
/// This is a lightweight structural check: single input with null outpoint.
pub fn is_coinbase(tx: &Transaction) -> bool {
    tx.input.len() == 1 && tx.input[0].previous_output == OutPoint::null()
}

/// Deserialize a CScriptNum from its byte representation.
///
/// Returns the integer value, handling little-endian encoding with sign bit.
fn deserialize_script_num(data: &[u8]) -> Result<i64, CoinbaseError> {
    if data.is_empty() {
        return Ok(0);
    }

    // Read as little-endian
    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (i * 8);
    }

    // Check sign bit on the last byte
    if data.last().unwrap() & 0x80 != 0 {
        // Negative: clear the sign bit and negate
        result &= !(0x80i64 << ((data.len() - 1) * 8));
        result = -result;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn make_valid_coinbase() -> Transaction {
        let script = crate::script::build_coinbase_script(840_000, &[0u8; 8], None).unwrap();
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(312_500_000),
                script_pubkey: ScriptBuf::new_op_return(&[]),
            }],
        }
    }

    #[test]
    fn test_valid_coinbase() {
        let tx = make_valid_coinbase();
        assert!(validate_coinbase_structure(&tx).is_ok());
        assert!(is_coinbase(&tx));
    }

    #[test]
    fn test_invalid_no_null_outpoint() {
        let mut tx = make_valid_coinbase();
        tx.input[0].previous_output = OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: 0, // Not 0xFFFFFFFF
        };
        let errors = validate_coinbase_structure(&tx).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, CoinbaseError::InvalidCoinbaseStructure { .. })));
    }

    #[test]
    fn test_invalid_no_outputs() {
        let mut tx = make_valid_coinbase();
        tx.output.clear();
        let errors = validate_coinbase_structure(&tx).unwrap_err();
        assert!(errors.iter().any(|e| matches!(e, CoinbaseError::NoOutputs)));
    }

    #[test]
    fn test_extract_bip34_height() {
        let script = crate::script::encode_bip34_height(840_000);
        let height = extract_bip34_height(&script).unwrap();
        assert_eq!(height, 840_000);
    }

    #[test]
    fn test_extract_bip34_height_from_full_script() {
        let script =
            crate::script::build_coinbase_script(500_000, &[0xab; 8], Some(b"test")).unwrap();
        let height = extract_bip34_height(&script).unwrap();
        assert_eq!(height, 500_000);
    }

    #[test]
    fn test_extract_bip34_various_heights() {
        for height in [0, 1, 127, 128, 255, 256, 500_000, 840_000, 1_000_000] {
            let script = crate::script::encode_bip34_height(height);
            let extracted = extract_bip34_height(&script).unwrap();
            assert_eq!(extracted, height, "failed for height {}", height);
        }
    }

    #[test]
    fn test_output_amount_overflow() {
        let mut tx = make_valid_coinbase();
        tx.output[0].value = Amount::from_sat(999_999_999_999);
        let errors = validate_coinbase(&tx, 840_000, Amount::ZERO).unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, CoinbaseError::OutputAmountOverflow)));
    }
}
