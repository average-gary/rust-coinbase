//! Stratum coinbase split model.
//!
//! In pool mining (Stratum V1), the coinbase transaction is split into two
//! segments around the extranonce:
//!
//! ```text
//! coinbase1 || extranonce1 || extranonce2 || coinbase2
//! ```
//!
//! The pool sends `coinbase1` and `coinbase2` to each worker. The pool assigns
//! a unique `extranonce1` per worker connection, and the worker iterates through
//! `extranonce2` values to search for valid blocks.
//!
//! This module provides [`CoinbaseSplit`] for producing and reassembling
//! coinbase transactions in this split format, optimized for the hot path
//! in mining operations.

use alloc::vec::Vec;

use bitcoin::consensus::Decodable;
use bitcoin::Transaction;

use crate::builder::CoinbaseBuilder;
use crate::error::CoinbaseError;
use crate::script;

/// A coinbase transaction split into two segments around the extranonce slot.
///
/// This is the format used by Stratum V1 pools to distribute work to miners.
///
/// The full serialized coinbase transaction can be reconstructed as:
/// `coinbase1 || extranonce1 || extranonce2 || coinbase2`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseSplit {
    /// Everything before the extranonce in the serialized coinbase transaction.
    /// Includes: version, input count, null outpoint, scriptSig length,
    /// BIP34 height encoding.
    pub coinbase1: Vec<u8>,

    /// Everything after the extranonce in the serialized coinbase transaction.
    /// Includes: remaining scriptSig data, sequence, outputs, witness, locktime.
    pub coinbase2: Vec<u8>,

    /// Size of extranonce1 (pool-assigned, unique per worker).
    pub extranonce1_size: usize,

    /// Size of extranonce2 (worker-iterated).
    pub extranonce2_size: usize,
}

impl CoinbaseSplit {
    /// Reassemble the full coinbase transaction from extranonce values.
    ///
    /// Concatenates `coinbase1 || extranonce1 || extranonce2 || coinbase2`
    /// and deserializes back into a [`Transaction`].
    ///
    /// # Errors
    ///
    /// Returns [`CoinbaseError::ExtraNonceSizeMismatch`] if the provided
    /// extranonce values don't match the expected sizes.
    pub fn assemble(
        &self,
        extranonce1: &[u8],
        extranonce2: &[u8],
    ) -> Result<Transaction, CoinbaseError> {
        let raw = self.assemble_raw(extranonce1, extranonce2)?;
        let mut cursor = &raw[..];
        Transaction::consensus_decode(&mut cursor).map_err(|_| {
            CoinbaseError::InvalidCoinbaseStructure {
                reason: "failed to decode reassembled coinbase transaction",
            }
        })
    }

    /// Reassemble the raw serialized coinbase transaction bytes.
    ///
    /// This is the fast path for pool operations: it produces the raw bytes
    /// suitable for direct hashing into a merkle root calculation, avoiding
    /// the overhead of full transaction deserialization.
    ///
    /// # Errors
    ///
    /// Returns [`CoinbaseError::ExtraNonceSizeMismatch`] if the provided
    /// extranonce values don't match the expected sizes.
    pub fn assemble_raw(
        &self,
        extranonce1: &[u8],
        extranonce2: &[u8],
    ) -> Result<Vec<u8>, CoinbaseError> {
        if extranonce1.len() != self.extranonce1_size {
            return Err(CoinbaseError::ExtraNonceSizeMismatch {
                expected: self.extranonce1_size,
                got: extranonce1.len(),
            });
        }
        if extranonce2.len() != self.extranonce2_size {
            return Err(CoinbaseError::ExtraNonceSizeMismatch {
                expected: self.extranonce2_size,
                got: extranonce2.len(),
            });
        }

        let total_len = self.coinbase1.len()
            + self.extranonce1_size
            + self.extranonce2_size
            + self.coinbase2.len();

        let mut raw = Vec::with_capacity(total_len);
        raw.extend_from_slice(&self.coinbase1);
        raw.extend_from_slice(extranonce1);
        raw.extend_from_slice(extranonce2);
        raw.extend_from_slice(&self.coinbase2);

        Ok(raw)
    }

    /// Total extranonce size (extranonce1 + extranonce2).
    pub fn total_extranonce_size(&self) -> usize {
        self.extranonce1_size + self.extranonce2_size
    }

    /// Total serialized size of the coinbase transaction (with zero extranonces).
    pub fn total_size(&self) -> usize {
        self.coinbase1.len() + self.extranonce1_size + self.extranonce2_size + self.coinbase2.len()
    }
}

impl CoinbaseBuilder {
    /// Build a [`CoinbaseSplit`] for Stratum pool distribution.
    ///
    /// The coinbase transaction is built with a zeroed extranonce placeholder,
    /// serialized, and split at the extranonce boundary.
    ///
    /// # Arguments
    ///
    /// * `extranonce1_size` - Bytes reserved for the pool-assigned extranonce1.
    /// * `extranonce2_size` - Bytes reserved for the worker-iterated extranonce2.
    ///
    /// The total `extranonce1_size + extranonce2_size` must fit within the
    /// coinbase scriptSig's available space.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_coinbase::{CoinbaseBuilder, CoinbaseSplit};
    /// use bitcoin::{Amount, ScriptBuf};
    ///
    /// let payout = ScriptBuf::new_op_return(&[]);
    ///
    /// let split = CoinbaseBuilder::new(840_000)
    ///     .output(payout, Amount::from_sat(312_500_000))
    ///     .build_split(4, 4)
    ///     .unwrap();
    ///
    /// // Reassemble with specific extranonce values
    /// let tx = split.assemble(&[0x01; 4], &[0x02; 4]).unwrap();
    /// assert!(tx.is_coinbase());
    /// ```
    pub fn build_split(
        &self,
        extranonce1_size: usize,
        extranonce2_size: usize,
    ) -> Result<CoinbaseSplit, CoinbaseError> {
        let total_extranonce = extranonce1_size + extranonce2_size;

        // Build with exact extranonce size, zeroed placeholder
        let builder = self.clone().extra_nonce_size(total_extranonce);
        let tx = builder.build()?;

        // Serialize the transaction
        let raw = bitcoin::consensus::serialize(&tx);

        // Find the extranonce position within the serialized bytes.
        // The serialized layout is:
        //   [4 bytes version]
        //   [optional 2 bytes segwit marker+flag: 0x00 0x01]
        //   [varint input_count = 1]
        //   [32 bytes null txid]
        //   [4 bytes null vout = 0xFFFFFFFF]
        //   [varint scriptSig_len]
        //   [scriptSig bytes...]
        //   ...
        //
        // The extranonce starts at scriptSig_offset + bip34_height_size.

        let has_witness = !tx.input[0].witness.is_empty();

        let mut offset = 4; // version

        if has_witness {
            offset += 2; // segwit marker + flag
        }

        offset += 1; // varint for input count (always 1 for coinbase)
        offset += 32; // null txid
        offset += 4; // null vout (0xFFFFFFFF)

        // scriptSig length varint
        let script_len = tx.input[0].script_sig.as_bytes().len();
        let varint_len = varint_size(script_len as u64);
        offset += varint_len;

        // BIP34 height encoding
        let height_size = script::bip34_height_size(self.get_height());
        offset += height_size;

        // Now `offset` points to the start of the extranonce in the raw bytes
        let extranonce_start = offset;
        let extranonce_end = extranonce_start + total_extranonce;

        let coinbase1 = raw[..extranonce_start].to_vec();
        let coinbase2 = raw[extranonce_end..].to_vec();

        Ok(CoinbaseSplit {
            coinbase1,
            coinbase2,
            extranonce1_size,
            extranonce2_size,
        })
    }
}

/// Calculate the size of a Bitcoin varint encoding.
fn varint_size(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x10000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, ScriptBuf};

    fn dummy_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
        ])
    }

    #[test]
    fn test_split_and_reassemble() {
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(312_500_000))
            .build_split(4, 4)
            .unwrap();

        assert_eq!(split.extranonce1_size, 4);
        assert_eq!(split.extranonce2_size, 4);

        // Reassemble with specific extranonce values
        let en1 = [0x11, 0x22, 0x33, 0x44];
        let en2 = [0x55, 0x66, 0x77, 0x88];
        let tx = split.assemble(&en1, &en2).unwrap();

        assert!(tx.is_coinbase());

        // Verify extranonce is in the script
        let script_bytes = tx.input[0].script_sig.as_bytes();
        let offset = script::bip34_height_size(840_000);
        assert_eq!(&script_bytes[offset..offset + 4], &en1);
        assert_eq!(&script_bytes[offset + 4..offset + 8], &en2);
    }

    #[test]
    fn test_split_with_witness() {
        let root = bitcoin::WitnessMerkleNode::all_zeros();
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(312_500_000))
            .witness_commitment_from_root(root)
            .build_split(4, 4)
            .unwrap();

        let tx = split.assemble(&[0x01; 4], &[0x02; 4]).unwrap();
        assert!(tx.is_coinbase());
        // Should have witness commitment output
        assert_eq!(tx.output.len(), 2);
        assert!(crate::witness::is_witness_commitment_script(
            &tx.output[1].script_pubkey
        ));
    }

    #[test]
    fn test_split_size_mismatch() {
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(1))
            .build_split(4, 4)
            .unwrap();

        // Wrong extranonce1 size
        let result = split.assemble(&[0x01; 3], &[0x02; 4]);
        assert!(matches!(
            result,
            Err(CoinbaseError::ExtraNonceSizeMismatch {
                expected: 4,
                got: 3
            })
        ));

        // Wrong extranonce2 size
        let result = split.assemble(&[0x01; 4], &[0x02; 5]);
        assert!(matches!(
            result,
            Err(CoinbaseError::ExtraNonceSizeMismatch {
                expected: 4,
                got: 5
            })
        ));
    }

    #[test]
    fn test_split_different_extranonces_produce_different_txs() {
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(312_500_000))
            .build_split(4, 4)
            .unwrap();

        let raw1 = split.assemble_raw(&[0x01; 4], &[0x01; 4]).unwrap();
        let raw2 = split.assemble_raw(&[0x02; 4], &[0x01; 4]).unwrap();
        let raw3 = split.assemble_raw(&[0x01; 4], &[0x02; 4]).unwrap();

        assert_ne!(raw1, raw2);
        assert_ne!(raw1, raw3);
        assert_ne!(raw2, raw3);
    }

    #[test]
    fn test_split_round_trip_matches_direct_build() {
        // Build directly with specific extranonce
        let en = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let direct_tx = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(312_500_000))
            .extra_nonce_value(&en)
            .build()
            .unwrap();

        // Build via split and reassemble
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(312_500_000))
            .build_split(4, 4)
            .unwrap();

        let split_tx = split.assemble(&en[..4], &en[4..]).unwrap();

        // The transactions should be identical
        let direct_raw = bitcoin::consensus::serialize(&direct_tx);
        let split_raw = bitcoin::consensus::serialize(&split_tx);
        assert_eq!(direct_raw, split_raw);
    }

    #[test]
    fn test_total_size() {
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(1))
            .build_split(4, 4)
            .unwrap();

        let expected_total = split.coinbase1.len() + 4 + 4 + split.coinbase2.len();
        assert_eq!(split.total_size(), expected_total);

        // Verify it matches actual serialized tx size
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(1))
            .extra_nonce_size(8)
            .build()
            .unwrap();
        let raw = bitcoin::consensus::serialize(&tx);
        assert_eq!(split.total_size(), raw.len());
    }

    #[test]
    fn test_split_with_extra_data() {
        let split = CoinbaseBuilder::new(840_000)
            .output(dummy_script(), Amount::from_sat(1))
            .extra_data(b"\xde\xad")
            .build_split(4, 4)
            .unwrap();

        let tx = split.assemble(&[0x01; 4], &[0x02; 4]).unwrap();
        let script_bytes = tx.input[0].script_sig.as_bytes();
        let offset = script::bip34_height_size(840_000) + 8; // height + extranonce
        assert_eq!(&script_bytes[offset..offset + 2], b"\xde\xad");
    }
}
