//! Fluent builder for coinbase transactions.
//!
//! The [`CoinbaseBuilder`] is the primary API for constructing coinbase transactions.
//! It provides a discoverable, chainable interface with sensible defaults and
//! clear error reporting.
//!
//! # Examples
//!
//! ## Solo mining
//!
//! ```
//! use rust_coinbase::CoinbaseBuilder;
//! use bitcoin::{Amount, ScriptBuf};
//!
//! let payout_script = ScriptBuf::new_op_return(&[]); // placeholder
//!
//! let tx = CoinbaseBuilder::new(840_000)
//!     .output(payout_script, Amount::from_sat(312_500_000))
//!     .extra_nonce_value(&[0xab; 8])
//!     .build()
//!     .unwrap();
//!
//! assert!(tx.is_coinbase());
//! ```
//!
//! ## With witness commitment
//!
//! ```
//! use rust_coinbase::CoinbaseBuilder;
//! use bitcoin::{Amount, ScriptBuf, WitnessMerkleNode};
//! use bitcoin::hashes::Hash;
//!
//! let payout_script = ScriptBuf::new_op_return(&[]); // placeholder
//! let witness_root = WitnessMerkleNode::all_zeros();
//!
//! let tx = CoinbaseBuilder::new(840_000)
//!     .output(payout_script, Amount::from_sat(312_500_000))
//!     .witness_commitment_from_root(witness_root)
//!     .build()
//!     .unwrap();
//! ```

use alloc::vec;
use alloc::vec::Vec;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, WitnessCommitment,
    WitnessMerkleNode,
};

use crate::error::CoinbaseError;
use crate::script;
use crate::witness as wit;

/// Builder for constructing coinbase transactions.
///
/// Provides a fluent API with sensible defaults for all optional fields.
/// The only required parameter is the block height (set via [`CoinbaseBuilder::new`]).
///
/// Defaults:
/// - Transaction version: 2 (BIP34)
/// - Lock time: 0
/// - Sequence: 0xFFFFFFFF
/// - Extra nonce size: 8 bytes (zeroed placeholder)
/// - No witness commitment (add via [`witness_commitment`] or [`witness_commitment_from_root`])
///
/// [`witness_commitment`]: CoinbaseBuilder::witness_commitment
/// [`witness_commitment_from_root`]: CoinbaseBuilder::witness_commitment_from_root
#[derive(Debug, Clone)]
pub struct CoinbaseBuilder {
    height: u32,
    version: Version,
    lock_time: LockTime,
    sequence: Sequence,
    outputs: Vec<TxOut>,
    extra_nonce_size: usize,
    extra_nonce_value: Option<Vec<u8>>,
    extra_data: Option<Vec<u8>>,
    witness_commitment: Option<WitnessCommitment>,
    witness_reserved_value: [u8; 32],
    include_witness: bool,
}

impl CoinbaseBuilder {
    /// Create a new coinbase builder for the given block height.
    ///
    /// The height is encoded per BIP34 as the first item in the coinbase
    /// scriptSig.
    pub fn new(height: u32) -> Self {
        Self {
            height,
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            sequence: Sequence::MAX,
            outputs: Vec::new(),
            extra_nonce_size: 8,
            extra_nonce_value: None,
            extra_data: None,
            witness_commitment: None,
            witness_reserved_value: wit::DEFAULT_WITNESS_RESERVED_VALUE,
            include_witness: false,
        }
    }

    /// Set the transaction version.
    ///
    /// Default: [`Version::TWO`] (required by BIP34).
    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Set the lock time.
    ///
    /// Default: [`LockTime::ZERO`].
    pub fn lock_time(mut self, lock_time: LockTime) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Set the input sequence number.
    ///
    /// Default: [`Sequence::MAX`] (0xFFFFFFFF).
    pub fn sequence(mut self, sequence: Sequence) -> Self {
        self.sequence = sequence;
        self
    }

    /// Add a payout output to the coinbase transaction.
    ///
    /// Call this multiple times to add multiple outputs (e.g., pool payout
    /// splits, development fund contributions).
    pub fn output(mut self, script_pubkey: ScriptBuf, value: Amount) -> Self {
        self.outputs.push(TxOut {
            value,
            script_pubkey,
        });
        self
    }

    /// Add a pre-built `TxOut` to the coinbase transaction.
    pub fn output_raw(mut self, output: TxOut) -> Self {
        self.outputs.push(output);
        self
    }

    /// Set the extranonce space reservation size (in bytes).
    ///
    /// This reserves space in the coinbase scriptSig for the extranonce.
    /// The extranonce bytes will be zeroed in the built transaction unless
    /// a specific value is set via [`extra_nonce_value`].
    ///
    /// Default: 8 bytes.
    ///
    /// Set to 0 to disable extranonce reservation.
    ///
    /// [`extra_nonce_value`]: CoinbaseBuilder::extra_nonce_value
    pub fn extra_nonce_size(mut self, size: usize) -> Self {
        self.extra_nonce_size = size;
        self
    }

    /// Set a specific extranonce value.
    ///
    /// The length of the value determines the extranonce size, overriding
    /// any value set via [`extra_nonce_size`].
    ///
    /// [`extra_nonce_size`]: CoinbaseBuilder::extra_nonce_size
    pub fn extra_nonce_value(mut self, value: &[u8]) -> Self {
        self.extra_nonce_size = value.len();
        self.extra_nonce_value = Some(value.to_vec());
        self
    }

    /// Set arbitrary extra data to embed in the coinbase scriptSig.
    ///
    /// This data is appended after the BIP34 height and extranonce.
    /// Must fit within the 100-byte scriptSig limit.
    pub fn extra_data(mut self, data: &[u8]) -> Self {
        self.extra_data = Some(data.to_vec());
        self
    }

    /// Set a pre-computed witness commitment.
    ///
    /// This adds an `OP_RETURN` output with the witness commitment and
    /// sets up the coinbase input witness with the reserved value.
    pub fn witness_commitment(mut self, commitment: WitnessCommitment) -> Self {
        self.witness_commitment = Some(commitment);
        self.include_witness = true;
        self
    }

    /// Compute and set the witness commitment from a witness merkle root.
    ///
    /// Uses the default (all-zeros) witness reserved value.
    pub fn witness_commitment_from_root(mut self, witness_root: WitnessMerkleNode) -> Self {
        let commitment =
            wit::compute_witness_commitment(&witness_root, &self.witness_reserved_value);
        self.witness_commitment = Some(commitment);
        self.include_witness = true;
        self
    }

    /// Compute and set the witness commitment from a list of transaction wtxids.
    ///
    /// Computes the witness merkle root from the provided wtxids (excluding
    /// the coinbase, which is handled internally) and then computes the
    /// witness commitment.
    pub fn witness_commitment_from_wtxids(mut self, wtxids: &[bitcoin::Wtxid]) -> Self {
        if let Some(root) = wit::compute_witness_root(wtxids) {
            let commitment = wit::compute_witness_commitment(&root, &self.witness_reserved_value);
            self.witness_commitment = Some(commitment);
        }
        self.include_witness = true;
        self
    }

    /// Set a custom witness reserved value.
    ///
    /// Default: all zeros. The witness reserved value is placed in the
    /// coinbase input witness and used in the witness commitment hash.
    /// This is reserved for future soft fork extensions.
    pub fn witness_reserved_value(mut self, value: [u8; 32]) -> Self {
        self.witness_reserved_value = value;
        self
    }

    /// Enable the coinbase witness (32-byte zero element) without setting
    /// a witness commitment output.
    ///
    /// This is useful when constructing a coinbase template where the witness
    /// commitment will be filled in later.
    pub fn with_witness(mut self) -> Self {
        self.include_witness = true;
        self
    }

    /// Build the coinbase transaction.
    ///
    /// # Errors
    ///
    /// Returns [`CoinbaseError`] if:
    /// - No outputs have been specified
    /// - The scriptSig exceeds 100 bytes or is less than 2 bytes
    /// - The extranonce doesn't fit in the available scriptSig space
    pub fn build(&self) -> Result<Transaction, CoinbaseError> {
        // Validate outputs
        if self.outputs.is_empty() {
            return Err(CoinbaseError::NoOutputs);
        }

        // Build the extranonce bytes
        let extranonce = match &self.extra_nonce_value {
            Some(v) => v.clone(),
            None => vec![0u8; self.extra_nonce_size],
        };

        // Check extranonce fits
        let available = script::remaining_script_capacity(self.height, 0);
        let extra_data_len = self.extra_data.as_ref().map(|d| d.len()).unwrap_or(0);
        let total_needed = extranonce.len() + extra_data_len;
        if total_needed > available {
            return Err(CoinbaseError::ExtraNonceTooLarge {
                requested: total_needed,
                available,
            });
        }

        // Build the coinbase scriptSig
        let script_sig =
            script::build_coinbase_script(self.height, &extranonce, self.extra_data.as_deref())?;

        // Build the witness
        let witness = if self.include_witness {
            wit::coinbase_witness_with_reserved_value(&self.witness_reserved_value)
        } else {
            Witness::new()
        };

        // Build outputs, appending witness commitment if set
        let mut outputs = self.outputs.clone();
        if let Some(commitment) = &self.witness_commitment {
            outputs.push(wit::build_witness_commitment_output(*commitment));
        }

        let tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig,
                sequence: self.sequence,
                witness,
            }],
            output: outputs,
        };

        Ok(tx)
    }

    /// Return the byte offset within the serialized coinbase scriptSig where
    /// the extranonce begins.
    ///
    /// This is useful for the Stratum split model and for directly patching
    /// the extranonce in a serialized transaction.
    pub fn extranonce_offset(&self) -> usize {
        script::bip34_height_size(self.height)
    }

    /// Return the current configured extranonce size.
    pub fn get_extra_nonce_size(&self) -> usize {
        self.extra_nonce_size
    }

    /// Return the current configured block height.
    pub fn get_height(&self) -> u32 {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Amount;

    fn dummy_payout_script() -> ScriptBuf {
        // A simple P2PKH-ish script for testing
        ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH20
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac, // OP_EQUALVERIFY OP_CHECKSIG
        ])
    }

    #[test]
    fn test_basic_build() {
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(312_500_000))
            .build()
            .unwrap();

        assert!(tx.is_coinbase());
        assert_eq!(tx.input.len(), 1);
        assert!(tx.input[0].previous_output.is_null());
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::from_sat(312_500_000));
    }

    #[test]
    fn test_bip34_height_in_script() {
        let tx = CoinbaseBuilder::new(500_000)
            .output(dummy_payout_script(), Amount::from_sat(1))
            .build()
            .unwrap();

        let height = crate::validation::extract_bip34_height(&tx.input[0].script_sig).unwrap();
        assert_eq!(height, 500_000);
    }

    #[test]
    fn test_with_witness_commitment() {
        let root = WitnessMerkleNode::all_zeros();
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(312_500_000))
            .witness_commitment_from_root(root)
            .build()
            .unwrap();

        // Should have 2 outputs: payout + witness commitment
        assert_eq!(tx.output.len(), 2);
        assert!(wit::is_witness_commitment_script(
            &tx.output[1].script_pubkey
        ));

        // Should have witness with 32-byte zero element
        assert_eq!(tx.input[0].witness.len(), 1);
        assert_eq!(tx.input[0].witness.nth(0).unwrap(), &[0u8; 32]);
    }

    #[test]
    fn test_extra_nonce_value() {
        let nonce = [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89];
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(1))
            .extra_nonce_value(&nonce)
            .build()
            .unwrap();

        let script_bytes = tx.input[0].script_sig.as_bytes();
        let offset = script::bip34_height_size(840_000);
        assert_eq!(&script_bytes[offset..offset + 8], &nonce);
    }

    #[test]
    fn test_extra_data() {
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(1))
            .extra_nonce_size(4)
            .extra_data(b"\xf0\x0d")
            .build()
            .unwrap();

        let script_bytes = tx.input[0].script_sig.as_bytes();
        let offset = script::bip34_height_size(840_000) + 4; // height + extranonce
        assert_eq!(&script_bytes[offset..offset + 2], b"\xf0\x0d");
    }

    #[test]
    fn test_no_outputs_error() {
        let result = CoinbaseBuilder::new(840_000).build();
        assert!(matches!(result, Err(CoinbaseError::NoOutputs)));
    }

    #[test]
    fn test_multiple_outputs() {
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(200_000_000))
            .output(dummy_payout_script(), Amount::from_sat(112_500_000))
            .build()
            .unwrap();

        assert_eq!(tx.output.len(), 2);
    }

    #[test]
    fn test_zero_extranonce() {
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(1))
            .extra_nonce_size(0)
            .build()
            .unwrap();

        // Script should be just the BIP34 height encoding
        let script_bytes = tx.input[0].script_sig.as_bytes();
        assert_eq!(script_bytes.len(), script::bip34_height_size(840_000));
    }

    #[test]
    fn test_version_and_locktime() {
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(1))
            .version(Version::ONE)
            .lock_time(LockTime::from_consensus(42))
            .sequence(Sequence::from_consensus(0))
            .build()
            .unwrap();

        assert_eq!(tx.version, Version::ONE);
        assert_eq!(tx.lock_time, LockTime::from_consensus(42));
        assert_eq!(tx.input[0].sequence, Sequence::from_consensus(0));
    }

    #[test]
    fn test_extranonce_offset() {
        let builder = CoinbaseBuilder::new(840_000);
        // Height 840000 encodes as 4 bytes: [0x03, 0x40, 0xD1, 0x0C]
        assert_eq!(builder.extranonce_offset(), 4);
    }

    #[test]
    fn test_with_witness_no_commitment() {
        let tx = CoinbaseBuilder::new(840_000)
            .output(dummy_payout_script(), Amount::from_sat(1))
            .with_witness()
            .build()
            .unwrap();

        // Witness should be set but no commitment output
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.input[0].witness.len(), 1);
    }
}
