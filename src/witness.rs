//! SegWit witness commitment construction (BIP141).
//!
//! Provides functions to compute the witness merkle root, witness commitment,
//! and construct the corresponding coinbase output and input witness.
//!
//! ## Witness Commitment Structure
//!
//! The witness commitment is placed in a coinbase output as:
//! ```text
//! OP_RETURN OP_PUSHBYTES_36 [aa21a9ed] [32-byte commitment hash]
//! ```
//!
//! The commitment hash is `SHA256d(witness_root_hash || witness_reserved_value)`.

use bitcoin::blockdata::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, TxOut, Witness, WitnessCommitment, WitnessMerkleNode, Wtxid};

/// The 4-byte magic prefix for the witness commitment in the scriptPubKey.
/// `0xaa21a9ed` identifies a SegWit witness commitment output.
pub const WITNESS_COMMITMENT_HEADER: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Default witness reserved value: 32 zero bytes.
///
/// BIP141 requires the coinbase input witness to contain a single 32-byte
/// element. By convention this is all zeros, reserved for future soft fork
/// commitments.
pub const DEFAULT_WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// Compute the witness merkle root from a list of transaction wtxids.
///
/// Per BIP141, the coinbase's wtxid is replaced with 32 zero bytes.
/// The `wtxids` slice should contain the wtxids of all transactions in the
/// block **excluding** the coinbase (the coinbase's zero-wtxid is prepended
/// internally).
///
/// # Returns
///
/// The witness merkle root, or `None` if the wtxid list is empty (which would
/// mean a block with only the coinbase transaction -- in that case the witness
/// commitment is optional).
pub fn compute_witness_root(wtxids: &[Wtxid]) -> Option<WitnessMerkleNode> {
    // Prepend the coinbase's zero wtxid
    let coinbase_wtxid = Wtxid::all_zeros();

    let hashes = core::iter::once(coinbase_wtxid.to_raw_hash())
        .chain(wtxids.iter().map(|w| w.to_raw_hash()));

    bitcoin::merkle_tree::calculate_root(hashes).map(|h| h.into())
}

/// Compute the witness commitment from a witness merkle root and reserved value.
///
/// The commitment is `SHA256d(witness_root || witness_reserved_value)`.
///
/// Uses [`DEFAULT_WITNESS_RESERVED_VALUE`] (all zeros) unless a custom
/// reserved value is needed for future soft fork chaining.
pub fn compute_witness_commitment(
    witness_root: &WitnessMerkleNode,
    witness_reserved_value: &[u8; 32],
) -> WitnessCommitment {
    Block::compute_witness_commitment(witness_root, witness_reserved_value)
}

/// Compute the witness commitment using the default (all-zeros) reserved value.
pub fn compute_witness_commitment_default(witness_root: &WitnessMerkleNode) -> WitnessCommitment {
    compute_witness_commitment(witness_root, &DEFAULT_WITNESS_RESERVED_VALUE)
}

/// Build the witness commitment output (`OP_RETURN` output) for the coinbase.
///
/// Creates a `TxOut` with `value = 0` and a scriptPubKey of:
/// ```text
/// OP_RETURN OP_PUSHBYTES_36 [aa21a9ed] [32-byte commitment]
/// ```
pub fn build_witness_commitment_output(commitment: WitnessCommitment) -> TxOut {
    let mut data = bitcoin::script::PushBytesBuf::with_capacity(36);
    data.extend_from_slice(&WITNESS_COMMITMENT_HEADER)
        .expect("36 bytes fits in PushBytesBuf");
    data.extend_from_slice(commitment.as_byte_array())
        .expect("36 bytes fits in PushBytesBuf");

    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(data),
    }
}

/// Build the default coinbase input witness.
///
/// BIP141 requires the coinbase input to have a witness with a single
/// 32-byte element (the witness reserved value). By convention this is
/// all zeros.
pub fn default_coinbase_witness() -> Witness {
    let mut witness = Witness::new();
    witness.push(DEFAULT_WITNESS_RESERVED_VALUE);
    witness
}

/// Build a coinbase input witness with a custom reserved value.
pub fn coinbase_witness_with_reserved_value(reserved_value: &[u8; 32]) -> Witness {
    let mut witness = Witness::new();
    witness.push(reserved_value);
    witness
}

/// Check if a script contains a witness commitment (starts with `OP_RETURN 0xaa21a9ed`).
///
/// This checks the first 6 bytes of the scriptPubKey:
/// `0x6a` (OP_RETURN) + `0x24` (push 36 bytes) + `0xaa21a9ed` (magic).
pub fn is_witness_commitment_script(script: &bitcoin::Script) -> bool {
    let bytes = script.as_bytes();
    bytes.len() >= 38
        && bytes[0] == 0x6a  // OP_RETURN
        && bytes[1] == 0x24  // push 36 bytes
        && bytes[2..6] == WITNESS_COMMITMENT_HEADER
}

/// Extract the witness commitment from a coinbase transaction.
///
/// Per BIP141, if multiple outputs match the witness commitment pattern,
/// the one with the highest index is the commitment.
///
/// Returns `None` if no witness commitment is found.
pub fn extract_witness_commitment(tx: &bitcoin::Transaction) -> Option<WitnessCommitment> {
    // Iterate outputs in reverse to find the highest-index match
    for output in tx.output.iter().rev() {
        if is_witness_commitment_script(&output.script_pubkey) {
            let bytes = output.script_pubkey.as_bytes();
            // The commitment is bytes 6..38 (32 bytes after the 4-byte header)
            let commitment_bytes: [u8; 32] =
                bytes[6..38].try_into().expect("slice is exactly 32 bytes");
            return Some(WitnessCommitment::from_byte_array(
                bitcoin::hashes::sha256d::Hash::from_byte_array(commitment_bytes).to_byte_array(),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_default_coinbase_witness() {
        let witness = default_coinbase_witness();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness.nth(0).unwrap(), &[0u8; 32]);
    }

    #[test]
    fn test_witness_commitment_output_structure() {
        // Create a dummy commitment
        let root = WitnessMerkleNode::all_zeros();
        let commitment = compute_witness_commitment_default(&root);
        let output = build_witness_commitment_output(commitment);

        assert_eq!(output.value, Amount::ZERO);

        let script_bytes = output.script_pubkey.as_bytes();
        assert_eq!(script_bytes[0], 0x6a); // OP_RETURN
        assert_eq!(script_bytes[1], 0x24); // push 36 bytes
        assert_eq!(&script_bytes[2..6], &WITNESS_COMMITMENT_HEADER);
        assert_eq!(script_bytes.len(), 38);
    }

    #[test]
    fn test_is_witness_commitment_script() {
        let root = WitnessMerkleNode::all_zeros();
        let commitment = compute_witness_commitment_default(&root);
        let output = build_witness_commitment_output(commitment);
        assert!(is_witness_commitment_script(&output.script_pubkey));
    }

    #[test]
    fn test_is_not_witness_commitment_script() {
        // Regular OP_RETURN without the magic
        let script = ScriptBuf::new_op_return(&[0x00; 36]);
        assert!(!is_witness_commitment_script(&script));
    }

    #[test]
    fn test_witness_root_single_coinbase() {
        // Block with only coinbase: witness root is just the coinbase zero-wtxid
        let root = compute_witness_root(&[]);
        // With no non-coinbase txs, the only hash is the coinbase zero-wtxid
        // The merkle root of a single item is that item itself
        assert!(root.is_some());
        let root = root.unwrap();
        assert_eq!(
            root,
            WitnessMerkleNode::from_byte_array(Wtxid::all_zeros().to_byte_array())
        );
    }
}
