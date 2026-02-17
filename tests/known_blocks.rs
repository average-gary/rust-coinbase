//! Integration tests against real mainnet coinbase transactions.
//!
//! These tests verify that rust-coinbase's parsing, validation, and subsidy
//! calculations produce correct results when applied to actual Bitcoin
//! mainnet coinbase transactions from notable blocks.

use bitcoin::consensus::deserialize;
use bitcoin::{Amount, Transaction};
use rust_coinbase::{subsidy, validation, witness};

/// Test vector for a known mainnet coinbase transaction.
struct CoinbaseVector {
    /// Block height.
    height: u32,
    /// Description of the block's significance.
    description: &'static str,
    /// Raw serialized coinbase transaction in hex.
    raw_hex: &'static str,
    /// Number of outputs in the coinbase transaction.
    num_outputs: usize,
    /// Total output value in satoshis.
    total_output_sats: u64,
    /// Expected block subsidy in satoshis (excluding fees).
    subsidy_sats: u64,
    /// Whether this block has a SegWit witness commitment.
    has_witness_commitment: bool,
    /// Whether BIP34 height extraction should succeed.
    /// Pre-BIP34 blocks (0, 170) use a different scriptSig format.
    has_bip34_height: bool,
}

const TEST_VECTORS: &[CoinbaseVector] = &[
    // Block 0 - Genesis block
    // Satoshi's "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    CoinbaseVector {
        height: 0,
        description: "Genesis block",
        raw_hex: "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        num_outputs: 1,
        total_output_sats: 5_000_000_000,
        subsidy_sats: 5_000_000_000,
        has_witness_commitment: false,
        has_bip34_height: false,
    },
    // Block 170 - First block with a non-coinbase transaction
    CoinbaseVector {
        height: 170,
        description: "First block with a non-coinbase transaction",
        raw_hex: "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0102ffffffff0100f2052a01000000434104d46c4968bde02899d2aa0963367c7a6ce34eec332b32e42e5f3407e052d64ac625da6f0718e7b302140434bd725706957c092db53805b821a85b23a7ac61725bac00000000",
        num_outputs: 1,
        total_output_sats: 5_000_000_000,
        subsidy_sats: 5_000_000_000,
        has_witness_commitment: false,
        has_bip34_height: false,
    },
    // Block 227836 - First BIP34 block (block height in coinbase scriptSig)
    // Mined by Slush pool. ScriptSig starts with 03fc7903 = push 3 bytes [fc, 79, 03]
    // which is 0x0379fc = 227,836 in little-endian.
    CoinbaseVector {
        height: 227_836,
        description: "First BIP34 block",
        raw_hex: "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2703fc7903062f503253482f04ac204f510858029a11000003550d3363646164312f736c7573682f0000000001207e6295000000001976a914e285a29e0704004d4e95dbb7c57a98563d9fb2eb88ac00000000",
        num_outputs: 1,
        total_output_sats: 2_506_260_000,
        subsidy_sats: 2_500_000_000, // second era: 25 BTC
        has_witness_commitment: false,
        has_bip34_height: true,
    },
    // Block 481824 - First SegWit block
    // Mined by BTCC. Has witness commitment in OP_RETURN output.
    CoinbaseVector {
        height: 481_824,
        description: "First SegWit block",
        raw_hex: "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff6403205a07f4d3f9da09acf878c2c9c96c410d69758f0eae0e479184e0564589052e832c42899c867100010000000000000000db9901006052ce25d80acfde2f425443432f20537570706f7274202f4e59412f00000000000000000000000000000000000000000000025d322c57000000001976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac0000000000000000266a24aa21a9ed6c3c4dff76b5760d58694147264d208689ee07823e5694c4872f856eacf5a5d80120000000000000000000000000000000000000000000000000000000000000000000000000",
        num_outputs: 2,
        total_output_sats: 1_462_514_269,
        subsidy_sats: 1_250_000_000, // third era: 12.5 BTC
        has_witness_commitment: true,
        has_bip34_height: true,
    },
    // Block 840000 - Fourth halving block
    // Mined by ViaBTC. 3 outputs: P2PKH reward, RSK merge-mining OP_RETURN,
    // SegWit witness commitment OP_RETURN.
    CoinbaseVector {
        height: 840_000,
        description: "Fourth halving block",
        raw_hex: "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff600340d10c192f5669614254432f4d696e65642062792062757a7a3132302f2cfabe6d6d144b553283a6e1a150c9989428c0695e3a1bef7d482ed1f829bbe25897fd37dc10000000000000001058a4c9000cc3a31889b38ae08249000000000000ffffffff03fb80e4f2000000001976a914536ffa992491508dca0354e52f32a3a7a679a53a88ac00000000000000002b6a2952534b424c4f434b3a52e15efafb3e2cf6dc2fc0e6bde5cb1d7d2143f1e089bd874e6b7913005fb2a00000000000000000266a24aa21a9ed88601d3d03ccce017fe2131c4c95a7292e4372983148e62996bb5e2de0e4d1d80120000000000000000000000000000000000000000000000000000000000000000000000000",
        num_outputs: 3,
        total_output_sats: 4_075_061_499,
        subsidy_sats: 312_500_000, // fourth era: 3.125 BTC
        has_witness_commitment: true,
        has_bip34_height: true,
    },
];

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn parse_coinbase(vector: &CoinbaseVector) -> Transaction {
    let raw = decode_hex(vector.raw_hex);
    deserialize::<Transaction>(&raw).unwrap_or_else(|e| {
        panic!(
            "Failed to deserialize block {} coinbase: {}",
            vector.height, e
        )
    })
}

// ============================================================
// Structural validation tests
// ============================================================

#[test]
fn test_all_vectors_are_coinbase() {
    for v in TEST_VECTORS {
        let tx = parse_coinbase(v);
        assert!(
            tx.is_coinbase(),
            "Block {} ({}) should be identified as coinbase",
            v.height,
            v.description
        );
        assert!(
            validation::is_coinbase(&tx),
            "Block {} ({}) should pass is_coinbase()",
            v.height,
            v.description
        );
    }
}

#[test]
fn test_all_vectors_pass_structural_validation() {
    for v in TEST_VECTORS {
        let tx = parse_coinbase(v);
        let result = validation::validate_coinbase_structure(&tx);
        assert!(
            result.is_ok(),
            "Block {} ({}) failed structural validation: {:?}",
            v.height,
            v.description,
            result.err()
        );
    }
}

#[test]
fn test_output_counts() {
    for v in TEST_VECTORS {
        let tx = parse_coinbase(v);
        assert_eq!(
            tx.output.len(),
            v.num_outputs,
            "Block {} ({}) output count mismatch",
            v.height,
            v.description
        );
    }
}

#[test]
fn test_total_output_values() {
    for v in TEST_VECTORS {
        let tx = parse_coinbase(v);
        let total: Amount = tx.output.iter().map(|o| o.value).sum();
        assert_eq!(
            total,
            Amount::from_sat(v.total_output_sats),
            "Block {} ({}) total output value mismatch",
            v.height,
            v.description
        );
    }
}

// ============================================================
// BIP34 height extraction tests
// ============================================================

#[test]
fn test_bip34_height_extraction() {
    for v in TEST_VECTORS {
        if !v.has_bip34_height {
            continue;
        }
        let tx = parse_coinbase(v);
        let extracted = validation::extract_bip34_height(&tx.input[0].script_sig);
        assert!(
            extracted.is_ok(),
            "Block {} ({}) BIP34 height extraction failed: {:?}",
            v.height,
            v.description,
            extracted.err()
        );
        assert_eq!(
            extracted.unwrap(),
            v.height,
            "Block {} ({}) BIP34 height mismatch",
            v.height,
            v.description
        );
    }
}

#[test]
fn test_bip34_first_block_height_227836() {
    // The first BIP34 block. ScriptSig starts with 03fc7903:
    // 03 = push 3 bytes, fc7903 = [0xfc, 0x79, 0x03] = 227836 in LE
    let v = &TEST_VECTORS[2]; // Block 227836
    assert_eq!(v.height, 227_836);

    let tx = parse_coinbase(v);
    let height = validation::extract_bip34_height(&tx.input[0].script_sig).unwrap();
    assert_eq!(height, 227_836);
}

// ============================================================
// Subsidy verification tests
// ============================================================

#[test]
fn test_subsidy_matches_expected() {
    for v in TEST_VECTORS {
        let calculated = subsidy::block_subsidy(v.height);
        assert_eq!(
            calculated,
            Amount::from_sat(v.subsidy_sats),
            "Block {} ({}) subsidy mismatch: calculated {:?}, expected {} sats",
            v.height,
            v.description,
            calculated,
            v.subsidy_sats
        );
    }
}

#[test]
fn test_output_does_not_exceed_subsidy_plus_fees() {
    for v in TEST_VECTORS {
        let tx = parse_coinbase(v);
        let total_output: Amount = tx.output.iter().map(|o| o.value).sum();
        let calculated_subsidy = subsidy::block_subsidy(v.height);

        // Total output should be >= subsidy (because fees are included)
        // and the difference is the fees collected
        assert!(
            total_output >= calculated_subsidy,
            "Block {} ({}) output {} < subsidy {}",
            v.height,
            v.description,
            total_output,
            calculated_subsidy
        );

        let fees = total_output
            .checked_sub(calculated_subsidy)
            .expect("output >= subsidy");
        // Sanity: fees should be reasonable (< 100 BTC for any real block)
        assert!(
            fees < Amount::from_sat(10_000_000_000),
            "Block {} ({}) unreasonable fees: {}",
            v.height,
            v.description,
            fees
        );
    }
}

// ============================================================
// Witness commitment tests
// ============================================================

#[test]
fn test_witness_commitment_presence() {
    for v in TEST_VECTORS {
        let tx = parse_coinbase(v);
        let commitment = witness::extract_witness_commitment(&tx);

        if v.has_witness_commitment {
            assert!(
                commitment.is_some(),
                "Block {} ({}) should have witness commitment",
                v.height,
                v.description
            );
        } else {
            assert!(
                commitment.is_none(),
                "Block {} ({}) should NOT have witness commitment",
                v.height,
                v.description
            );
        }
    }
}

#[test]
fn test_segwit_coinbase_witness_structure() {
    // SegWit blocks should have a coinbase witness with a single 32-byte zero element
    for v in TEST_VECTORS {
        if !v.has_witness_commitment {
            continue;
        }
        let tx = parse_coinbase(v);
        assert_eq!(
            tx.input[0].witness.len(),
            1,
            "Block {} ({}) coinbase witness should have 1 element",
            v.height,
            v.description
        );
        assert_eq!(
            tx.input[0].witness.nth(0).unwrap(),
            &[0u8; 32],
            "Block {} ({}) coinbase witness reserved value should be all zeros",
            v.height,
            v.description
        );
    }
}

#[test]
fn test_witness_commitment_script_detection() {
    // Block 481824 - First SegWit block
    let v = &TEST_VECTORS[3];
    let tx = parse_coinbase(v);

    // Output 1 should be the witness commitment (OP_RETURN)
    assert!(
        witness::is_witness_commitment_script(&tx.output[1].script_pubkey),
        "Block 481824 output 1 should be witness commitment"
    );
    // Output 0 should NOT be a witness commitment
    assert!(
        !witness::is_witness_commitment_script(&tx.output[0].script_pubkey),
        "Block 481824 output 0 should NOT be witness commitment"
    );
}

#[test]
fn test_block_840000_has_rsk_and_witness_outputs() {
    // Block 840000 has 3 outputs:
    // 0: P2PKH reward
    // 1: RSK merge-mining OP_RETURN (starts with 6a2952534b424c4f434b)
    // 2: SegWit witness commitment OP_RETURN
    let v = &TEST_VECTORS[4];
    assert_eq!(v.height, 840_000);

    let tx = parse_coinbase(v);
    assert_eq!(tx.output.len(), 3);

    // Output 0: reward (non-zero value)
    assert!(tx.output[0].value > Amount::ZERO);

    // Output 1: RSK OP_RETURN (zero value, NOT a witness commitment)
    assert_eq!(tx.output[1].value, Amount::ZERO);
    assert!(!witness::is_witness_commitment_script(
        &tx.output[1].script_pubkey
    ));

    // Output 2: Witness commitment OP_RETURN
    assert_eq!(tx.output[2].value, Amount::ZERO);
    assert!(witness::is_witness_commitment_script(
        &tx.output[2].script_pubkey
    ));

    // extract_witness_commitment should return the highest-index match (output 2)
    let commitment = witness::extract_witness_commitment(&tx);
    assert!(commitment.is_some());
}

// ============================================================
// Validate_coinbase with fees tests
// ============================================================

#[test]
fn test_validate_coinbase_with_known_fees() {
    // Block 227836: output is 25.0626 BTC, subsidy is 25 BTC, fees = 0.0626 BTC
    let v = &TEST_VECTORS[2];
    let tx = parse_coinbase(v);
    let fees = Amount::from_sat(v.total_output_sats - v.subsidy_sats);

    let result = validation::validate_coinbase(&tx, v.height, fees);
    assert!(
        result.is_ok(),
        "Block {} should pass full validation with correct fees: {:?}",
        v.height,
        result.err()
    );
}

#[test]
fn test_validate_coinbase_rejects_insufficient_fees() {
    // Try to validate block 227836 with zero fees -- should fail because
    // the output exceeds subsidy + 0
    let v = &TEST_VECTORS[2];
    let tx = parse_coinbase(v);

    // The output is 25.0626 BTC but subsidy is only 25 BTC.
    // With zero fees claimed, this should be rejected.
    let result = validation::validate_coinbase(&tx, v.height, Amount::ZERO);
    assert!(
        result.is_err(),
        "Block {} should fail validation with zero fees (output exceeds subsidy)",
        v.height,
    );
}

// ============================================================
// Genesis block special tests
// ============================================================

#[test]
fn test_genesis_block_satoshi_message() {
    let v = &TEST_VECTORS[0];
    let tx = parse_coinbase(v);

    let script_bytes = tx.input[0].script_sig.as_bytes();
    // The famous message is embedded in the scriptSig
    let message = b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    let script_str = core::str::from_utf8(script_bytes).unwrap_or("");

    // The message should be present somewhere in the scriptSig bytes
    let found = script_bytes.windows(message.len()).any(|w| w == message);
    assert!(
        found,
        "Genesis block scriptSig should contain Satoshi's Times headline. ScriptSig: {:?}",
        script_str
    );
}

#[test]
fn test_genesis_block_output_value() {
    let v = &TEST_VECTORS[0];
    let tx = parse_coinbase(v);
    assert_eq!(tx.output[0].value, Amount::from_sat(5_000_000_000));
}
