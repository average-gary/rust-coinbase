//! Descriptor-based script derivation (requires `descriptors` feature).
//!
//! Provides [`DescriptorDerivator`], an implementation of [`ScriptDerivator`]
//! that derives payout scripts from BIP380 output descriptors with wildcard
//! derivation paths.
//!
//! This is designed for coinbase address rotation in mining pools, where each
//! block found uses a fresh address derived from an xpub. By never reusing
//! an address, the corresponding public key is never exposed on-chain while
//! guarding unspent funds.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "descriptors")]
//! # {
//! use rust_coinbase::descriptor::DescriptorDerivator;
//! use rust_coinbase::ScriptDerivator;
//!
//! // BIP84 testnet descriptor with wildcard
//! let desc = "wpkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)";
//! let mut derivator = DescriptorDerivator::new(desc, 0).unwrap();
//!
//! let script0 = derivator.script_pubkey().unwrap();
//! let script1 = derivator.next_script_pubkey().unwrap();
//! assert_ne!(script0, script1); // different addresses
//! # }
//! ```
//!
//! # Integration with CoinbaseBuilder
//!
//! ```
//! # #[cfg(feature = "descriptors")]
//! # {
//! use rust_coinbase::{CoinbaseBuilder, descriptor::DescriptorDerivator};
//! use rust_coinbase::ScriptDerivator;
//! use bitcoin::Amount;
//!
//! let mut derivator = DescriptorDerivator::new(
//!     "wpkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)",
//!     0,
//! ).unwrap();
//!
//! let tx = CoinbaseBuilder::new(840_000)
//!     .output_from_derivator(&derivator, Amount::from_sat(312_500_000))
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! assert!(tx.is_coinbase());
//! # }
//! ```

use alloc::string::{String, ToString};

use bitcoin::ScriptBuf;
use miniscript::descriptor::DescriptorPublicKey;
use miniscript::Descriptor;

use crate::derivator::ScriptDerivator;
use crate::error::CoinbaseError;

/// Known extended key prefixes for testnet/regtest networks.
///
/// These are the Base58 prefixes for BIP32 extended keys on test networks:
/// - `tpub` / `tprv` -- BIP44/49/84 testnet
/// - `upub` / `uprv` -- BIP49 testnet (P2SH-P2WPKH)
/// - `vpub` / `vprv` -- BIP84 testnet (P2WPKH)
const TESTNET_KEY_PREFIXES: &[&str] = &["tpub", "tprv", "upub", "uprv", "vpub", "vprv"];

/// Derives payout scripts from a wildcard output descriptor.
///
/// Supports any descriptor that `miniscript` can parse with a wildcard (`*`)
/// in the derivation path, including:
/// - `wpkh(xpub.../0/*)` -- P2WPKH (BIP84)
/// - `tr(xpub.../0/*)` -- Taproot (BIP86)
/// - `pkh(xpub.../0/*)` -- P2PKH (BIP44)
/// - `sh(wpkh(xpub.../0/*))` -- P2SH-P2WPKH (BIP49)
///
/// The descriptor string is stored and re-parsed on each derivation to ensure
/// `Send + Sync` compatibility. This is necessary because miniscript's
/// `Descriptor<DescriptorPublicKey>` uses internal `RefCell` for taproot
/// caching, making it `!Send + !Sync`. Re-parsing is cheap and block finds
/// are infrequent.
///
/// # Thread Safety
///
/// `DescriptorDerivator` is `Send + Sync`. For thread-safe concurrent access
/// with atomic index management, wrap it in a [`PersistentDerivator`] (issue #3).
///
/// [`PersistentDerivator`]: crate::PersistentDerivator
#[derive(Debug, Clone)]
pub struct DescriptorDerivator {
    /// The wildcard descriptor string (e.g., "wpkh(xpub.../0/*)")
    descriptor_str: String,
    /// Current derivation index.
    current_index: u32,
}

impl DescriptorDerivator {
    /// Create a new descriptor derivator from a wildcard descriptor string.
    ///
    /// The descriptor is validated immediately: it must parse successfully
    /// and contain a wildcard (`*`) in the derivation path. A test derivation
    /// at `start_index` is performed to verify the descriptor produces valid
    /// scripts.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - A descriptor string with a wildcard path (e.g., `wpkh(xpub.../0/*)`)
    /// * `start_index` - Initial derivation index (typically 0)
    ///
    /// # Errors
    ///
    /// Returns [`CoinbaseError::DescriptorParse`] if the descriptor is invalid.
    /// Returns [`CoinbaseError::DescriptorNoWildcard`] if no wildcard is present.
    /// Returns [`CoinbaseError::DescriptorDerivation`] if the initial derivation fails.
    pub fn new(descriptor: &str, start_index: u32) -> Result<Self, CoinbaseError> {
        // Parse and validate
        let parsed: Descriptor<DescriptorPublicKey> = descriptor
            .parse()
            .map_err(|e| CoinbaseError::DescriptorParse(alloc::format!("{}", e)))?;

        if !parsed.has_wildcard() {
            return Err(CoinbaseError::DescriptorNoWildcard);
        }

        let derivator = Self {
            descriptor_str: descriptor.to_string(),
            current_index: start_index,
        };

        // Verify we can derive at the start index
        derivator.derive_at_index(start_index)?;

        Ok(derivator)
    }

    /// Return the current derivation index.
    pub fn current_index(&self) -> u32 {
        self.current_index
    }

    /// Set the current derivation index.
    ///
    /// The next call to [`script_pubkey`] will derive at this index.
    /// The next call to [`next_script_pubkey`] will derive at `index + 1`.
    ///
    /// [`script_pubkey`]: ScriptDerivator::script_pubkey
    /// [`next_script_pubkey`]: ScriptDerivator::next_script_pubkey
    pub fn set_index(&mut self, index: u32) {
        self.current_index = index;
    }

    /// Derive the script pubkey at a specific index.
    ///
    /// This does not affect the internal index counter.
    pub fn derive_at_index(&self, index: u32) -> Result<ScriptBuf, CoinbaseError> {
        // Re-parse each time for Send + Sync safety.
        // See struct-level docs for rationale.
        let parsed: Descriptor<DescriptorPublicKey> = self
            .descriptor_str
            .parse()
            .map_err(|e| CoinbaseError::DescriptorParse(alloc::format!("{}", e)))?;

        let definite = parsed.at_derivation_index(index).map_err(|e| {
            CoinbaseError::DescriptorDerivation(alloc::format!("failed at index {}: {}", index, e))
        })?;

        Ok(definite.script_pubkey())
    }

    /// Return the descriptor string.
    pub fn descriptor_str(&self) -> &str {
        &self.descriptor_str
    }

    /// Check whether the descriptor uses testnet extended keys.
    ///
    /// This is a heuristic check based on known extended key prefixes
    /// (`tpub`, `tprv`, `upub`, `uprv`, `vpub`, `vprv`). Descriptors
    /// do not encode network information directly, so this relies on
    /// the Base58 key prefix convention.
    ///
    /// Returns `true` if any key in the descriptor has a testnet prefix.
    /// Returns `false` if all keys have mainnet prefixes (or are raw keys
    /// without extended key encoding).
    pub fn uses_testnet_keys(&self) -> bool {
        descriptor_uses_testnet_keys(&self.descriptor_str)
    }
}

impl ScriptDerivator for DescriptorDerivator {
    type Error = CoinbaseError;

    fn script_pubkey(&self) -> Result<ScriptBuf, CoinbaseError> {
        self.derive_at_index(self.current_index)
    }

    fn next_script_pubkey(&mut self) -> Result<ScriptBuf, CoinbaseError> {
        self.current_index = self.current_index.checked_add(1).ok_or_else(|| {
            CoinbaseError::DescriptorDerivation("derivation index overflow (u32::MAX)".to_string())
        })?;
        self.derive_at_index(self.current_index)
    }
}

/// Check whether a descriptor string contains testnet extended key prefixes.
///
/// Searches for known testnet key prefixes (`tpub`, `tprv`, `upub`, `uprv`,
/// `vpub`, `vprv`) anywhere in the descriptor string.
pub fn descriptor_uses_testnet_keys(descriptor: &str) -> bool {
    TESTNET_KEY_PREFIXES
        .iter()
        .any(|prefix| descriptor.contains(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP84 testnet tpub from the sv2-apps test vectors.
    const TEST_TPUB_WPKH: &str = "wpkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)";

    // Mainnet xpub
    const TEST_XPUB_WPKH: &str = "wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)";

    // Known test vector tpub from sv2-apps (different from the one above)
    const KNOWN_TPUB: &str = "wpkh(tpubDDHYkDsJ8XB1LLjMNrk5gXsmze87LRkWoNqprdXPud9Yx3ZfsjZZJEqscUgSRLJ1EG77KSKygC9uNAeDtgHsLtvH93MnPF2M9Vq5WvGvcLw/0/*)";

    #[test]
    fn test_new_with_wildcard() {
        let d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();
        assert_eq!(d.current_index(), 0);
    }

    #[test]
    fn test_new_without_wildcard_fails() {
        let desc = "wpkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/0)";
        let result = DescriptorDerivator::new(desc, 0);
        assert!(matches!(result, Err(CoinbaseError::DescriptorNoWildcard)));
    }

    #[test]
    fn test_new_with_invalid_descriptor_fails() {
        let result = DescriptorDerivator::new("not_a_descriptor", 0);
        assert!(matches!(result, Err(CoinbaseError::DescriptorParse(_))));
    }

    #[test]
    fn test_script_pubkey_does_not_increment() {
        let d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();
        let s1 = d.script_pubkey().unwrap();
        let s2 = d.script_pubkey().unwrap();
        let s3 = d.script_pubkey().unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
        assert_eq!(d.current_index(), 0);
    }

    #[test]
    fn test_next_script_pubkey_increments() {
        let mut d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();

        let s0 = d.script_pubkey().unwrap(); // index 0
        let s1 = d.next_script_pubkey().unwrap(); // advances to 1
        assert_eq!(d.current_index(), 1);

        let s2 = d.next_script_pubkey().unwrap(); // advances to 2
        assert_eq!(d.current_index(), 2);

        // All different
        assert_ne!(s0, s1);
        assert_ne!(s1, s2);
        assert_ne!(s0, s2);
    }

    #[test]
    fn test_derive_at_index_does_not_change_state() {
        let d = DescriptorDerivator::new(TEST_TPUB_WPKH, 5).unwrap();
        let _ = d.derive_at_index(100).unwrap();
        assert_eq!(d.current_index(), 5);
    }

    #[test]
    fn test_set_index() {
        let mut d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();
        d.set_index(42);
        assert_eq!(d.current_index(), 42);
    }

    #[test]
    fn test_start_index_offset() {
        let d0 = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();
        let d100 = DescriptorDerivator::new(TEST_TPUB_WPKH, 100).unwrap();

        let s0 = d0.script_pubkey().unwrap();
        let s100 = d100.script_pubkey().unwrap();
        assert_ne!(s0, s100);
    }

    // ============================================================
    // Known derivation vectors from sv2-apps
    // ============================================================

    /// Expected scripts at each index for KNOWN_TPUB (P2WPKH format: 0014<20-byte-hash>)
    /// These vectors are from average-gary/sv2-apps:feat/coinbase-rotation
    const EXPECTED_SCRIPTS: &[&str] = &[
        "0014798fb52bc77ba8e028dfad1b522505223c7e7ca0", // Index 0
        "00143acc8d6d349a24a198fb9eec0e27b822c589d407", // Index 1
        "0014dd4da77967b0a8c59ee3026af582de496abad124", // Index 2
        "001401b85a64c3c8d8dcf46f49230d938ec1245fcd8e", // Index 3
        "0014a72ae2dddcc84c99a0abe43f4fbef1a46d153b8e", // Index 4
    ];

    fn script_to_hex(script: &ScriptBuf) -> String {
        script
            .as_bytes()
            .iter()
            .map(|b| alloc::format!("{:02x}", b))
            .collect()
    }

    #[test]
    fn test_known_derivation_vectors() {
        let d = DescriptorDerivator::new(KNOWN_TPUB, 0).unwrap();

        for (i, expected) in EXPECTED_SCRIPTS.iter().enumerate() {
            let script = d.derive_at_index(i as u32).unwrap();
            assert_eq!(
                script_to_hex(&script),
                *expected,
                "Script mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_rotation_flow_matches_sv2_apps() {
        // Simulate the rotation flow from sv2-apps:
        // Start at index 2, verify current, rotate twice
        let mut d = DescriptorDerivator::new(KNOWN_TPUB, 2).unwrap();

        // current_script_pubkey at index 2
        let initial = d.script_pubkey().unwrap();
        assert_eq!(script_to_hex(&initial), EXPECTED_SCRIPTS[2]);

        // Rotate: next_script_pubkey advances to index 3
        let after_first = d.next_script_pubkey().unwrap();
        assert_eq!(d.current_index(), 3);
        assert_eq!(script_to_hex(&after_first), EXPECTED_SCRIPTS[3]);

        // Rotate again: index 4
        let after_second = d.next_script_pubkey().unwrap();
        assert_eq!(d.current_index(), 4);
        assert_eq!(script_to_hex(&after_second), EXPECTED_SCRIPTS[4]);
    }

    // ============================================================
    // Network detection tests
    // ============================================================

    #[test]
    fn test_testnet_key_detection() {
        let d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();
        assert!(d.uses_testnet_keys());
    }

    #[test]
    fn test_mainnet_key_detection() {
        let d = DescriptorDerivator::new(TEST_XPUB_WPKH, 0).unwrap();
        assert!(!d.uses_testnet_keys());
    }

    #[test]
    fn test_descriptor_uses_testnet_keys_function() {
        assert!(descriptor_uses_testnet_keys("wpkh(tpubD6Nz...)"));
        assert!(descriptor_uses_testnet_keys("wpkh(vpubD6Nz...)"));
        assert!(descriptor_uses_testnet_keys("tr(tpubD6Nz...)"));
        assert!(!descriptor_uses_testnet_keys("wpkh(xpub661M...)"));
        assert!(!descriptor_uses_testnet_keys("tr(xpub661M...)"));
    }

    // ============================================================
    // Descriptor type tests
    // ============================================================

    #[test]
    fn test_taproot_descriptor() {
        let desc = "tr(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)";
        let mut d = DescriptorDerivator::new(desc, 0).unwrap();

        let s0 = d.script_pubkey().unwrap();
        let s1 = d.next_script_pubkey().unwrap();

        assert_ne!(s0, s1);

        // Taproot scripts start with OP_1 OP_PUSHBYTES_32 = 0x5120
        let hex = script_to_hex(&s0);
        assert!(
            hex.starts_with("5120"),
            "Taproot script should start with 5120, got: {}",
            hex
        );
        // Taproot scriptPubKey is 34 bytes: 0x5120 + 32 bytes
        assert_eq!(s0.as_bytes().len(), 34);
    }

    #[test]
    fn test_clone_produces_independent_state() {
        let mut d1 = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();
        let d2 = d1.clone();

        d1.next_script_pubkey().unwrap();
        assert_eq!(d1.current_index(), 1);
        assert_eq!(d2.current_index(), 0); // clone is independent
    }

    // ============================================================
    // CoinbaseBuilder integration
    // ============================================================

    #[test]
    fn test_with_coinbase_builder() {
        let d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();

        let tx = crate::CoinbaseBuilder::new(840_000)
            .output_from_derivator(&d, bitcoin::Amount::from_sat(312_500_000))
            .unwrap()
            .build()
            .unwrap();

        assert!(tx.is_coinbase());
        assert_eq!(tx.output.len(), 1);

        // Output script should match index 0 derivation
        let expected = d.derive_at_index(0).unwrap();
        assert_eq!(tx.output[0].script_pubkey, expected);
    }

    #[test]
    fn test_with_coinbase_builder_rotation() {
        let mut d = DescriptorDerivator::new(TEST_TPUB_WPKH, 0).unwrap();

        // Build first block's coinbase
        let tx1 = crate::CoinbaseBuilder::new(840_000)
            .output_from_derivator_next(&mut d, bitcoin::Amount::from_sat(312_500_000))
            .unwrap()
            .build()
            .unwrap();

        // Build second block's coinbase
        let tx2 = crate::CoinbaseBuilder::new(840_001)
            .output_from_derivator_next(&mut d, bitcoin::Amount::from_sat(312_500_000))
            .unwrap()
            .build()
            .unwrap();

        // Different payout addresses
        assert_ne!(tx1.output[0].script_pubkey, tx2.output[0].script_pubkey);
    }
}
