//! Script derivation trait and implementations.
//!
//! The [`ScriptDerivator`] trait defines the interface for payout script
//! generation in coinbase transactions. Mining operations can implement this
//! trait to provide any payout strategy:
//!
//! - **Static**: single address, never changes ([`StaticScript`])
//! - **Rotating**: HD-derived addresses from an xpub descriptor (see `descriptors` feature, issue #2)
//! - **Custom**: round-robin, multi-party, treasury splits, etc.
//!
//! # Examples
//!
//! ## Static payout (solo mining)
//!
//! ```
//! use rust_coinbase::derivator::{ScriptDerivator, StaticScript};
//! use bitcoin::ScriptBuf;
//!
//! let script = ScriptBuf::new_op_return(&[]); // use a real address
//! let derivator = StaticScript::new(script.clone());
//!
//! assert_eq!(derivator.script_pubkey().unwrap(), script);
//! ```
//!
//! ## With CoinbaseBuilder
//!
//! ```
//! use rust_coinbase::{CoinbaseBuilder, derivator::StaticScript};
//! use bitcoin::{Amount, ScriptBuf};
//!
//! let payout = StaticScript::new(ScriptBuf::new_op_return(&[]));
//!
//! let tx = CoinbaseBuilder::new(840_000)
//!     .output_from_derivator(&payout, Amount::from_sat(312_500_000))
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! assert!(tx.is_coinbase());
//! ```

use bitcoin::ScriptBuf;

/// Trait for generating payout scripts for coinbase transaction outputs.
///
/// Implementations produce `ScriptBuf` values suitable for use as
/// `script_pubkey` in coinbase `TxOut` outputs.
///
/// The trait has two methods reflecting two usage patterns:
/// - [`script_pubkey`]: peek at the current script without side effects
/// - [`next_script_pubkey`]: advance to the next script (for address rotation)
///
/// For non-rotating implementations (like [`StaticScript`]), both methods
/// return the same value.
///
/// [`script_pubkey`]: ScriptDerivator::script_pubkey
/// [`next_script_pubkey`]: ScriptDerivator::next_script_pubkey
pub trait ScriptDerivator {
    /// The error type returned by derivation operations.
    type Error: core::fmt::Debug;

    /// Get the current payout script without advancing.
    ///
    /// Calling this multiple times without calling [`next_script_pubkey`]
    /// should always return the same script.
    ///
    /// [`next_script_pubkey`]: ScriptDerivator::next_script_pubkey
    fn script_pubkey(&self) -> Result<ScriptBuf, Self::Error>;

    /// Advance to the next payout script and return it.
    ///
    /// For rotating derivators (e.g., HD wallet-based), this increments an
    /// internal index and derives the script at the new index.
    ///
    /// For static derivators, this is equivalent to [`script_pubkey`].
    ///
    /// [`script_pubkey`]: ScriptDerivator::script_pubkey
    fn next_script_pubkey(&mut self) -> Result<ScriptBuf, Self::Error>;
}

/// A static script derivator that always returns the same `ScriptBuf`.
///
/// This is the simplest implementation of [`ScriptDerivator`], suitable for
/// solo miners or any scenario where the payout address does not change.
///
/// # Examples
///
/// ```
/// use rust_coinbase::derivator::{ScriptDerivator, StaticScript};
/// use bitcoin::ScriptBuf;
///
/// let script = ScriptBuf::new_op_return(&[]);
/// let mut derivator = StaticScript::new(script.clone());
///
/// // Always returns the same script
/// assert_eq!(derivator.script_pubkey().unwrap(), script);
/// assert_eq!(derivator.next_script_pubkey().unwrap(), script);
/// assert_eq!(derivator.script_pubkey().unwrap(), script);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScript(ScriptBuf);

impl StaticScript {
    /// Create a new static script derivator from a `ScriptBuf`.
    pub fn new(script: ScriptBuf) -> Self {
        Self(script)
    }

    /// Return a reference to the inner `ScriptBuf`.
    pub fn inner(&self) -> &ScriptBuf {
        &self.0
    }

    /// Consume the derivator and return the inner `ScriptBuf`.
    pub fn into_inner(self) -> ScriptBuf {
        self.0
    }
}

impl ScriptDerivator for StaticScript {
    type Error = core::convert::Infallible;

    fn script_pubkey(&self) -> Result<ScriptBuf, Self::Error> {
        Ok(self.0.clone())
    }

    fn next_script_pubkey(&mut self) -> Result<ScriptBuf, Self::Error> {
        Ok(self.0.clone())
    }
}

impl From<ScriptBuf> for StaticScript {
    fn from(script: ScriptBuf) -> Self {
        Self::new(script)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_script_returns_same() {
        let script = ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14]);
        let mut derivator = StaticScript::new(script.clone());

        assert_eq!(derivator.script_pubkey().unwrap(), script);
        assert_eq!(derivator.next_script_pubkey().unwrap(), script);
        assert_eq!(derivator.script_pubkey().unwrap(), script);
    }

    #[test]
    fn test_static_script_from_scriptbuf() {
        let script = ScriptBuf::from_bytes(vec![0x00, 0x14]);
        let derivator: StaticScript = script.clone().into();
        assert_eq!(derivator.script_pubkey().unwrap(), script);
    }

    #[test]
    fn test_static_script_inner() {
        let script = ScriptBuf::from_bytes(vec![0xab]);
        let derivator = StaticScript::new(script.clone());
        assert_eq!(derivator.inner(), &script);
        assert_eq!(derivator.into_inner(), script);
    }

    #[test]
    fn test_static_script_clone_eq() {
        let a = StaticScript::new(ScriptBuf::from_bytes(vec![0x01]));
        let b = a.clone();
        assert_eq!(a, b);
    }

    /// Test that a custom derivator can be implemented.
    #[test]
    fn test_custom_derivator() {
        struct RoundRobin {
            scripts: alloc::vec::Vec<ScriptBuf>,
            index: usize,
        }

        impl ScriptDerivator for RoundRobin {
            type Error = &'static str;

            fn script_pubkey(&self) -> Result<ScriptBuf, Self::Error> {
                self.scripts
                    .get(self.index)
                    .cloned()
                    .ok_or("index out of range")
            }

            fn next_script_pubkey(&mut self) -> Result<ScriptBuf, Self::Error> {
                self.index = (self.index + 1) % self.scripts.len();
                self.script_pubkey()
            }
        }

        let mut rr = RoundRobin {
            scripts: alloc::vec![
                ScriptBuf::from_bytes(alloc::vec![0x01]),
                ScriptBuf::from_bytes(alloc::vec![0x02]),
                ScriptBuf::from_bytes(alloc::vec![0x03]),
            ],
            index: 0,
        };

        // Starts at index 0
        assert_eq!(
            rr.script_pubkey().unwrap(),
            ScriptBuf::from_bytes(alloc::vec![0x01])
        );

        // Advances through all scripts
        assert_eq!(
            rr.next_script_pubkey().unwrap(),
            ScriptBuf::from_bytes(alloc::vec![0x02])
        );
        assert_eq!(
            rr.next_script_pubkey().unwrap(),
            ScriptBuf::from_bytes(alloc::vec![0x03])
        );
        // Wraps around
        assert_eq!(
            rr.next_script_pubkey().unwrap(),
            ScriptBuf::from_bytes(alloc::vec![0x01])
        );
    }
}
