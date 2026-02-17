//! Error types for coinbase transaction construction and validation.

use alloc::vec::Vec;
use core::fmt;

/// Errors that can occur during coinbase transaction construction or validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinbaseError {
    /// The coinbase scriptSig exceeds the 100-byte consensus maximum.
    ScriptTooLong {
        /// Actual size in bytes.
        size: usize,
        /// Maximum allowed size (100).
        max: usize,
    },
    /// The coinbase scriptSig is below the 2-byte consensus minimum.
    ScriptTooShort {
        /// Actual size in bytes.
        size: usize,
        /// Minimum required size (2).
        min: usize,
    },
    /// The total output amount exceeds the maximum allowed value.
    OutputAmountOverflow,
    /// No outputs were specified for the coinbase transaction.
    NoOutputs,
    /// The extranonce size is too large to fit in the remaining scriptSig space.
    ExtraNonceTooLarge {
        /// Requested extranonce size in bytes.
        requested: usize,
        /// Available space in bytes.
        available: usize,
    },
    /// The provided extranonce value does not match the expected size.
    ExtraNonceSizeMismatch {
        /// Expected size in bytes.
        expected: usize,
        /// Actual size in bytes.
        got: usize,
    },
    /// The witness commitment data is invalid.
    InvalidWitnessCommitment,
    /// Extra data is too large to fit in the remaining scriptSig space.
    ExtraDataTooLarge {
        /// Requested extra data size in bytes.
        requested: usize,
        /// Available space in bytes.
        available: usize,
    },
    /// The coinbase transaction has an invalid structure.
    InvalidCoinbaseStructure {
        /// Description of the structural issue.
        reason: &'static str,
    },
    /// BIP34 height could not be decoded from the scriptSig.
    InvalidBip34Height,
    /// Multiple validation errors occurred.
    Multiple(Vec<CoinbaseError>),
}

impl fmt::Display for CoinbaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoinbaseError::ScriptTooLong { size, max } => {
                write!(
                    f,
                    "coinbase scriptSig too long: {} bytes (max {})",
                    size, max
                )
            }
            CoinbaseError::ScriptTooShort { size, min } => {
                write!(
                    f,
                    "coinbase scriptSig too short: {} bytes (min {})",
                    size, min
                )
            }
            CoinbaseError::OutputAmountOverflow => {
                write!(f, "coinbase output amount overflow")
            }
            CoinbaseError::NoOutputs => {
                write!(f, "coinbase transaction must have at least one output")
            }
            CoinbaseError::ExtraNonceTooLarge {
                requested,
                available,
            } => {
                write!(
                    f,
                    "extranonce too large: {} bytes requested, {} available",
                    requested, available
                )
            }
            CoinbaseError::ExtraNonceSizeMismatch { expected, got } => {
                write!(
                    f,
                    "extranonce size mismatch: expected {} bytes, got {}",
                    expected, got
                )
            }
            CoinbaseError::InvalidWitnessCommitment => {
                write!(f, "invalid witness commitment")
            }
            CoinbaseError::ExtraDataTooLarge {
                requested,
                available,
            } => {
                write!(
                    f,
                    "extra data too large: {} bytes requested, {} available",
                    requested, available
                )
            }
            CoinbaseError::InvalidCoinbaseStructure { reason } => {
                write!(f, "invalid coinbase structure: {}", reason)
            }
            CoinbaseError::InvalidBip34Height => {
                write!(f, "invalid BIP34 height encoding in coinbase scriptSig")
            }
            CoinbaseError::Multiple(errors) => {
                write!(f, "multiple coinbase errors: [")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", e)?;
                }
                write!(f, "]")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CoinbaseError {}
