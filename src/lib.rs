//! # rust-coinbase
//!
//! A Rust library for constructing and manipulating Bitcoin coinbase transactions.
//!
//! This crate provides a high-level builder API on top of [`bitcoin`] for
//! crafting coinbase transactions used in mining operations. It handles the
//! fiddly details of BIP34 height encoding, SegWit witness commitments,
//! extranonce management, and Stratum-compatible coinbase splitting.
//!
//! ## Quick Start
//!
//! ```rust
//! use rust_coinbase::CoinbaseBuilder;
//! use bitcoin::{Amount, ScriptBuf};
//!
//! // Build a coinbase transaction for block 840,000
//! let payout_script = ScriptBuf::new_op_return(&[]); // use a real address
//!
//! let tx = CoinbaseBuilder::new(840_000)
//!     .output(payout_script, Amount::from_sat(312_500_000))
//!     .extra_nonce_value(&[0u8; 8])
//!     .build()
//!     .unwrap();
//!
//! assert!(tx.is_coinbase());
//! ```
//!
//! ## Stratum Pool Usage
//!
//! ```rust
//! use rust_coinbase::{CoinbaseBuilder, CoinbaseSplit};
//! use bitcoin::{Amount, ScriptBuf};
//!
//! let payout = ScriptBuf::new_op_return(&[]);
//!
//! // Build a split coinbase for pool distribution
//! let split = CoinbaseBuilder::new(840_000)
//!     .output(payout, Amount::from_sat(312_500_000))
//!     .build_split(4, 4) // extranonce1=4 bytes, extranonce2=4 bytes
//!     .unwrap();
//!
//! // Each worker gets (coinbase1, coinbase2) and a unique extranonce1.
//! // Workers iterate extranonce2 to search for valid blocks.
//! let tx = split.assemble(&[0x01; 4], &[0x00; 4]).unwrap();
//! assert!(tx.is_coinbase());
//! ```
//!
//! ## Modules
//!
//! - [`builder`] - Fluent [`CoinbaseBuilder`] API for constructing coinbase transactions
//! - [`derivator`] - [`ScriptDerivator`] trait and [`StaticScript`] for payout script generation
//! - [`split`] - Stratum coinbase split model ([`CoinbaseSplit`])
//! - [`script`] - Coinbase scriptSig construction and BIP34 height encoding
//! - [`witness`] - SegWit witness commitment calculation (BIP141)
//! - [`subsidy`] - Block reward halving schedule
//! - [`validation`] - Coinbase transaction validation and parsing
//! - [`error`] - Error types
//!
//! [`ScriptDerivator`]: derivator::ScriptDerivator
//! [`StaticScript`]: derivator::StaticScript

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod builder;
pub mod derivator;
pub mod error;
pub mod script;
pub mod split;
pub mod subsidy;
pub mod validation;
pub mod witness;

// Re-export primary types for convenience.
pub use builder::CoinbaseBuilder;
pub use derivator::{ScriptDerivator, StaticScript};
pub use error::CoinbaseError;
pub use split::CoinbaseSplit;

// Re-export commonly used bitcoin types so users don't need a separate
// bitcoin dependency for basic usage.
pub use bitcoin;
