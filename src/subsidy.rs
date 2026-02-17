//! Block subsidy (reward) calculation.
//!
//! Implements the Bitcoin block reward halving schedule and related utilities.

use bitcoin::Amount;

/// Number of blocks between each subsidy halving (210,000).
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;

/// Initial block subsidy: 50 BTC = 5,000,000,000 satoshis.
pub const INITIAL_SUBSIDY_SATS: u64 = 50_0000_0000;

/// Number of confirmations required before a coinbase output can be spent (100).
pub const COINBASE_MATURITY: u32 = 100;

/// Maximum number of halvings before the subsidy reaches zero.
/// After 64 halvings the right-shift zeroes out the initial subsidy.
pub const MAX_HALVINGS: u32 = 64;

/// Calculate the block subsidy for a given block height.
///
/// Returns the mining reward (excluding transaction fees) for the block at `height`.
/// The subsidy halves every [`SUBSIDY_HALVING_INTERVAL`] blocks, starting at
/// [`INITIAL_SUBSIDY_SATS`] satoshis (50 BTC).
///
/// # Examples
///
/// ```
/// use rust_coinbase::subsidy::block_subsidy;
/// use bitcoin::Amount;
///
/// // Genesis block: 50 BTC
/// assert_eq!(block_subsidy(0), Amount::from_sat(5_000_000_000));
///
/// // After first halving: 25 BTC
/// assert_eq!(block_subsidy(210_000), Amount::from_sat(2_500_000_000));
///
/// // After fourth halving (current era): 3.125 BTC
/// assert_eq!(block_subsidy(840_000), Amount::from_sat(312_500_000));
/// ```
pub fn block_subsidy(height: u32) -> Amount {
    let halvings = halvings(height);
    if halvings >= MAX_HALVINGS {
        return Amount::ZERO;
    }
    Amount::from_sat(INITIAL_SUBSIDY_SATS >> halvings)
}

/// Return the number of halvings that have occurred by block `height`.
///
/// # Examples
///
/// ```
/// use rust_coinbase::subsidy::halvings;
///
/// assert_eq!(halvings(0), 0);
/// assert_eq!(halvings(209_999), 0);
/// assert_eq!(halvings(210_000), 1);
/// assert_eq!(halvings(840_000), 4);
/// ```
pub fn halvings(height: u32) -> u32 {
    height / SUBSIDY_HALVING_INTERVAL
}

/// Return the block height at which the next halving will occur after `height`.
///
/// # Examples
///
/// ```
/// use rust_coinbase::subsidy::next_halving_height;
///
/// assert_eq!(next_halving_height(0), 210_000);
/// assert_eq!(next_halving_height(840_000), 1_050_000);
/// ```
pub fn next_halving_height(height: u32) -> u32 {
    let current = halvings(height);
    (current + 1) * SUBSIDY_HALVING_INTERVAL
}

/// Returns `true` if the subsidy is zero at the given height.
///
/// This occurs after [`MAX_HALVINGS`] halvings (well beyond any practical timeframe).
pub fn is_subsidy_zero(height: u32) -> bool {
    halvings(height) >= MAX_HALVINGS
}

/// Calculate the maximum total coinbase output value for a block.
///
/// This is the block subsidy plus the total transaction fees. The coinbase
/// transaction's outputs must not exceed this amount.
///
/// # Examples
///
/// ```
/// use rust_coinbase::subsidy::max_coinbase_value;
/// use bitcoin::Amount;
///
/// let fees = Amount::from_sat(1_000_000);
/// let max = max_coinbase_value(840_000, fees);
/// assert_eq!(max, Amount::from_sat(312_500_000 + 1_000_000));
/// ```
pub fn max_coinbase_value(height: u32, total_fees: Amount) -> Amount {
    block_subsidy(height)
        .checked_add(total_fees)
        .expect("coinbase value overflow: subsidy + fees exceeds Amount::MAX")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_subsidy() {
        assert_eq!(block_subsidy(0), Amount::from_sat(5_000_000_000));
    }

    #[test]
    fn test_first_halving() {
        assert_eq!(block_subsidy(210_000), Amount::from_sat(2_500_000_000));
    }

    #[test]
    fn test_second_halving() {
        assert_eq!(block_subsidy(420_000), Amount::from_sat(1_250_000_000));
    }

    #[test]
    fn test_fourth_halving() {
        assert_eq!(block_subsidy(840_000), Amount::from_sat(312_500_000));
    }

    #[test]
    fn test_last_block_before_halving() {
        assert_eq!(block_subsidy(209_999), Amount::from_sat(5_000_000_000));
    }

    #[test]
    fn test_subsidy_eventually_zero() {
        // After 64 halvings, subsidy is zero
        let height = 64 * SUBSIDY_HALVING_INTERVAL;
        assert_eq!(block_subsidy(height), Amount::ZERO);
        assert!(is_subsidy_zero(height));
    }

    #[test]
    fn test_halvings_count() {
        assert_eq!(halvings(0), 0);
        assert_eq!(halvings(209_999), 0);
        assert_eq!(halvings(210_000), 1);
        assert_eq!(halvings(419_999), 1);
        assert_eq!(halvings(420_000), 2);
    }

    #[test]
    fn test_next_halving() {
        assert_eq!(next_halving_height(0), 210_000);
        assert_eq!(next_halving_height(100_000), 210_000);
        assert_eq!(next_halving_height(210_000), 420_000);
        assert_eq!(next_halving_height(840_000), 1_050_000);
    }

    #[test]
    fn test_max_coinbase_value() {
        let fees = Amount::from_sat(50_000_000);
        let max = max_coinbase_value(840_000, fees);
        assert_eq!(max, Amount::from_sat(312_500_000 + 50_000_000));
    }
}
