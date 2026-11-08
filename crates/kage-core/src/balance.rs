//! Balances, following wallet2's spendability rules (differentially tested
//! against `monero-wallet-rpc` in `tests/regtest.rs`).
//!
//! wallet2 (`wallet2::is_transfer_unlocked`):
//! - spendable age: `chain_height >= output_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE (10)`;
//! - unlock time (`is_tx_spendtime_unlocked`), where `chain_height` is the
//!   number of blocks (tip + 1):
//!   - block-based (< 500 000 000): `chain_height - 1 + 1 >= unlock_time`
//!     (`CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1`);
//!   - time-based: `now + 120 >= unlock_time` (v2 allowed delta: one block target).
//!
//! Coinbase outputs carry `unlock_time = height + 60` in the miner tx, so the
//! same rule covers them.

use monero_wallet::transaction::Timelock;

use crate::state::{OwnedOutput, WalletState};

/// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`.
pub const SPENDABLE_AGE: u64 = 10;
/// `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS`.
const ALLOWED_DELTA_BLOCKS: u64 = 1;
/// `CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2`.
const ALLOWED_DELTA_SECONDS: u64 = 120;

/// Balance of one account (or the whole wallet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Balance {
    /// Sum of outputs not known to be spent (piconero).
    pub total: u64,
    /// Part of `total` that is spendable now.
    pub unlocked: u64,
    /// Outputs whose spend status is unknown because their key image has not
    /// been imported from the signer. Until this is 0, `total` may be too high
    /// (a view-only wallet cannot see its own spends before FCMP++).
    pub unverified_outputs: usize,
    /// Outputs that can be spent now *and* have a key image (usable as inputs).
    pub spendable_outputs: usize,
}

/// Whether an output is unlocked at `chain_height` (= tip + 1) and `now` (unix seconds).
#[must_use]
pub fn is_unlocked(o: &OwnedOutput, chain_height: u64, now: u64) -> bool {
    if chain_height < o.height.saturating_add(SPENDABLE_AGE) {
        return false;
    }
    match o.output.additional_timelock() {
        Timelock::None => true,
        Timelock::Block(b) => {
            let b = u64::try_from(b).unwrap_or(u64::MAX);
            chain_height
                .saturating_sub(1)
                .saturating_add(ALLOWED_DELTA_BLOCKS)
                >= b
        }
        Timelock::Time(t) => now.saturating_add(ALLOWED_DELTA_SECONDS) >= t,
    }
}

/// Computes the balance. `account = None` sums all accounts.
#[must_use]
pub fn balance(state: &WalletState, account: Option<u32>, chain_height: u64, now: u64) -> Balance {
    let mut b = Balance::default();
    for o in &state.outputs {
        if account.is_some_and(|a| o.subaddress().0 != a) {
            continue;
        }
        if o.spent().is_some() {
            continue;
        }
        b.total = b.total.saturating_add(o.amount());
        let unlocked = is_unlocked(o, chain_height, now);
        if unlocked {
            b.unlocked = b.unlocked.saturating_add(o.amount());
        }
        if o.key_image.is_none() {
            b.unverified_outputs = b.unverified_outputs.saturating_add(1);
        } else if unlocked {
            b.spendable_outputs = b.spendable_outputs.saturating_add(1);
        }
    }
    b
}

/// Formats piconero as XMR with 12 decimals, without floating point.
#[must_use]
pub fn format_xmr(piconero: u64) -> String {
    let whole = piconero / 1_000_000_000_000;
    let frac = piconero % 1_000_000_000_000;
    format!("{whole}.{frac:012}")
}

/// Parses a user-entered XMR amount into piconero, exactly (no floats).
/// Accepts up to 12 decimals; rejects anything else.
#[must_use]
pub fn parse_xmr(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if w.is_empty() && f.is_empty() {
        return None;
    }
    if !w.bytes().all(|c| c.is_ascii_digit())
        || !f.bytes().all(|c| c.is_ascii_digit())
        || f.len() > 12
    {
        return None;
    }
    let whole: u64 = if w.is_empty() { 0 } else { w.parse().ok()? };
    let mut frac_s = f.to_owned();
    while frac_s.len() < 12 {
        frac_s.push('0');
    }
    let frac: u64 = frac_s.parse().ok()?;
    whole.checked_mul(1_000_000_000_000)?.checked_add(frac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn xmr_formatting() {
        assert_eq!(format_xmr(0), "0.000000000000");
        assert_eq!(format_xmr(1_500_000_000_000), "1.500000000000");
        assert_eq!(format_xmr(1), "0.000000000001");
        assert_eq!(parse_xmr("1.5"), Some(1_500_000_000_000));
        assert_eq!(parse_xmr(".000000000001"), Some(1));
        assert_eq!(parse_xmr("1."), Some(1_000_000_000_000));
        for bad in [
            "",
            ".",
            "1.0000000000001",
            "-1",
            "1e3",
            "1,5",
            " ",
            "18446745.0",
        ] {
            assert_eq!(parse_xmr(bad), None, "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn xmr_round_trip(p in any::<u64>()) {
            prop_assert_eq!(parse_xmr(&format_xmr(p)), Some(p));
        }
    }
}
