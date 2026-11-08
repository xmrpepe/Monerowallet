//! Building an unsigned transaction intent (ADR-019).
//!
//! The intent is validated here by constructing the exact
//! `SignableTransaction` the signer will construct, from the same data. That
//! proves it is well formed and gives the exact fee, without any spend key.
//!
//! Output selection: largest-first among verified, unlocked, unspent outputs
//! of the chosen account. This is **not** identical to wallet2's selection
//! (which is not consensus, but is a weak fingerprint). See
//! `docs/THREAT_MODEL.md`, T-CORE-DECOY. Decoy selection itself is
//! `monero-wallet`'s, which mirrors wallet2's.

use monero_wallet::OutputWithDecoys;
use monero_wallet::address::SubaddressIndex;
use monero_wallet::interface::{
    FeePriority, ProvidesBlockchainMeta, ProvidesDecoys, ProvidesFeeRates,
};
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SendError, SignableTransaction};
use zeroize::Zeroizing;

use kage_airgap::payload::{MAX_INPUTS, MAX_PAYMENTS, Payment, TxIntent, max_fee_per_weight};

use crate::balance::is_unlocked;
use crate::keys::ViewKeys;
use crate::state::WalletState;

/// Ring size (16, current consensus).
pub const RING_LEN: u8 = 16;

/// What the user asked for.
#[derive(Debug, Clone)]
pub struct SendRequest {
    /// Account to spend from (change returns to it).
    pub account: u32,
    /// Destinations.
    pub payments: Vec<Payment>,
    /// Fee priority.
    pub priority: FeePriority,
}

/// A validated intent plus the figures to show the user.
#[derive(Debug, Clone)]
pub struct BuiltIntent {
    /// The intent to send to the signer.
    pub intent: TxIntent,
    /// Exact fee (piconero).
    pub fee: u64,
    /// Sum of inputs.
    pub inputs_total: u64,
    /// Change returned to the wallet.
    pub change: u64,
    /// Keys of the outputs being spent (to mark as pending).
    pub spent_keys: Vec<[u8; 32]>,
}

/// Intent-building errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IntentError {
    /// Nothing to pay.
    #[error("no payments")]
    NoPayments,
    /// Too many payments.
    #[error("too many destinations (max {MAX_PAYMENTS})")]
    TooManyPayments,
    /// Amount zero.
    #[error("amounts must be greater than zero")]
    ZeroAmount,
    /// Not enough spendable funds.
    #[error(
        "insufficient spendable funds: need at least {needed} piconero, spendable {available}{hint}"
    )]
    InsufficientFunds {
        /// Spendable sum.
        available: u64,
        /// Payments total (fee not included).
        needed: u64,
        /// Hint about unverified outputs.
        hint: &'static str,
    },
    /// Node RPC failure.
    #[error("node error: {0}")]
    Node(String),
    /// Transaction construction failed.
    #[error("cannot build transaction: {0}")]
    Build(String),
    /// Too many inputs would be needed.
    #[error("would need more than {MAX_INPUTS} inputs; consolidate funds first")]
    TooManyInputs,
}

fn rng() -> rand_core::OsRng {
    rand_core::OsRng
}

/// Builds an intent for `req`.
///
/// # Errors
/// [`IntentError`].
#[allow(clippy::too_many_lines)] // one linear selection loop; splitting it obscures the flow
pub async fn build_intent<R>(
    state: &WalletState,
    keys: &ViewKeys,
    rpc: &R,
    req: &SendRequest,
    now: u64,
) -> Result<BuiltIntent, IntentError>
where
    R: ProvidesDecoys + ProvidesFeeRates + ProvidesBlockchainMeta,
{
    if req.payments.is_empty() {
        return Err(IntentError::NoPayments);
    }
    if req.payments.len() > MAX_PAYMENTS {
        return Err(IntentError::TooManyPayments);
    }
    if req.payments.iter().any(|p| p.amount == 0) {
        return Err(IntentError::ZeroAmount);
    }
    let needed = req
        .payments
        .iter()
        .try_fold(0u64, |acc, p| acc.checked_add(p.amount))
        .ok_or(IntentError::ZeroAmount)?;

    let tip = rpc
        .latest_block_number()
        .await
        .map_err(|e| IntentError::Node(e.to_string()))?;
    let chain_height = u64::try_from(tip).unwrap_or(u64::MAX).saturating_add(1);
    let fee_rate = rpc
        .fee_rate(req.priority, max_fee_per_weight(keys.network()))
        .await
        .map_err(|e| IntentError::Node(format!("fee rate: {e}")))?;

    // Candidates: this account, key image known, not spent, unlocked.
    let mut candidates: Vec<&crate::state::OwnedOutput> = state
        .outputs
        .iter()
        .filter(|o| o.subaddress().0 == req.account)
        .filter(|o| o.key_image.is_some() && o.spent().is_none())
        .filter(|o| is_unlocked(o, chain_height, now))
        .collect();
    candidates.sort_by_key(|o| core::cmp::Reverse(o.amount()));
    let available: u64 = candidates.iter().map(|o| o.amount()).sum();
    let unverified = state
        .outputs
        .iter()
        .any(|o| o.subaddress().0 == req.account && o.key_image.is_none());
    let hint = if unverified {
        " (some outputs have no key image yet: import key images from the signer)"
    } else {
        ""
    };
    if available < needed {
        return Err(IntentError::InsufficientFunds {
            available,
            needed,
            hint,
        });
    }

    let change_idx = SubaddressIndex::new(req.account, 0);
    let payments: Vec<_> = req.payments.iter().map(|p| (p.address, p.amount)).collect();
    // A fresh outgoing view key for validation only; the signer generates its own.
    let mut ovk = Zeroizing::new([0u8; 32]);
    getrandom::fill(ovk.as_mut()).map_err(|_| IntentError::Build("OS RNG failed".into()))?;

    let mut inputs: Vec<OutputWithDecoys> = Vec::new();
    let mut spent_keys = Vec::new();
    let mut inputs_total = 0u64;
    for o in candidates {
        if inputs.len() >= MAX_INPUTS {
            return Err(IntentError::TooManyInputs);
        }
        let with_decoys = OutputWithDecoys::new(&mut rng(), rpc, RING_LEN, tip, o.output.clone())
            .await
            .map_err(|e| IntentError::Node(format!("decoy selection: {e}")))?;
        inputs.push(with_decoys);
        spent_keys.push(o.key());
        inputs_total = inputs_total.saturating_add(o.amount());
        if inputs_total < needed {
            continue;
        }
        match SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            ovk.clone(),
            inputs.clone(),
            payments.clone(),
            Change::new(keys.view_pair(), change_idx),
            vec![],
            fee_rate,
        ) {
            Ok(stx) => {
                let fee = stx.necessary_fee();
                let change = inputs_total
                    .checked_sub(needed)
                    .and_then(|r| r.checked_sub(fee))
                    .ok_or_else(|| IntentError::Build("fee exceeds inputs".into()))?;
                let intent = TxIntent {
                    rct_type: RctType::ClsagBulletproofPlus,
                    fee_rate,
                    inputs,
                    payments: req.payments.clone(),
                    change: change_idx,
                };
                intent
                    .check(keys.network())
                    .map_err(|e| IntentError::Build(e.to_string()))?;
                return Ok(BuiltIntent {
                    intent,
                    fee,
                    inputs_total,
                    change,
                    spent_keys,
                });
            }
            Err(SendError::NotEnoughFunds { .. }) => {}
            Err(e) => return Err(IntentError::Build(e.to_string())),
        }
    }
    Err(IntentError::InsufficientFunds {
        available,
        needed,
        hint: " (not enough to also cover the fee)",
    })
}
