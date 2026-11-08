//! Chain synchronisation: scanning, reorg handling, private spend detection.
//!
//! Trust handling (T-CORE-PARSE, T-NODE-LIE):
//! - each batch must chain onto our cursor by `previous` hash; if not, it is a
//!   reorg, handled by rewinding to the last block hash the node still agrees with;
//! - the "first RingCT output index" the node claims for each block is
//!   checked against our own running count (anchored once at the restore
//!   height). Any mismatch means the node is lying, and syncing stops;
//! - `monero-wallet`'s scanner verifies amounts and commitments for every
//!   output it reports.

use std::collections::HashMap;

use monero_wallet::Scanner;
use monero_wallet::interface::{
    InterfaceError, ProvidesBlockchain, ProvidesBlockchainMeta, ProvidesScannableBlocks,
    ScannableBlock,
};
use monero_wallet::transaction::{Input, Transaction};

use crate::keys::ViewKeys;
use crate::state::{Appearance, Cursor, MAX_APPEARANCES, OwnedOutput, REORG_WINDOW, WalletState};

/// Blocks fetched per request.
pub const BATCH: u64 = 100;

/// Sync errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// RPC failure.
    #[error("node error: {0}")]
    Node(#[from] InterfaceError),
    /// The scanner rejected a block.
    #[error("scan error: {0}")]
    Scan(String),
    /// The node's data is inconsistent with what we verified (lying or broken node).
    #[error("node data is inconsistent: {0}. Disconnecting; do not trust this node")]
    Inconsistent(String),
    /// A reorg deeper than our window.
    #[error("chain reorganisation deeper than {REORG_WINDOW} blocks; a full rescan is required")]
    DeepReorg,
}

/// Progress callback payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// Last scanned block.
    pub scanned: u64,
    /// Node tip.
    pub tip: u64,
}

/// What a sync call did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Blocks scanned.
    pub blocks: u64,
    /// New outputs found.
    pub new_outputs: usize,
    /// Blocks rolled back by a reorg.
    pub rolled_back: u64,
}

fn usize_of(v: u64) -> Result<usize, SyncError> {
    usize::try_from(v).map_err(|_| SyncError::Inconsistent("height overflow".into()))
}

fn u64_of(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

/// Number of RingCT outputs a block creates (v2 miner tx + v2 txs), matching
/// `monero-interface`'s and monerod's indexing.
fn ringct_outputs_in(block: &ScannableBlock) -> u64 {
    let miner = block.block.miner_transaction();
    let miner_count = if matches!(miner, Transaction::V2 { .. }) {
        miner.prefix().outputs.len()
    } else {
        0
    };
    let txs: usize = block
        .transactions
        .iter()
        .filter(|t| matches!(t, Transaction::V2 { .. }))
        .map(|t| t.prefix().outputs.len())
        .sum();
    u64_of(miner_count.saturating_add(txs))
}

/// Brings `state` up to the node's tip.
///
/// # Errors
/// [`SyncError`]. `state` is only modified for fully processed blocks, so it
/// remains consistent on error.
pub async fn sync<P>(
    state: &mut WalletState,
    keys: &ViewKeys,
    rpc: &P,
    mut progress: impl FnMut(Progress),
) -> Result<SyncReport, SyncError>
where
    P: ProvidesScannableBlocks + ProvidesBlockchain + ProvidesBlockchainMeta,
{
    let mut report = SyncReport {
        rolled_back: handle_reorg(state, rpc).await?,
        ..SyncReport::default()
    };

    let mut scanner = Scanner::new(keys.view_pair());
    state.subaddresses.register(&mut scanner);

    let tip = u64_of(rpc.latest_block_number().await?);
    let mut next = state
        .cursor
        .map_or(state.restore_height, |c| c.height.saturating_add(1));

    while next <= tip {
        let end = next.saturating_add(BATCH - 1).min(tip);
        let blocks = rpc
            .contiguous_scannable_blocks(usize_of(next)?..=usize_of(end)?)
            .await?;
        if u64_of(blocks.len()) != end.saturating_sub(next).saturating_add(1) {
            return Err(SyncError::Inconsistent(
                "wrong number of blocks returned".into(),
            ));
        }
        for block in blocks {
            let found = process_block(state, &mut scanner, block)?;
            report.new_outputs = report.new_outputs.saturating_add(found);
            report.blocks = report.blocks.saturating_add(1);
        }
        progress(Progress { scanned: end, tip });
        next = end.saturating_add(1);
    }
    Ok(report)
}

fn process_block(
    state: &mut WalletState,
    scanner: &mut Scanner,
    mut block: ScannableBlock,
) -> Result<usize, SyncError> {
    let height = u64_of(block.block.number());
    let hash = block.block.hash();

    // 1. Chain linkage.
    if let Some(c) = state.cursor
        && (height != c.height.saturating_add(1) || block.block.header.previous != c.hash)
    {
        return Err(SyncError::Inconsistent(format!(
            "block {height} does not build on our last block {}",
            c.height
        )));
    }

    // 2. RingCT index: verify the node's claim against our own count.
    let created = ringct_outputs_in(&block);
    let claimed = block.output_index_for_first_ringct_output;
    let first_index = match state.cursor {
        Some(c) => {
            match claimed {
                Some(v) if v != c.next_ringct_index => {
                    return Err(SyncError::Inconsistent(format!(
                        "node claims RingCT index {v} for block {height}, expected {}",
                        c.next_ringct_index
                    )));
                }
                None if created != 0 => {
                    return Err(SyncError::Inconsistent(format!(
                        "block {height} has RingCT outputs but no index"
                    )));
                }
                _ => {}
            }
            // Use OUR value regardless of what the node said.
            block.output_index_for_first_ringct_output =
                (created != 0).then_some(c.next_ringct_index);
            c.next_ringct_index
        }
        // First block after restore: the anchor is trusted once (documented).
        None => claimed.unwrap_or(0),
    };

    // 3. Ring appearances of our outputs (private spend detection).
    let by_index: HashMap<u64, usize> = state
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| (o.output.index_on_blockchain(), i))
        .collect();
    let tx_hashes = block.block.transactions.clone();
    for (tx, tx_hash) in block.transactions.iter().zip(tx_hashes.iter()) {
        for input in &tx.prefix().inputs {
            let Input::ToKey {
                key_offsets,
                key_image,
                ..
            } = input
            else {
                continue;
            };
            let mut abs = 0u64;
            for off in key_offsets {
                abs = abs.saturating_add(*off);
                if let Some(&i) = by_index.get(&abs)
                    && let Some(o) = state.outputs.get_mut(i)
                {
                    record(o, key_image.to_bytes(), height, *tx_hash);
                }
            }
        }
    }

    // 4. Scan for new outputs.
    let miner_hash = block.block.miner_transaction().hash();
    let found = scanner
        .scan(block)
        .map_err(|e| SyncError::Scan(e.to_string()))?
        .ignore_additional_timelock(); // timelocks are evaluated in `balance`
    let mut new = 0usize;
    for out in found {
        let key = out.key().compress().to_bytes();
        if state.outputs.iter().any(|o| o.key() == key) {
            continue; // burning-bug protection: same output key twice is ignored
        }
        let coinbase = out.transaction() == miner_hash;
        if let Some(s) = out.subaddress()
            && state.subaddresses.mark_used(s.account(), s.address())
        {
            state.subaddresses.register(scanner);
        }
        state.outputs.push(OwnedOutput {
            output: out,
            height,
            coinbase,
            key_image: None,
            ring_appearances: Vec::new(),
            appearances_overflowed: false,
        });
        new = new.saturating_add(1);
    }

    // 5. Advance.
    let cursor = Cursor {
        height,
        hash,
        next_ringct_index: first_index.saturating_add(created),
    };
    state.cursor = Some(cursor);
    state.recent.push_back(cursor);
    while state.recent.len() > REORG_WINDOW {
        state.recent.pop_front();
    }
    Ok(new)
}

fn record(o: &mut OwnedOutput, key_image: [u8; 32], height: u64, tx: [u8; 32]) {
    if o.ring_appearances
        .iter()
        .any(|a| a.key_image == key_image && a.tx == tx)
    {
        return;
    }
    if o.ring_appearances.len() >= MAX_APPEARANCES {
        o.appearances_overflowed = true;
        return;
    }
    o.ring_appearances.push(Appearance {
        key_image,
        height,
        tx,
    });
}

/// Detects a reorg by comparing our recent hashes with the node's, newest
/// first, and rewinds to the newest block both agree on.
async fn handle_reorg<P>(state: &mut WalletState, rpc: &P) -> Result<u64, SyncError>
where
    P: ProvidesBlockchain + ProvidesBlockchainMeta,
{
    let Some(cursor) = state.cursor else {
        return Ok(0);
    };
    let tip = u64_of(rpc.latest_block_number().await?);
    if cursor.height <= tip {
        let node_hash = rpc.block_hash(usize_of(cursor.height)?).await?;
        if node_hash == cursor.hash {
            return Ok(0);
        }
    }
    // Walk back through our window.
    let recent: Vec<Cursor> = state.recent.iter().rev().copied().collect();
    for c in recent {
        if c.height > tip {
            continue;
        }
        if rpc.block_hash(usize_of(c.height)?).await? == c.hash {
            let rolled = cursor.height.saturating_sub(c.height);
            rewind_to(state, c);
            return Ok(rolled);
        }
    }
    Err(SyncError::DeepReorg)
}

/// Drops everything above `keep.height` and restores that block's cursor
/// (including its verified RingCT counter).
fn rewind_to(state: &mut WalletState, keep: Cursor) {
    state.outputs.retain(|o| o.height <= keep.height);
    for o in &mut state.outputs {
        o.ring_appearances.retain(|a| a.height <= keep.height);
    }
    while state.recent.back().is_some_and(|c| c.height > keep.height) {
        state.recent.pop_back();
    }
    state.cursor = Some(keep);
}
