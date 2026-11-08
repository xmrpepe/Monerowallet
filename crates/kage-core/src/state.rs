//! Persistent view-only wallet state.

use std::collections::{HashMap, VecDeque};

use kage_airgap::Network;
use monero_wallet::WalletOutput;

use crate::subaddr::SubaddressBook;

/// How many recent block hashes are kept for reorg detection.
pub const REORG_WINDOW: usize = 128;
/// Bound on recorded ring appearances per output (see [`OwnedOutput::ring_appearances`]).
pub const MAX_APPEARANCES: usize = 4096;

/// A transaction input whose ring contains one of our outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appearance {
    /// The input's key image.
    pub key_image: [u8; 32],
    /// Height of the block containing the spending transaction.
    pub height: u64,
    /// Hash of the spending transaction.
    pub tx: [u8; 32],
}

/// One output we own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedOutput {
    /// The output as found by the scanner.
    pub output: WalletOutput,
    /// Height of the block containing it.
    pub height: u64,
    /// Whether it is a miner (coinbase) output.
    pub coinbase: bool,
    /// Key image, once imported from the signer.
    pub key_image: Option<[u8; 32]>,
    /// Every on-chain input whose ring included this output. An output is
    /// spent iff its key image is among these. This detects spends privately:
    /// no key image is ever sent to the node (cf. wallet2's
    /// `is_key_image_spent`).
    pub ring_appearances: Vec<Appearance>,
    /// More than [`MAX_APPEARANCES`] were seen; spend detection for this output
    /// then falls back to a full rescan after key-image import.
    pub appearances_overflowed: bool,
}

impl OwnedOutput {
    /// Output's one-time key.
    #[must_use]
    pub fn key(&self) -> [u8; 32] {
        self.output.key().compress().to_bytes()
    }

    /// Amount in piconero.
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.output.commitment().amount
    }

    /// `(account, index)` it was received on.
    #[must_use]
    pub fn subaddress(&self) -> (u32, u32) {
        self.output
            .subaddress()
            .map_or((0, 0), |s| (s.account(), s.address()))
    }

    /// The spending input, if spent and known.
    #[must_use]
    pub fn spent(&self) -> Option<&Appearance> {
        let ki = self.key_image?;
        self.ring_appearances.iter().find(|a| a.key_image == ki)
    }
}

/// Where scanning stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Last scanned block number.
    pub height: u64,
    /// Its hash.
    pub hash: [u8; 32],
    /// The RingCT output index the *next* block's first RingCT output must
    /// have. Tracked locally so a node cannot lie about it (see `sync`).
    pub next_ringct_index: u64,
}

/// Seed-backup status, which gates showing receive addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupStatus {
    /// No backup confirmed yet. Receive addresses are not shown.
    Unconfirmed,
    /// The user attested that they verified the backup of a wallet created
    /// elsewhere (this wallet never sees the seed, so it cannot check).
    Attested,
    /// The ZeroTrace signer verified the backup interactively (Stage 4).
    VerifiedBySigner,
}

/// The whole wallet state that is persisted (encrypted) to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletState {
    /// Network.
    pub network: Network,
    /// First block to scan.
    pub restore_height: u64,
    /// Last scanned block, if any.
    pub cursor: Option<Cursor>,
    /// Cursors of the most recent blocks, oldest first, for reorg detection.
    /// Each keeps its verified RingCT counter, so a rewind restores it exactly.
    pub recent: VecDeque<Cursor>,
    /// Outputs we own.
    pub outputs: Vec<OwnedOutput>,
    /// Accounts and subaddresses.
    pub subaddresses: SubaddressBook,
    /// Backup gating.
    pub backup: BackupStatus,
}

impl WalletState {
    /// A fresh wallet.
    #[must_use]
    pub fn new(network: Network, restore_height: u64) -> Self {
        Self {
            network,
            restore_height,
            cursor: None,
            recent: VecDeque::new(),
            outputs: Vec::new(),
            subaddresses: SubaddressBook::default(),
            backup: BackupStatus::Unconfirmed,
        }
    }

    /// Imports key images (from the signer). Returns how many matched an
    /// owned output. Unknown output keys are ignored.
    pub fn import_key_images(&mut self, entries: &[kage_airgap::payload::KeyImageEntry]) -> usize {
        let map: HashMap<[u8; 32], [u8; 32]> = entries
            .iter()
            .map(|e| (e.output_key, e.key_image))
            .collect();
        let mut matched = 0usize;
        for o in &mut self.outputs {
            if let Some(ki) = map.get(&o.key()) {
                o.key_image = Some(*ki);
                matched = matched.saturating_add(1);
            }
        }
        matched
    }

    /// Whether receive addresses may be shown (forced backup flow).
    #[must_use]
    pub fn receive_allowed(&self) -> bool {
        self.backup != BackupStatus::Unconfirmed
    }
}
