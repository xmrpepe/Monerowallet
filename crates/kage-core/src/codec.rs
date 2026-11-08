//! View-only wallet file plaintext (stored inside a `kage-vault` file of
//! content type `ViewWallet`). Spec: `docs/FORMATS.md` §4.
//!
//! The decoder is strict and total: bounded counts before allocation, exact
//! lengths, no trailing bytes. It is fuzzed (`fuzz/fuzz_targets/wallet_state.rs`).

use std::collections::VecDeque;

use kage_airgap::Network;
use monero_wallet::WalletOutput;
use zeroize::Zeroizing;

use crate::keys::ViewKeys;
use crate::state::{
    Appearance, BackupStatus, Cursor, MAX_APPEARANCES, OwnedOutput, REORG_WINDOW, WalletState,
};
use crate::subaddr::{Account, MAX_ACCOUNTS, MAX_LABEL_LEN, SubaddressBook, sanitize_label};

const MAGIC: [u8; 4] = *b"ZTVW";
const VERSION: u8 = 1;
/// Maximum outputs in one wallet file.
pub const MAX_OUTPUTS: usize = 1_000_000;
const MAX_OUTPUT_LEN: usize = 64 * 1024;

/// Decoding errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// Input ended early.
    #[error("wallet data truncated")]
    Truncated,
    /// Not a wallet file payload.
    #[error("not a ZeroTrace view-wallet payload")]
    Magic,
    /// Unsupported version.
    #[error("unsupported wallet data version {0}")]
    Version(u8),
    /// A field is invalid.
    #[error("invalid {0}")]
    Invalid(&'static str),
    /// A count is out of bounds.
    #[error("{0} out of bounds")]
    Bounds(&'static str),
    /// Bytes after the end.
    #[error("trailing bytes")]
    Trailing,
}

struct W(Zeroizing<Vec<u8>>);
impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    fn len(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
}

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let (h, t) = self.0.split_at_checked(n).ok_or(CodecError::Truncated)?;
        self.0 = t;
        Ok(h)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, CodecError> {
        self.arr::<1>().map(|[b]| b)
    }
    fn u16(&mut self) -> Result<u16, CodecError> {
        self.arr::<2>().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Result<u32, CodecError> {
        self.arr::<4>().map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Result<u64, CodecError> {
        self.arr::<8>().map(u64::from_le_bytes)
    }
    fn bool(&mut self) -> Result<bool, CodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::Invalid("flag")),
        }
    }
    fn count(&mut self, max: usize, what: &'static str) -> Result<usize, CodecError> {
        let n = usize::try_from(self.u32()?).map_err(|_| CodecError::Bounds(what))?;
        if n > max {
            return Err(CodecError::Bounds(what));
        }
        Ok(n)
    }
}

fn put_cursor(w: &mut W, c: &Cursor) {
    w.u64(c.height);
    w.bytes(&c.hash);
    w.u64(c.next_ringct_index);
}

fn get_cursor(r: &mut R<'_>) -> Result<Cursor, CodecError> {
    Ok(Cursor {
        height: r.u64()?,
        hash: r.arr::<32>()?,
        next_ringct_index: r.u64()?,
    })
}

/// Serialises keys + state. The result contains the private view key: it is
/// returned in zeroize-on-drop memory and must only be passed to `kage-vault`.
#[must_use]
pub fn encode(keys: &ViewKeys, state: &WalletState) -> Zeroizing<Vec<u8>> {
    let mut w = W(Zeroizing::new(Vec::new()));
    w.bytes(&MAGIC);
    w.u8(VERSION);
    w.u8(state.network.to_wire());
    w.bytes(keys.view_key_for_vault());
    w.bytes(&keys.spend_public());
    w.u8(match state.backup {
        BackupStatus::Unconfirmed => 0,
        BackupStatus::Attested => 1,
        BackupStatus::VerifiedBySigner => 2,
    });
    w.u64(state.restore_height);
    match &state.cursor {
        None => w.u8(0),
        Some(c) => {
            w.u8(1);
            put_cursor(&mut w, c);
        }
    }
    w.len(state.recent.len());
    for c in &state.recent {
        put_cursor(&mut w, c);
    }
    w.len(state.subaddresses.accounts().len());
    for a in state.subaddresses.accounts() {
        let label = sanitize_label(&a.label);
        w.u16(u16::try_from(label.len()).unwrap_or(0));
        w.bytes(label.as_bytes());
        w.u32(a.addresses);
    }
    w.len(state.outputs.len());
    for o in &state.outputs {
        let ser = Zeroizing::new(o.output.serialize());
        w.len(ser.len());
        w.bytes(&ser);
        w.u64(o.height);
        w.u8(u8::from(o.coinbase));
        match o.key_image {
            None => w.u8(0),
            Some(ki) => {
                w.u8(1);
                w.bytes(&ki);
            }
        }
        w.len(o.ring_appearances.len());
        for a in &o.ring_appearances {
            w.bytes(&a.key_image);
            w.u64(a.height);
            w.bytes(&a.tx);
        }
        w.u8(u8::from(o.appearances_overflowed));
    }
    w.0
}

/// Strictly decodes keys + state.
///
/// # Errors
/// Any format violation, or keys that fail validation.
pub fn decode(bytes: &[u8]) -> Result<(ViewKeys, WalletState), CodecError> {
    let mut r = R(bytes);
    if r.arr::<4>()? != MAGIC {
        return Err(CodecError::Magic);
    }
    match r.u8()? {
        VERSION => {}
        v => return Err(CodecError::Version(v)),
    }
    let network = Network::from_wire(r.u8()?).map_err(|_| CodecError::Invalid("network"))?;
    let mut view = Zeroizing::new(r.arr::<32>()?);
    let spend = r.arr::<32>()?;
    let keys =
        ViewKeys::from_parts(network, &mut view, spend).map_err(|_| CodecError::Invalid("keys"))?;
    let backup = match r.u8()? {
        0 => BackupStatus::Unconfirmed,
        1 => BackupStatus::Attested,
        2 => BackupStatus::VerifiedBySigner,
        _ => return Err(CodecError::Invalid("backup status")),
    };
    let restore_height = r.u64()?;
    let cursor = if r.bool()? {
        Some(get_cursor(&mut r)?)
    } else {
        None
    };
    let n_recent = r.count(REORG_WINDOW, "recent blocks")?;
    let mut recent = VecDeque::with_capacity(n_recent);
    for _ in 0..n_recent {
        recent.push_back(get_cursor(&mut r)?);
    }
    let n_acc = r.count(usize::try_from(MAX_ACCOUNTS).unwrap_or(0), "accounts")?;
    let mut accounts = Vec::with_capacity(n_acc);
    for _ in 0..n_acc {
        let len = usize::from(r.u16()?);
        if len > MAX_LABEL_LEN {
            return Err(CodecError::Bounds("label"));
        }
        let label = core::str::from_utf8(r.take(len)?).map_err(|_| CodecError::Invalid("label"))?;
        if sanitize_label(label) != label {
            return Err(CodecError::Invalid("label"));
        }
        let addresses = r.u32()?;
        if addresses == 0 || addresses > crate::subaddr::MAX_ADDRESSES_PER_ACCOUNT {
            return Err(CodecError::Bounds("addresses"));
        }
        accounts.push(Account {
            label: label.to_owned(),
            addresses,
        });
    }
    let n_out = r.count(MAX_OUTPUTS, "outputs")?;
    let mut outputs = Vec::with_capacity(n_out.min(4096));
    for _ in 0..n_out {
        let len = r.count(MAX_OUTPUT_LEN, "output size")?;
        let mut cur = r.take(len)?;
        let output = WalletOutput::read(&mut cur).map_err(|_| CodecError::Invalid("output"))?;
        if !cur.is_empty() {
            return Err(CodecError::Invalid("output"));
        }
        let height = r.u64()?;
        let coinbase = r.bool()?;
        let key_image = if r.bool()? {
            Some(r.arr::<32>()?)
        } else {
            None
        };
        let n_app = r.count(MAX_APPEARANCES, "appearances")?;
        let mut ring_appearances = Vec::with_capacity(n_app);
        for _ in 0..n_app {
            ring_appearances.push(Appearance {
                key_image: r.arr::<32>()?,
                height: r.u64()?,
                tx: r.arr::<32>()?,
            });
        }
        let appearances_overflowed = r.bool()?;
        outputs.push(OwnedOutput {
            output,
            height,
            coinbase,
            key_image,
            ring_appearances,
            appearances_overflowed,
        });
    }
    if !r.0.is_empty() {
        return Err(CodecError::Trailing);
    }
    let state = WalletState {
        network,
        restore_height,
        cursor,
        recent,
        outputs,
        subaddresses: SubaddressBook::from_accounts(accounts),
        backup,
    };
    Ok((keys, state))
}
