//! Vault header: layout, bounds and strict parsing. Spec: `docs/FORMATS.md`.

use crate::{NONCE_LEN, SALT_LEN, VaultError};

/// Magic bytes at offset 0.
pub const MAGIC: [u8; 8] = *b"ZTVAULT\0";
/// The only format version this build reads or writes.
pub const VERSION: u16 = 1;
/// Header length in bytes (the whole header is AEAD associated data).
pub const HEADER_LEN: usize = 92;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// Largest accepted plaintext (256 MiB).
pub const MAX_PLAINTEXT_LEN: usize = 256 * 1024 * 1024;

const KDF_ARGON2ID_V13: u8 = 1;
const AEAD_XCHACHA20POLY1305: u8 = 1;

/// What a vault file contains. Bound into the AAD so that a file of one kind
/// can never be accepted as another (e.g. a view-wallet cache as signer keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentType {
    /// Signer secrets (seed / spend key). Only `kage-signer` opens these.
    SignerSecrets,
    /// View-only wallet: view key, public spend key, cache.
    ViewWallet,
}

impl ContentType {
    /// Wire value.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        match self {
            Self::SignerSecrets => 1,
            Self::ViewWallet => 2,
        }
    }

    fn from_u16(v: u16) -> Result<Self, VaultError> {
        match v {
            1 => Ok(Self::SignerSecrets),
            2 => Ok(Self::ViewWallet),
            other => Err(VaultError::UnknownContentType(other)),
        }
    }
}

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// Minimum memory: 64 MiB. That is RFC 9106 §4's second recommended
    /// option, and the floor we never go below.
    pub const MIN_M_COST_KIB: u32 = 64 * 1024;
    /// Maximum memory accepted from a file: 4 GiB (DoS bound).
    pub const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024;
    /// Minimum iterations (RFC 9106 §4 second option: t=3).
    pub const MIN_T_COST: u32 = 3;
    /// Maximum iterations accepted from a file (DoS bound).
    pub const MAX_T_COST: u32 = 64;
    /// Maximum lanes.
    pub const MAX_P_COST: u32 = 16;

    /// Default for new vaults: 256 MiB, t=4, p=1. That is 4x the RFC 9106
    /// minimum memory, and still workable on a low-end offline signer (ADR-004).
    pub const DEFAULT: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 4,
        p_cost: 1,
    };

    /// The weakest parameters accepted. Used by tests and benchmarks.
    pub const MINIMUM: Self = Self {
        m_cost_kib: Self::MIN_M_COST_KIB,
        t_cost: Self::MIN_T_COST,
        p_cost: 1,
    };

    /// Validates bounds.
    ///
    /// # Errors
    /// [`VaultError::KdfParamsOutOfBounds`].
    pub fn check(self) -> Result<(), VaultError> {
        if !(Self::MIN_M_COST_KIB..=Self::MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            return Err(VaultError::KdfParamsOutOfBounds("memory"));
        }
        if !(Self::MIN_T_COST..=Self::MAX_T_COST).contains(&self.t_cost) {
            return Err(VaultError::KdfParamsOutOfBounds("iterations"));
        }
        if !(1..=Self::MAX_P_COST).contains(&self.p_cost) {
            return Err(VaultError::KdfParamsOutOfBounds("lanes"));
        }
        // Argon2 requires m >= 8 * p; implied by the bounds above, but be explicit.
        if self.m_cost_kib < self.p_cost.saturating_mul(8) {
            return Err(VaultError::KdfParamsOutOfBounds("memory/lanes"));
        }
        Ok(())
    }
}

/// Parsed vault header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Format version.
    pub version: u16,
    /// Content type.
    pub content: ContentType,
    /// KDF parameters.
    pub params: KdfParams,
    /// Argon2 salt.
    pub salt: [u8; SALT_LEN],
    /// AEAD nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext length (excluding the tag).
    pub ciphertext_len: u64,
}

impl Header {
    /// Serialises the header (exactly [`HEADER_LEN`] bytes).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut w = Writer {
            buf: [0u8; HEADER_LEN],
            pos: 0,
        };
        w.put(&MAGIC);
        w.put(&self.version.to_le_bytes());
        w.put(&self.content.to_u16().to_le_bytes());
        w.put(&[KDF_ARGON2ID_V13, AEAD_XCHACHA20POLY1305, 0, 0]);
        w.put(&self.params.m_cost_kib.to_le_bytes());
        w.put(&self.params.t_cost.to_le_bytes());
        w.put(&self.params.p_cost.to_le_bytes());
        w.put(&self.salt);
        w.put(&self.nonce);
        w.put(&self.ciphertext_len.to_le_bytes());
        w.buf
    }
}

struct Writer {
    buf: [u8; HEADER_LEN],
    pos: usize,
}

impl Writer {
    fn put(&mut self, bytes: &[u8]) {
        // Layout is fixed and sums to HEADER_LEN; a mismatch is caught by the
        // `layout_is_exact` test. Out-of-range writes are dropped, never panic.
        let end = self.pos.saturating_add(bytes.len());
        if let Some(dst) = self.buf.get_mut(self.pos..end) {
            dst.copy_from_slice(bytes);
        }
        self.pos = end;
    }
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], VaultError> {
        let (head, rest) = self.buf.split_at_checked(N).ok_or(VaultError::Truncated)?;
        self.buf = rest;
        head.try_into().map_err(|_| VaultError::Truncated)
    }
    fn u16(&mut self) -> Result<u16, VaultError> {
        self.take::<2>().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Result<u32, VaultError> {
        self.take::<4>().map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Result<u64, VaultError> {
        self.take::<8>().map(u64::from_le_bytes)
    }
    fn u8(&mut self) -> Result<u8, VaultError> {
        self.take::<1>().map(|[b]| b)
    }
}

/// Strictly parses and validates the header of a **complete** vault file.
///
/// Performs every check that does not need the password, so malformed or
/// hostile files are rejected before the (expensive) KDF runs. Safe on
/// arbitrary input (fuzzed: `fuzz/fuzz_targets/vault_header.rs`).
///
/// # Errors
/// Any format violation.
pub fn parse_header(file: &[u8]) -> Result<Header, VaultError> {
    let min = HEADER_LEN.saturating_add(TAG_LEN);
    if file.len() < min {
        return Err(VaultError::Truncated);
    }
    let mut r = Reader { buf: file };
    if r.take::<8>()? != MAGIC {
        return Err(VaultError::BadMagic);
    }
    let version = r.u16()?;
    if version != VERSION {
        return Err(VaultError::UnsupportedVersion(version));
    }
    let content = ContentType::from_u16(r.u16()?)?;
    let kdf = r.u8()?;
    if kdf != KDF_ARGON2ID_V13 {
        return Err(VaultError::UnsupportedKdf(kdf));
    }
    let aead = r.u8()?;
    if aead != AEAD_XCHACHA20POLY1305 {
        return Err(VaultError::UnsupportedAead(aead));
    }
    if r.take::<2>()? != [0, 0] {
        return Err(VaultError::Reserved);
    }
    let params = KdfParams {
        m_cost_kib: r.u32()?,
        t_cost: r.u32()?,
        p_cost: r.u32()?,
    };
    params.check()?;
    let salt = r.take::<SALT_LEN>()?;
    let nonce = r.take::<NONCE_LEN>()?;
    let ciphertext_len = r.u64()?;

    let declared = usize::try_from(ciphertext_len).map_err(|_| VaultError::TooLarge)?;
    if declared > MAX_PLAINTEXT_LEN {
        return Err(VaultError::TooLarge);
    }
    let expected_total = min.checked_add(declared).ok_or(VaultError::TooLarge)?;
    if file.len() != expected_total {
        return Err(VaultError::LengthMismatch);
    }
    Ok(Header {
        version,
        content,
        params,
        salt,
        nonce,
        ciphertext_len,
    })
}
