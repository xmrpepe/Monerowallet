//! # kage-vault: encrypted, versioned, tamper-evident wallet files
//!
//! **Security-critical. Listed in `AUDIT.md`. Format spec: `docs/FORMATS.md`.**
//!
//! A vault file is `header || ciphertext || tag`:
//!
//! - key = Argon2id v1.3 (password, 32-byte random salt, params from header)
//! - AEAD = XChaCha20-Poly1305, 24-byte random nonce, fresh on every write
//! - AAD = the **entire** 92-byte header, so any header change (version,
//!   content type, KDF params, salt, nonce, length) fails authentication
//!
//! No cryptography is implemented here: only the audited-lineage RustCrypto
//! primitives are composed, in the standard way (ADR-004).
//!
//! Before running the KDF, the parser rejects anything outside strict bounds:
//! unknown version or algorithm, non-zero reserved bytes, KDF parameters out
//! of range (prevents both downgrade and memory-exhaustion DoS), and a length
//! field that does not match the file length exactly.
//!
//! **Not detected:** rollback, i.e. an attacker replacing the file with an
//! *older* valid file. See `docs/THREAT_MODEL.md`, T-VAULT-ROLLBACK.

#![forbid(unsafe_code)]

mod atomic;
mod format;

pub use atomic::{read_bounded, write_atomic};
pub use format::{
    ContentType, HEADER_LEN, Header, KdfParams, MAGIC, MAX_PLAINTEXT_LEN, TAG_LEN, VERSION,
    parse_header,
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use kage_sys::{LockError, LockedBytes};
use zeroize::Zeroizing;

/// Length of the derived AEAD key.
pub const KEY_LEN: usize = 32;
/// Length of the Argon2 salt.
pub const SALT_LEN: usize = 32;
/// Length of the XChaCha20 nonce.
pub const NONCE_LEN: usize = 24;

/// Vault errors.
///
/// [`VaultError::Authentication`] deliberately does not distinguish "wrong
/// password" from "file tampered with".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VaultError {
    /// Input shorter than a header plus tag.
    #[error("vault file truncated")]
    Truncated,
    /// Magic bytes do not match.
    #[error("not a ZeroTrace vault file")]
    BadMagic,
    /// Format version not supported by this build.
    #[error("unsupported vault format version {0}")]
    UnsupportedVersion(u16),
    /// The file holds a different kind of content than requested.
    #[error("vault content type mismatch (expected {expected:?}, found {found})")]
    WrongContentType {
        /// What the caller asked for.
        expected: ContentType,
        /// Raw value in the file.
        found: u16,
    },
    /// Unknown content type value.
    #[error("unknown vault content type {0}")]
    UnknownContentType(u16),
    /// Unknown KDF identifier.
    #[error("unsupported KDF id {0}")]
    UnsupportedKdf(u8),
    /// Unknown AEAD identifier.
    #[error("unsupported AEAD id {0}")]
    UnsupportedAead(u8),
    /// Reserved header bytes are non-zero.
    #[error("reserved header field is non-zero")]
    Reserved,
    /// KDF parameters outside the accepted bounds.
    #[error("KDF parameters out of bounds: {0}")]
    KdfParamsOutOfBounds(&'static str),
    /// Declared ciphertext length does not match the input length.
    #[error("vault length field does not match file size")]
    LengthMismatch,
    /// Plaintext or file exceeds [`MAX_PLAINTEXT_LEN`].
    #[error("vault content too large")]
    TooLarge,
    /// The password is empty.
    #[error("empty password")]
    EmptyPassword,
    /// Wrong password, or the file was modified.
    #[error("authentication failed: wrong password or file modified")]
    Authentication,
    /// The key does not belong to this file (different salt/params/type).
    #[error("key does not match this vault file")]
    KeyMismatch,
    /// The KDF failed.
    #[error("key derivation failed")]
    Kdf,
    /// The OS CSPRNG failed.
    #[error("OS random number generator failed")]
    Rng,
    /// Locked memory could not be allocated.
    #[error(transparent)]
    Lock(#[from] LockError),
    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A derived vault key, held in locked memory, bound to one salt, one set of
/// KDF parameters and one content type.
pub struct VaultKey {
    key: LockedBytes,
    salt: [u8; SALT_LEN],
    params: KdfParams,
    content: ContentType,
}

impl core::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultKey")
            .field("key", &"[REDACTED]")
            .field("params", &self.params)
            .field("content", &self.content)
            .finish_non_exhaustive()
    }
}

impl VaultKey {
    /// Derives a key for a **new** vault with a fresh random salt.
    ///
    /// # Errors
    /// Empty password, out-of-bounds params, RNG, KDF or memory-lock failure.
    pub fn derive_new(
        password: &[u8],
        params: KdfParams,
        content: ContentType,
    ) -> Result<Self, VaultError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt).map_err(|_| VaultError::Rng)?;
        Self::derive(password, salt, params, content)
    }

    fn derive(
        password: &[u8],
        salt: [u8; SALT_LEN],
        params: KdfParams,
        content: ContentType,
    ) -> Result<Self, VaultError> {
        if password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        params.check()?;
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                params.m_cost_kib,
                params.t_cost,
                params.p_cost,
                Some(KEY_LEN),
            )
            .map_err(|_| VaultError::Kdf)?,
        );
        let mut key = LockedBytes::new_zeroed(KEY_LEN)?;
        argon
            .hash_password_into(password, &salt, key.expose_mut())
            .map_err(|_| VaultError::Kdf)?;
        Ok(Self {
            key,
            salt,
            params,
            content,
        })
    }

    /// KDF parameters this key was derived with.
    #[must_use]
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Content type this key is bound to.
    #[must_use]
    pub fn content(&self) -> ContentType {
        self.content
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, VaultError> {
        XChaCha20Poly1305::new_from_slice(self.key.expose()).map_err(|_| VaultError::Kdf)
    }
}

/// Encrypts `plaintext` into a complete vault file, with a fresh random nonce.
///
/// # Errors
/// Plaintext too large, RNG failure.
pub fn seal(key: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let len = u64::try_from(plaintext.len()).map_err(|_| VaultError::TooLarge)?;
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(VaultError::TooLarge);
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Rng)?;
    let header = Header {
        version: VERSION,
        content: key.content,
        params: key.params,
        salt: key.salt,
        nonce,
        ciphertext_len: len,
    };
    let header_bytes = header.to_bytes();

    let total = HEADER_LEN
        .checked_add(plaintext.len())
        .and_then(|n| n.checked_add(TAG_LEN))
        .ok_or(VaultError::TooLarge)?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(plaintext);
    let body = out.get_mut(HEADER_LEN..).ok_or(VaultError::Truncated)?;
    let tag = key
        .cipher()?
        .encrypt_inout_detached(&XNonce::from(nonce), &header_bytes, body.into())
        .map_err(|_| VaultError::Authentication)?;
    out.extend_from_slice(tag.as_slice());
    Ok(out)
}

/// Opens a vault with a password, decrypting into **locked** memory.
/// Use for small, secret-bearing files (keys, seeds).
///
/// Returns the derived key so the caller can re-seal later without running
/// the KDF again.
///
/// # Errors
/// Any header/bounds violation (checked *before* the KDF runs), wrong
/// password or tampering ([`VaultError::Authentication`]).
pub fn open_locked(
    password: &[u8],
    expected: ContentType,
    file: &[u8],
) -> Result<(VaultKey, LockedBytes), VaultError> {
    let header = checked_header(expected, file)?;
    let key = VaultKey::derive(password, header.salt, header.params, header.content)?;
    let pt = open_locked_with_key(&key, file)?;
    Ok((key, pt))
}

/// Opens a vault with a password into ordinary (zeroize-on-drop) memory. Use
/// for large, privacy-sensitive but non-key data (e.g. the view-only cache).
///
/// # Errors
/// As [`open_locked`].
pub fn open(
    password: &[u8],
    expected: ContentType,
    file: &[u8],
) -> Result<(VaultKey, Zeroizing<Vec<u8>>), VaultError> {
    let header = checked_header(expected, file)?;
    let key = VaultKey::derive(password, header.salt, header.params, header.content)?;
    let pt = open_with_key(&key, file)?;
    Ok((key, pt))
}

/// Decrypts with an already-derived key into locked memory.
///
/// # Errors
/// [`VaultError::KeyMismatch`] if salt/params/type differ, else as [`open_locked`].
pub fn open_locked_with_key(key: &VaultKey, file: &[u8]) -> Result<LockedBytes, VaultError> {
    let (header, ct, tag) = split_for_key(key, file)?;
    if ct.is_empty() {
        // LockedBytes cannot be zero-length; an empty secret is never valid.
        return Err(VaultError::Truncated);
    }
    let mut buf = LockedBytes::new_zeroed(ct.len())?;
    buf.expose_mut().copy_from_slice(ct);
    decrypt_in_place(key, &header, buf.expose_mut(), tag)?;
    Ok(buf)
}

/// Decrypts with an already-derived key into zeroize-on-drop memory.
///
/// # Errors
/// As [`open_locked_with_key`].
pub fn open_with_key(key: &VaultKey, file: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let (header, ct, tag) = split_for_key(key, file)?;
    let mut buf = Zeroizing::new(ct.to_vec());
    decrypt_in_place(key, &header, buf.as_mut_slice(), tag)?;
    Ok(buf)
}

fn checked_header(expected: ContentType, file: &[u8]) -> Result<Header, VaultError> {
    let header = parse_header(file)?;
    if header.content != expected {
        return Err(VaultError::WrongContentType {
            expected,
            found: header.content.to_u16(),
        });
    }
    Ok(header)
}

fn split_for_key<'a>(
    key: &VaultKey,
    file: &'a [u8],
) -> Result<(Header, &'a [u8], &'a [u8]), VaultError> {
    let header = checked_header(key.content, file)?;
    if header.salt != key.salt || header.params != key.params {
        return Err(VaultError::KeyMismatch);
    }
    let body = file.get(HEADER_LEN..).ok_or(VaultError::Truncated)?;
    let ct_len = body
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(VaultError::Truncated)?;
    let (ct, tag) = body.split_at_checked(ct_len).ok_or(VaultError::Truncated)?;
    Ok((header, ct, tag))
}

fn decrypt_in_place(
    key: &VaultKey,
    header: &Header,
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), VaultError> {
    let tag = Tag::try_from(tag).map_err(|_| VaultError::Truncated)?;
    let result = key.cipher()?.decrypt_inout_detached(
        &XNonce::from(header.nonce),
        &header.to_bytes(),
        buf.into(),
        &tag,
    );
    if result.is_err() {
        // Do not leave unauthenticated plaintext behind.
        zeroize::Zeroize::zeroize(buf);
        return Err(VaultError::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
