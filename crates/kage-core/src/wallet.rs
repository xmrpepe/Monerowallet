//! A view-only wallet bound to its encrypted file.

use std::path::{Path, PathBuf};

use kage_vault::{ContentType, KdfParams, VaultError, VaultKey};

use crate::codec::{self, CodecError};
use crate::keys::ViewKeys;
use crate::state::WalletState;

/// Wallet file errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WalletError {
    /// Encryption, authentication or I/O failure.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// The decrypted payload is malformed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Refusing to overwrite an existing wallet.
    #[error("a wallet already exists at {0}")]
    Exists(PathBuf),
}

/// An open view-only wallet.
pub struct ViewWallet {
    /// Keys (view key locked in memory).
    pub keys: ViewKeys,
    /// State.
    pub state: WalletState,
    vault_key: VaultKey,
    path: PathBuf,
}

impl core::fmt::Debug for ViewWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViewWallet")
            .field("path", &self.path)
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl ViewWallet {
    /// Creates and saves a new wallet file. Refuses to overwrite.
    ///
    /// # Errors
    /// [`WalletError`].
    pub fn create(
        path: &Path,
        password: &[u8],
        params: KdfParams,
        keys: ViewKeys,
        state: WalletState,
    ) -> Result<Self, WalletError> {
        if path.exists() {
            return Err(WalletError::Exists(path.to_path_buf()));
        }
        let vault_key = VaultKey::derive_new(password, params, ContentType::ViewWallet)?;
        let w = Self {
            keys,
            state,
            vault_key,
            path: path.to_path_buf(),
        };
        w.save()?;
        Ok(w)
    }

    /// Opens a wallet file.
    ///
    /// # Errors
    /// Wrong password or tampered file ([`VaultError::Authentication`]), or a
    /// malformed payload.
    pub fn open(path: &Path, password: &[u8]) -> Result<Self, WalletError> {
        let file = kage_vault::read_bounded(path)?;
        let (vault_key, plaintext) = kage_vault::open(password, ContentType::ViewWallet, &file)?;
        let (keys, state) = codec::decode(&plaintext)?;
        Ok(Self {
            keys,
            state,
            vault_key,
            path: path.to_path_buf(),
        })
    }

    /// Re-encrypts and atomically replaces the wallet file (fresh nonce).
    ///
    /// # Errors
    /// [`WalletError`].
    pub fn save(&self) -> Result<(), WalletError> {
        let plaintext = codec::encode(&self.keys, &self.state);
        let sealed = kage_vault::seal(&self.vault_key, &plaintext)?;
        kage_vault::write_atomic(&self.path, &sealed)?;
        Ok(())
    }

    /// Verifies `password` against this wallet (screen-lock unlock).
    /// Re-derives the key with the stored salt and parameters, so it costs
    /// one Argon2id run.
    #[must_use]
    pub fn check_password(&self, password: &[u8]) -> bool {
        kage_vault::read_bounded(&self.path)
            .ok()
            .and_then(|file| kage_vault::open(password, ContentType::ViewWallet, &file).ok())
            .is_some()
    }

    /// File path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}
