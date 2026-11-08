//! View-only keys: the private view key (in locked memory) plus the public
//! spend key. There is deliberately no way to hold a spend key here
//! (T-CORE-SPEND).

use kage_airgap::Network;
use kage_sys::LockedBytes;
use monero_wallet::ViewPair;
use monero_wallet::address::{AddressType, MoneroAddress, SubaddressIndex};
use monero_wallet::ed25519::{CompressedPoint, Point, Scalar};
use zeroize::Zeroizing;

/// Key import errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// Address does not parse for this network.
    #[error("invalid address for {0}")]
    Address(&'static str),
    /// Only a standard primary address identifies a wallet.
    #[error(
        "expected the wallet's primary (standard) address, not a subaddress or integrated address"
    )]
    NotPrimary,
    /// View key is not a canonical scalar.
    #[error("invalid private view key")]
    ViewKey,
    /// The view key does not belong to the address.
    #[error("the private view key does not match this address")]
    Mismatch,
    /// Locked memory unavailable.
    #[error(transparent)]
    Lock(#[from] kage_sys::LockError),
}

/// The keys of a view-only wallet.
pub struct ViewKeys {
    network: Network,
    view: LockedBytes,
    spend: CompressedPoint,
}

impl core::fmt::Debug for ViewKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViewKeys")
            .field("network", &self.network)
            .field("view", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn parse_scalar(bytes: &[u8]) -> Option<Zeroizing<Scalar>> {
    let mut cur = bytes;
    let s = Scalar::read(&mut cur).ok()?;
    cur.is_empty().then(|| Zeroizing::new(s))
}

impl ViewKeys {
    /// Builds view-only keys from the wallet's primary address and private
    /// view key, verifying that they belong together. `view_key` is zeroized
    /// in every case.
    ///
    /// # Errors
    /// [`KeyError`].
    pub fn from_address_and_view_key(
        network: Network,
        address: &str,
        view_key: &mut [u8; 32],
    ) -> Result<Self, KeyError> {
        let result = Self::build(network, address, view_key);
        zeroize::Zeroize::zeroize(view_key);
        result
    }

    fn build(network: Network, address: &str, view_key: &mut [u8; 32]) -> Result<Self, KeyError> {
        let addr = MoneroAddress::from_str(network.address_network(), address.trim())
            .map_err(|_| KeyError::Address(network.name()))?;
        if *addr.kind() != AddressType::Legacy {
            return Err(KeyError::NotPrimary);
        }
        let scalar = parse_scalar(view_key).ok_or(KeyError::ViewKey)?;
        let pair = ViewPair::new(addr.spend(), scalar).map_err(|_| KeyError::Mismatch)?;
        // The view pair derives the view public key from the private view key;
        // the derived primary address must be the one given.
        if pair.legacy_address(network.address_network()) != addr {
            return Err(KeyError::Mismatch);
        }
        let view = LockedBytes::from_slice_zeroizing(view_key)?;
        Ok(Self {
            network,
            view,
            spend: addr.spend().compress(),
        })
    }

    /// Re-creates keys from their stored form (vault plaintext).
    ///
    /// # Errors
    /// Invalid encodings.
    pub fn from_parts(
        network: Network,
        view_key: &mut [u8; 32],
        spend_public: [u8; 32],
    ) -> Result<Self, KeyError> {
        let result = (|| {
            let spend_point = CompressedPoint::from(spend_public)
                .decompress()
                .ok_or(KeyError::Mismatch)?;
            let scalar = parse_scalar(view_key).ok_or(KeyError::ViewKey)?;
            ViewPair::new(spend_point, scalar).map_err(|_| KeyError::Mismatch)?;
            let view = LockedBytes::from_slice_zeroizing(view_key)?;
            Ok(Self {
                network,
                view,
                spend: CompressedPoint::from(spend_public),
            })
        })();
        zeroize::Zeroize::zeroize(view_key);
        result
    }

    /// The wallet's network.
    #[must_use]
    pub fn network(&self) -> Network {
        self.network
    }

    /// The public spend key.
    #[must_use]
    pub fn spend_public(&self) -> [u8; 32] {
        self.spend.to_bytes()
    }

    /// The private view key bytes, for persistence into the encrypted vault
    /// only. Never display or log.
    #[must_use]
    pub fn view_key_for_vault(&self) -> &[u8] {
        self.view.expose()
    }

    fn spend_point(&self) -> Point {
        // Validated at construction.
        self.spend.decompress().unwrap_or_else(unreachable_point)
    }

    /// A `ViewPair` for scanning and change derivation.
    ///
    /// The returned value holds a `Zeroizing` copy of the view key in
    /// ordinary memory for as long as it lives (T-MEM-COPIES). Keep it short-lived.
    #[must_use]
    pub fn view_pair(&self) -> ViewPair {
        let scalar = parse_scalar(self.view.expose()).unwrap_or_else(unreachable_scalar);
        ViewPair::new(self.spend_point(), scalar).unwrap_or_else(|_| unreachable_pair())
    }

    /// The primary address.
    #[must_use]
    pub fn primary_address(&self) -> MoneroAddress {
        self.view_pair()
            .legacy_address(self.network.address_network())
    }

    /// The address for `(account, index)`; `(0, 0)` is the primary address.
    #[must_use]
    pub fn address(&self, account: u32, index: u32) -> MoneroAddress {
        match SubaddressIndex::new(account, index) {
            None => self.primary_address(),
            Some(idx) => self
                .view_pair()
                .subaddress(self.network.address_network(), idx),
        }
    }
}

// Invariant violations: construction validated these values. Abort rather
// than continue with corrupt key material.
#[cold]
fn unreachable_point() -> Point {
    std::process::abort()
}
#[cold]
fn unreachable_scalar() -> Zeroizing<Scalar> {
    std::process::abort()
}
#[cold]
fn unreachable_pair() -> ViewPair {
    std::process::abort()
}
