//! # kage-airgap: envelope format for the air gap
//!
//! **Security-critical. Listed in `AUDIT.md`. Format spec: `docs/FORMATS.md`.**
//!
//! Everything that crosses the air gap, by file or by animated QR (BC-UR,
//! Stage 4), is wrapped in an [`Envelope`]: a fixed 12-byte header followed by
//! an opaque payload. This crate parses the envelope **strictly**: exact
//! length, known version/kind/network, zero reserved byte, bounded size. It
//! also enforces **direction**, so the signer cannot be fed a message kind
//! that only flows from signer to hot wallet.
//!
//! There is deliberately **no checksum or MAC** here. The signer's safety
//! never depends on transport integrity: it fully decodes the payload,
//! rejects anything it cannot decode, and shows the user every amount,
//! destination and the fee for confirmation (ADR-006). Transport corruption
//! is caught by BC-UR's CRC and by strict payload decoding.

#![forbid(unsafe_code)]

#[cfg(feature = "mainnet")]
compile_error!(
    "Mainnet is disabled until FCMP++/Carrot support is released in monero-oxide and \
     reviewed. See docs/DECISIONS.md, ADR-002."
);

/// Magic bytes.
pub const MAGIC: [u8; 4] = *b"ZTAG";
/// Envelope format version.
pub const VERSION: u8 = 1;
/// Header length.
pub const HEADER_LEN: usize = 12;
/// Maximum payload length (8 MiB). Bounds memory use on the signer.
pub const MAX_PAYLOAD_LEN: usize = 8 * 1024 * 1024;

/// Wire value reserved for mainnet; rejected by this build (ADR-002).
const NET_MAINNET: u8 = 1;

/// Monero network. Mainnet does not exist in this build (ADR-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Testnet.
    Testnet,
    /// Stagenet (default for development and integration tests).
    Stagenet,
}

impl Network {
    fn to_u8(self) -> u8 {
        match self {
            Self::Testnet => 2,
            Self::Stagenet => 3,
        }
    }
    fn from_u8(v: u8) -> Result<Self, EnvelopeError> {
        match v {
            2 => Ok(Self::Testnet),
            3 => Ok(Self::Stagenet),
            NET_MAINNET => Err(EnvelopeError::MainnetDisabled),
            other => Err(EnvelopeError::UnknownNetwork(other)),
        }
    }
}

/// Message kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Hot → signer: an unsigned transaction to review and sign.
    UnsignedTx,
    /// Hot → signer: owned outputs, so the signer can compute key images.
    OutputsExport,
    /// Signer → hot: a signed transaction, ready to broadcast.
    SignedTx,
    /// Signer → hot: key images, so the view-only wallet can detect spends.
    KeyImages,
}

impl Kind {
    fn to_u8(self) -> u8 {
        match self {
            Self::UnsignedTx => 1,
            Self::OutputsExport => 2,
            Self::SignedTx => 3,
            Self::KeyImages => 4,
        }
    }
    fn from_u8(v: u8) -> Result<Self, EnvelopeError> {
        match v {
            1 => Ok(Self::UnsignedTx),
            2 => Ok(Self::OutputsExport),
            3 => Ok(Self::SignedTx),
            4 => Ok(Self::KeyImages),
            other => Err(EnvelopeError::UnknownKind(other)),
        }
    }

    /// Which side is allowed to **receive** this kind.
    #[must_use]
    pub fn receiver(self) -> Side {
        match self {
            Self::UnsignedTx | Self::OutputsExport => Side::Signer,
            Self::SignedTx | Self::KeyImages => Side::Hot,
        }
    }
}

/// A side of the air gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The online, view-only wallet (`kage-core` / `kage-tui`).
    Hot,
    /// The offline signer (`kage-signer`).
    Signer,
}

/// Envelope errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Shorter than the header.
    #[error("envelope truncated")]
    Truncated,
    /// Wrong magic.
    #[error("not a ZeroTrace air-gap envelope")]
    BadMagic,
    /// Unsupported version.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    /// Unknown message kind.
    #[error("unknown message kind {0}")]
    UnknownKind(u8),
    /// Unknown network.
    #[error("unknown network {0}")]
    UnknownNetwork(u8),
    /// Mainnet message received by a build where mainnet is disabled.
    #[error("mainnet is disabled in this build (ADR-002)")]
    MainnetDisabled,
    /// Message is for a different network than this wallet.
    #[error("network mismatch: expected {expected:?}, got {got:?}")]
    WrongNetwork {
        /// Configured network.
        expected: Network,
        /// Network in the envelope.
        got: Network,
    },
    /// Message kind is not accepted by this side.
    #[error("{kind:?} messages are not accepted by the {side:?} side")]
    WrongDirection {
        /// The kind received.
        kind: Kind,
        /// The side that received it.
        side: Side,
    },
    /// Reserved byte non-zero.
    #[error("reserved field is non-zero")]
    Reserved,
    /// Payload too large.
    #[error("payload too large")]
    TooLarge,
    /// Length field does not match input length.
    #[error("length field does not match input")]
    LengthMismatch,
}

/// A parsed envelope borrowing its payload from the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    /// Message kind.
    pub kind: Kind,
    /// Network.
    pub network: Network,
    /// Opaque payload (decoded by the receiving side, strictly).
    pub payload: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Serialises the envelope.
    ///
    /// # Errors
    /// [`EnvelopeError::TooLarge`] if the payload exceeds [`MAX_PAYLOAD_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::TooLarge);
        }
        let len = u32::try_from(self.payload.len()).map_err(|_| EnvelopeError::TooLarge)?;
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(self.payload.len()));
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&[VERSION, self.kind.to_u8(), self.network.to_u8(), 0]);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(self.payload);
        Ok(out)
    }

    /// Strictly parses an envelope. Total on arbitrary input (fuzzed:
    /// `fuzz/fuzz_targets/airgap_envelope.rs`).
    ///
    /// # Errors
    /// Any format violation.
    pub fn parse(input: &'a [u8]) -> Result<Self, EnvelopeError> {
        let (header, payload) = input
            .split_at_checked(HEADER_LEN)
            .ok_or(EnvelopeError::Truncated)?;
        let [
            m0,
            m1,
            m2,
            m3,
            version,
            kind,
            network,
            reserved,
            l0,
            l1,
            l2,
            l3,
        ] = <[u8; HEADER_LEN]>::try_from(header).map_err(|_| EnvelopeError::Truncated)?;
        if [m0, m1, m2, m3] != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let kind = Kind::from_u8(kind)?;
        let network = Network::from_u8(network)?;
        if reserved != 0 {
            return Err(EnvelopeError::Reserved);
        }
        let len = usize::try_from(u32::from_le_bytes([l0, l1, l2, l3]))
            .map_err(|_| EnvelopeError::TooLarge)?;
        if len > MAX_PAYLOAD_LEN {
            return Err(EnvelopeError::TooLarge);
        }
        if payload.len() != len {
            return Err(EnvelopeError::LengthMismatch);
        }
        Ok(Self {
            kind,
            network,
            payload,
        })
    }

    /// Parses and checks that `side` may receive this message on `network`.
    /// Receivers must use this rather than [`Envelope::parse`].
    ///
    /// # Errors
    /// Format violation, wrong network or wrong direction.
    pub fn parse_for(input: &'a [u8], side: Side, network: Network) -> Result<Self, EnvelopeError> {
        let env = Self::parse(input)?;
        if env.network != network {
            return Err(EnvelopeError::WrongNetwork {
                expected: network,
                got: env.network,
            });
        }
        if env.kind.receiver() != side {
            return Err(EnvelopeError::WrongDirection {
                kind: env.kind,
                side,
            });
        }
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn env(kind: Kind) -> Vec<u8> {
        Envelope {
            kind,
            network: Network::Stagenet,
            payload: b"payload",
        }
        .encode()
        .expect("encode")
    }

    #[test]
    fn round_trip() {
        let bytes = env(Kind::UnsignedTx);
        let e = Envelope::parse_for(&bytes, Side::Signer, Network::Stagenet).expect("parse");
        assert_eq!(e.kind, Kind::UnsignedTx);
        assert_eq!(e.payload, b"payload");
    }

    #[test]
    fn signer_rejects_hot_bound_kinds() {
        for k in [Kind::SignedTx, Kind::KeyImages] {
            let bytes = env(k);
            assert!(matches!(
                Envelope::parse_for(&bytes, Side::Signer, Network::Stagenet),
                Err(EnvelopeError::WrongDirection { .. })
            ));
        }
    }

    #[test]
    fn mainnet_rejected() {
        let mut bytes = env(Kind::UnsignedTx);
        bytes[6] = NET_MAINNET;
        assert_eq!(Envelope::parse(&bytes), Err(EnvelopeError::MainnetDisabled));
    }

    #[test]
    fn network_mismatch_rejected() {
        let bytes = env(Kind::UnsignedTx);
        assert!(matches!(
            Envelope::parse_for(&bytes, Side::Signer, Network::Testnet),
            Err(EnvelopeError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn trailing_and_truncated_rejected() {
        let mut bytes = env(Kind::UnsignedTx);
        bytes.push(0);
        assert_eq!(Envelope::parse(&bytes), Err(EnvelopeError::LengthMismatch));
        bytes.truncate(bytes.len() - 2);
        assert_eq!(Envelope::parse(&bytes), Err(EnvelopeError::LengthMismatch));
        assert_eq!(Envelope::parse(&bytes[..5]), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn oversized_length_rejected_without_allocation() {
        let mut bytes = env(Kind::UnsignedTx);
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Envelope::parse(&bytes), Err(EnvelopeError::TooLarge));
    }

    proptest! {
        #[test]
        fn prop_parse_total(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Envelope::parse(&bytes);
        }

        #[test]
        fn prop_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..1024), k in 1u8..=4, testnet: bool) {
            let kind = Kind::from_u8(k).expect("kind");
            let network = if testnet { Network::Testnet } else { Network::Stagenet };
            let bytes = Envelope { kind, network, payload: &payload }.encode().expect("encode");
            let e = Envelope::parse_for(&bytes, kind.receiver(), network).expect("parse");
            prop_assert_eq!(e.payload, payload.as_slice());
        }
    }
}
