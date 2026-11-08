//! Air-gap payloads carried inside an [`Envelope`](crate::Envelope).
//! Spec: `docs/FORMATS.md` §3.
//!
//! Decoding is strict: version checked, every count and length bounded
//! *before* allocation, every field parsed with the network the receiver
//! expects, no trailing bytes. Anything that does not decode is rejected
//! (ADR-006). All decoders are fuzzed (`fuzz/fuzz_targets/airgap_payloads.rs`).
//!
//! **Why an intent and not a pre-built `SignableTransaction` (ADR-019):**
//! `monero-wallet` keeps a `SignableTransaction`'s payments private, so a
//! signer handed one could not show the user what it is about to sign. Instead
//! the hot wallet sends a [`TxIntent`]: inputs with their decoy rings, the
//! destinations and amounts, the change subaddress and the fee rate. The
//! signer displays those fields and then builds the transaction *itself* with
//! `SignableTransaction::new`. What the user approves is exactly what gets
//! signed.

use std::io::{self, Read as _};

use monero_wallet::OutputWithDecoys;
use monero_wallet::address::{MoneroAddress, SubaddressIndex};
use monero_wallet::ed25519::{CompressedPoint, Scalar};
use monero_wallet::interface::FeeRate;
use monero_wallet::ringct::RctType;
use zeroize::Zeroizing;

use crate::Network;

/// Payload format version (all payload kinds).
pub const PAYLOAD_VERSION: u8 = 1;
/// Maximum inputs in one intent.
pub const MAX_INPUTS: usize = 64;
/// Maximum payments (Bulletproofs+ allows 16 outputs; one is change).
pub const MAX_PAYMENTS: usize = 15;
/// Maximum serialized size of one input with its decoys.
pub const MAX_INPUT_LEN: usize = 16 * 1024;
/// Maximum address string length (integrated addresses are 106 chars).
pub const MAX_ADDRESS_LEN: usize = 128;
/// Maximum entries in an outputs export or key-image list.
pub const MAX_OUTPUT_ENTRIES: usize = 100_000;
/// Fee-rate sanity ceiling, in piconero per weight unit, checked on both
/// sides of the air gap so a lying node cannot inflate fees unnoticed
/// (T-NODE-LIE). The fee itself is always shown to the user as well.
///
/// Stagenet/testnet: 10 000 000, about 2.5x today's highest wallet2 priority
/// level (~4 000 000) on chains with tail-emission rewards. Regtest (test
/// only): its young chain has a huge block reward, so fees are ~100x higher.
#[must_use]
pub fn max_fee_per_weight(network: Network) -> u64 {
    match network {
        Network::Stagenet | Network::Testnet => 10_000_000,
        #[cfg(feature = "regtest")]
        Network::Regtest => 1_000_000_000,
    }
}

/// Payload decoding errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PayloadError {
    /// Input ended early.
    #[error("payload truncated")]
    Truncated,
    /// Bytes left after a complete payload.
    #[error("trailing bytes after payload")]
    Trailing,
    /// Unsupported payload version.
    #[error("unsupported payload version {0}")]
    Version(u8),
    /// A count or length is out of bounds.
    #[error("{0} out of bounds")]
    Bounds(&'static str),
    /// A field failed to parse.
    #[error("invalid {0}")]
    Invalid(&'static str),
}

/// A destination and amount, as entered by the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// Destination.
    pub address: MoneroAddress,
    /// Amount in piconero (> 0).
    pub amount: u64,
}

/// Everything the signer needs to build, show and sign a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIntent {
    /// Always `ClsagBulletproofPlus` (current consensus).
    pub rct_type: RctType,
    /// Fee rate from the node, bounded by [`max_fee_per_weight`].
    pub fee_rate: FeeRate,
    /// Inputs being spent, each with its decoy ring.
    pub inputs: Vec<OutputWithDecoys>,
    /// Destinations.
    pub payments: Vec<Payment>,
    /// Where change goes: `None` = the primary address (account 0, index 0),
    /// otherwise a subaddress. Always the signer's own wallet: the signer
    /// derives the change output from its own keys.
    pub change: Option<SubaddressIndex>,
}

/// One owned output, sent to the signer so it can compute the key image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportedOutput {
    /// The output's one-time public key.
    pub key: CompressedPoint,
    /// The scalar added to the spend key to spend this output.
    pub key_offset: Zeroizing<[u8; 32]>,
}

/// A key image computed by the signer for one output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyImageEntry {
    /// The output's one-time public key.
    pub output_key: [u8; 32],
    /// Its key image.
    pub key_image: [u8; 32],
}

// ---------------------------------------------------------------------------
// Encoding helpers

struct W(Vec<u8>);

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
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PayloadError> {
        let (h, t) = self.0.split_at_checked(n).ok_or(PayloadError::Truncated)?;
        self.0 = t;
        Ok(h)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], PayloadError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PayloadError::Truncated)
    }
    fn u8(&mut self) -> Result<u8, PayloadError> {
        self.arr::<1>().map(|[b]| b)
    }
    fn u16(&mut self) -> Result<u16, PayloadError> {
        self.arr::<2>().map(u16::from_le_bytes)
    }
    fn u32(&mut self) -> Result<u32, PayloadError> {
        self.arr::<4>().map(u32::from_le_bytes)
    }
    fn u64(&mut self) -> Result<u64, PayloadError> {
        self.arr::<8>().map(u64::from_le_bytes)
    }
    fn count(&mut self, max: usize, what: &'static str) -> Result<usize, PayloadError> {
        let n = usize::try_from(self.u32()?).map_err(|_| PayloadError::Bounds(what))?;
        if n > max {
            return Err(PayloadError::Bounds(what));
        }
        Ok(n)
    }
    fn version(&mut self) -> Result<(), PayloadError> {
        match self.u8()? {
            PAYLOAD_VERSION => Ok(()),
            v => Err(PayloadError::Version(v)),
        }
    }
    fn finish(&self) -> Result<(), PayloadError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(PayloadError::Trailing)
        }
    }
}

/// Reads a value with a `monero-wallet` reader and requires that it consumed
/// the slice exactly.
fn read_exact<T>(
    bytes: &[u8],
    what: &'static str,
    f: impl FnOnce(&mut &[u8]) -> io::Result<T>,
) -> Result<T, PayloadError> {
    let mut cur = bytes;
    let v = f(&mut cur).map_err(|_| PayloadError::Invalid(what))?;
    let mut rest = [0u8; 1];
    if cur
        .read(&mut rest)
        .map_err(|_| PayloadError::Invalid(what))?
        != 0
    {
        return Err(PayloadError::Invalid(what));
    }
    Ok(v)
}

fn len_u32(n: usize, what: &'static str) -> Result<u32, PayloadError> {
    u32::try_from(n).map_err(|_| PayloadError::Bounds(what))
}

// ---------------------------------------------------------------------------
// TxIntent

impl TxIntent {
    /// Checks every bound. Called by both `encode` and `decode`.
    ///
    /// # Errors
    /// The first violated bound.
    pub fn check(&self, network: Network) -> Result<(), PayloadError> {
        if self.rct_type != RctType::ClsagBulletproofPlus {
            return Err(PayloadError::Invalid("rct type"));
        }
        let fee = self.fee_rate.per_weight();
        if fee == 0 || fee > max_fee_per_weight(network) {
            return Err(PayloadError::Bounds("fee rate"));
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(PayloadError::Bounds("inputs"));
        }
        if self.payments.is_empty() || self.payments.len() > MAX_PAYMENTS {
            return Err(PayloadError::Bounds("payments"));
        }
        if self.payments.iter().any(|p| p.amount == 0) {
            return Err(PayloadError::Invalid("zero amount"));
        }
        Ok(())
    }

    /// Encodes the intent for `network`.
    ///
    /// # Errors
    /// Bounds violations, or a payment address from another network.
    pub fn encode(&self, network: Network) -> Result<Vec<u8>, PayloadError> {
        self.check(network)?;
        if self
            .payments
            .iter()
            .any(|p| p.address.network() != network.address_network())
        {
            return Err(PayloadError::Invalid("address network"));
        }
        let mut w = W(Vec::new());
        w.u8(PAYLOAD_VERSION);
        w.u8(u8::from(self.rct_type));
        w.bytes(&self.fee_rate.serialize());
        w.u32(len_u32(self.inputs.len(), "inputs")?);
        for input in &self.inputs {
            let b = input.serialize();
            if b.len() > MAX_INPUT_LEN {
                return Err(PayloadError::Bounds("input size"));
            }
            w.u32(len_u32(b.len(), "input size")?);
            w.bytes(&b);
        }
        w.u32(len_u32(self.payments.len(), "payments")?);
        for p in &self.payments {
            let a = p.address.to_string();
            let len = u16::try_from(a.len()).map_err(|_| PayloadError::Bounds("address"))?;
            if a.len() > MAX_ADDRESS_LEN {
                return Err(PayloadError::Bounds("address"));
            }
            w.u16(len);
            w.bytes(a.as_bytes());
            w.u64(p.amount);
        }
        match self.change {
            None => w.u8(0),
            Some(idx) => {
                w.u8(1);
                w.u32(idx.account());
                w.u32(idx.address());
            }
        }
        Ok(w.0)
    }

    /// Strictly decodes an intent; addresses must belong to `network`.
    ///
    /// # Errors
    /// Any format or bounds violation.
    pub fn decode(bytes: &[u8], network: Network) -> Result<Self, PayloadError> {
        let mut r = R(bytes);
        r.version()?;
        let rct_type =
            RctType::try_from(r.u8()?).map_err(|()| PayloadError::Invalid("rct type"))?;
        // FeeRate is two u64s (per_weight, mask) in monero-interface's encoding.
        let fee_rate = read_exact(r.take(16)?, "fee rate", |c| FeeRate::read(c))?;

        let n_in = r.count(MAX_INPUTS, "inputs")?;
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let len = r.count(MAX_INPUT_LEN, "input size")?;
            inputs.push(read_exact(r.take(len)?, "input", |c| {
                OutputWithDecoys::read(c)
            })?);
        }

        let n_pay = r.count(MAX_PAYMENTS, "payments")?;
        let mut payments = Vec::with_capacity(n_pay);
        for _ in 0..n_pay {
            let len = usize::from(r.u16()?);
            if len > MAX_ADDRESS_LEN {
                return Err(PayloadError::Bounds("address"));
            }
            let s =
                core::str::from_utf8(r.take(len)?).map_err(|_| PayloadError::Invalid("address"))?;
            let address = MoneroAddress::from_str(network.address_network(), s)
                .map_err(|_| PayloadError::Invalid("address"))?;
            let amount = r.u64()?;
            payments.push(Payment { address, amount });
        }

        let change = match r.u8()? {
            0 => None,
            1 => Some(
                SubaddressIndex::new(r.u32()?, r.u32()?)
                    .ok_or(PayloadError::Invalid("change subaddress"))?,
            ),
            _ => return Err(PayloadError::Invalid("change flag")),
        };
        r.finish()?;

        let intent = Self {
            rct_type,
            fee_rate,
            inputs,
            payments,
            change,
        };
        intent.check(network)?;
        Ok(intent)
    }
}

// ---------------------------------------------------------------------------
// Outputs export (hot → signer) and key images (signer → hot)

/// Encodes an outputs export.
///
/// # Errors
/// Too many entries.
pub fn encode_outputs(outputs: &[ExportedOutput]) -> Result<Vec<u8>, PayloadError> {
    if outputs.len() > MAX_OUTPUT_ENTRIES {
        return Err(PayloadError::Bounds("outputs"));
    }
    let mut w = W(Vec::with_capacity(
        outputs.len().saturating_mul(64).saturating_add(5),
    ));
    w.u8(PAYLOAD_VERSION);
    w.u32(len_u32(outputs.len(), "outputs")?);
    for o in outputs {
        w.bytes(&o.key.to_bytes());
        w.bytes(o.key_offset.as_ref());
    }
    Ok(w.0)
}

/// Strictly decodes an outputs export. Every key must be a valid point
/// encoding and every offset a canonical scalar.
///
/// # Errors
/// Any format violation.
pub fn decode_outputs(bytes: &[u8]) -> Result<Vec<ExportedOutput>, PayloadError> {
    let mut r = R(bytes);
    r.version()?;
    let n = r.count(MAX_OUTPUT_ENTRIES, "outputs")?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let key = CompressedPoint::from(r.arr::<32>()?);
        if key.decompress().is_none() {
            return Err(PayloadError::Invalid("output key"));
        }
        let offset = Zeroizing::new(r.arr::<32>()?);
        // Canonicality check only; the scalar itself is not kept here.
        read_exact(offset.as_ref(), "key offset", |c| Scalar::read(c))?;
        out.push(ExportedOutput {
            key,
            key_offset: offset,
        });
    }
    r.finish()?;
    Ok(out)
}

/// Encodes key images.
///
/// # Errors
/// Too many entries.
pub fn encode_key_images(entries: &[KeyImageEntry]) -> Result<Vec<u8>, PayloadError> {
    if entries.len() > MAX_OUTPUT_ENTRIES {
        return Err(PayloadError::Bounds("key images"));
    }
    let mut w = W(Vec::with_capacity(
        entries.len().saturating_mul(64).saturating_add(5),
    ));
    w.u8(PAYLOAD_VERSION);
    w.u32(len_u32(entries.len(), "key images")?);
    for e in entries {
        w.bytes(&e.output_key);
        w.bytes(&e.key_image);
    }
    Ok(w.0)
}

/// Strictly decodes key images. Each key image must be a valid,
/// torsion-free, non-identity point (as consensus requires).
///
/// # Errors
/// Any format violation.
pub fn decode_key_images(bytes: &[u8]) -> Result<Vec<KeyImageEntry>, PayloadError> {
    let mut r = R(bytes);
    r.version()?;
    let n = r.count(MAX_OUTPUT_ENTRIES, "key images")?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let output_key = r.arr::<32>()?;
        let key_image = r.arr::<32>()?;
        let valid = CompressedPoint::from(key_image)
            .decompress()
            .and_then(monero_wallet::ed25519::Point::key_image)
            .is_some();
        if !valid {
            return Err(PayloadError::Invalid("key image"));
        }
        out.push(KeyImageEntry {
            output_key,
            key_image,
        });
    }
    r.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Ed25519 base point: a valid, torsion-free, non-identity point.
    const G: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    #[test]
    fn key_images_round_trip_and_validate() {
        let e = vec![KeyImageEntry {
            output_key: G,
            key_image: G,
        }];
        let b = encode_key_images(&e).expect("encode");
        assert_eq!(decode_key_images(&b).expect("decode"), e);

        // Identity point (y = 1) is rejected as a key image.
        let mut ident = [0u8; 32];
        ident[0] = 1;
        let b = encode_key_images(&[KeyImageEntry {
            output_key: G,
            key_image: ident,
        }])
        .expect("encode");
        assert_eq!(
            decode_key_images(&b),
            Err(PayloadError::Invalid("key image"))
        );
    }

    #[test]
    fn outputs_round_trip_and_reject_noncanonical() {
        let mut one = [0u8; 32];
        one[0] = 1;
        let o = vec![ExportedOutput {
            key: CompressedPoint::from(G),
            key_offset: Zeroizing::new(one),
        }];
        let b = encode_outputs(&o).expect("encode");
        assert_eq!(decode_outputs(&b).expect("decode"), o);

        let bad = vec![ExportedOutput {
            key: CompressedPoint::from(G),
            key_offset: Zeroizing::new([0xFF; 32]), // >= group order
        }];
        let b = encode_outputs(&bad).expect("encode");
        assert_eq!(decode_outputs(&b), Err(PayloadError::Invalid("key offset")));
    }

    #[test]
    fn counts_bounded_before_allocation() {
        let mut b = vec![PAYLOAD_VERSION];
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_key_images(&b),
            Err(PayloadError::Bounds("key images"))
        );
        assert_eq!(decode_outputs(&b), Err(PayloadError::Bounds("outputs")));
        assert!(TxIntent::decode(&[PAYLOAD_VERSION, 6, 0], Network::Stagenet).is_err());
    }

    #[test]
    fn trailing_and_version() {
        let mut b = encode_key_images(&[]).expect("encode");
        b.push(0);
        assert_eq!(decode_key_images(&b), Err(PayloadError::Trailing));
        assert_eq!(
            decode_key_images(&[2, 0, 0, 0, 0]),
            Err(PayloadError::Version(2))
        );
    }
}
