use monero_wallet::ViewPair;
use monero_wallet::ed25519::{CompressedPoint, Scalar};
use zeroize::Zeroizing;

use crate::keys::{KeyError, ViewKeys};
use crate::state::{BackupStatus, WalletState};
use crate::{Network, codec};

// Ed25519 base point, used as a stand-in public spend key.
const G: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

fn view_key() -> [u8; 32] {
    let mut v = [0u8; 32];
    v[0] = 7;
    v
}

fn address_for(view: [u8; 32]) -> String {
    let spend = CompressedPoint::from(G).decompress().expect("G");
    let scalar = Scalar::read(&mut &view[..]).expect("scalar");
    ViewPair::new(spend, Zeroizing::new(scalar))
        .expect("pair")
        .legacy_address(Network::Stagenet.address_network())
        .to_string()
}

#[test]
fn view_keys_verify_address() {
    let addr = address_for(view_key());
    let mut vk = view_key();
    let keys =
        ViewKeys::from_address_and_view_key(Network::Stagenet, &addr, &mut vk).expect("keys");
    assert_eq!(vk, [0u8; 32], "input view key must be zeroized");
    assert_eq!(keys.primary_address().to_string(), addr);
    assert_ne!(keys.address(0, 1).to_string(), addr);
    assert!(
        !format!("{keys:?}").contains("07"),
        "Debug must not leak the key"
    );

    // Wrong view key for this address.
    let mut other = view_key();
    other[0] = 8;
    assert!(matches!(
        ViewKeys::from_address_and_view_key(Network::Stagenet, &addr, &mut other),
        Err(KeyError::Mismatch)
    ));
    // Wrong network.
    let mut vk = view_key();
    assert!(matches!(
        ViewKeys::from_address_and_view_key(Network::Testnet, &addr, &mut vk),
        Err(KeyError::Address(_))
    ));
    // Subaddress is not a wallet identity.
    let sub = keys.address(0, 1).to_string();
    let mut vk = view_key();
    assert!(matches!(
        ViewKeys::from_address_and_view_key(Network::Stagenet, &sub, &mut vk),
        Err(KeyError::NotPrimary)
    ));
    // Non-canonical scalar.
    let mut bad = [0xFFu8; 32];
    assert!(matches!(
        ViewKeys::from_address_and_view_key(Network::Stagenet, &addr, &mut bad),
        Err(KeyError::ViewKey)
    ));
}

#[test]
fn codec_round_trip_and_strictness() {
    let addr = address_for(view_key());
    let mut vk = view_key();
    let keys =
        ViewKeys::from_address_and_view_key(Network::Stagenet, &addr, &mut vk).expect("keys");
    let mut state = WalletState::new(Network::Stagenet, 1234);
    state.backup = BackupStatus::Attested;
    state.subaddresses.add_account("Savings");
    let bytes = codec::encode(&keys, &state);
    let (k2, s2) = codec::decode(&bytes).expect("decode");
    assert_eq!(s2, state);
    assert_eq!(k2.primary_address().to_string(), addr);

    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(
        codec::decode(&trailing).unwrap_err(),
        codec::CodecError::Trailing
    );
    for cut in [0, 4, 5, 37, 70, bytes.len() - 1] {
        assert!(codec::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn backup_gate() {
    let mut s = WalletState::new(Network::Stagenet, 0);
    assert!(!s.receive_allowed());
    s.backup = BackupStatus::Attested;
    assert!(s.receive_allowed());
}

#[test]
fn wallet_file_round_trip() {
    let dir = std::env::temp_dir().join(format!("zt-core-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("w.ztv");
    let _ = std::fs::remove_file(&path);
    let addr = address_for(view_key());
    let mut vk = view_key();
    let keys =
        ViewKeys::from_address_and_view_key(Network::Stagenet, &addr, &mut vk).expect("keys");
    let w = crate::wallet::ViewWallet::create(
        &path,
        b"pw",
        kage_vault::KdfParams::MINIMUM,
        keys,
        WalletState::new(Network::Stagenet, 5),
    )
    .expect("create");
    assert!(w.check_password(b"pw"));
    assert!(!w.check_password(b"nope"));
    let w2 = crate::wallet::ViewWallet::open(&path, b"pw").expect("open");
    assert_eq!(w2.state.restore_height, 5);
    assert!(crate::wallet::ViewWallet::open(&path, b"bad").is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
