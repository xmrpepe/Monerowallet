#![allow(clippy::arithmetic_side_effects)]

use std::sync::OnceLock;

use proptest::prelude::*;

use super::*;

const PW: &[u8] = b"correct horse battery staple";

/// One real Argon2id derivation (minimum params), shared by property tests.
fn shared_key() -> &'static VaultKey {
    static KEY: OnceLock<VaultKey> = OnceLock::new();
    KEY.get_or_init(|| {
        VaultKey::derive_new(PW, KdfParams::MINIMUM, ContentType::ViewWallet).expect("derive")
    })
}

#[test]
fn layout_is_exact() {
    let h = Header {
        version: VERSION,
        content: ContentType::SignerSecrets,
        params: KdfParams::DEFAULT,
        salt: [7; SALT_LEN],
        nonce: [9; NONCE_LEN],
        ciphertext_len: 0,
    };
    let b = h.to_bytes();
    assert_eq!(&b[..8], b"ZTVAULT\0");
    assert_eq!(&b[84..92], &0u64.to_le_bytes());
    let mut file = b.to_vec();
    file.extend_from_slice(&[0u8; TAG_LEN]);
    assert_eq!(parse_header(&file).expect("parse"), h);
}

#[test]
fn password_round_trip_locked() {
    let key =
        VaultKey::derive_new(PW, KdfParams::MINIMUM, ContentType::SignerSecrets).expect("derive");
    let file = seal(&key, b"seed material").expect("seal");
    let (key2, pt) = open_locked(PW, ContentType::SignerSecrets, &file).expect("open");
    assert_eq!(pt.expose(), b"seed material");
    assert_eq!(key2.params(), KdfParams::MINIMUM);
    // Re-seal with the returned key, open again.
    let file2 = seal(&key2, b"v2").expect("seal");
    assert_ne!(file[60..84], file2[60..84], "nonce must be fresh per write");
    assert_eq!(
        open_locked_with_key(&key2, &file2).expect("open").expose(),
        b"v2"
    );
}

#[test]
fn wrong_password_fails_authentication() {
    let file = seal(shared_key(), b"x").expect("seal");
    let err = open(b"wrong", ContentType::ViewWallet, &file).unwrap_err();
    assert!(matches!(err, VaultError::Authentication), "{err:?}");
}

#[test]
fn content_type_checked_before_kdf() {
    let file = seal(shared_key(), b"x").expect("seal");
    let err = open(PW, ContentType::SignerSecrets, &file).unwrap_err();
    assert!(
        matches!(err, VaultError::WrongContentType { .. }),
        "{err:?}"
    );
}

#[test]
fn hostile_kdf_params_rejected_before_kdf() {
    let mut file = seal(shared_key(), b"x").expect("seal");
    // m_cost = u32::MAX KiB: must be refused without allocating.
    file[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        parse_header(&file).unwrap_err(),
        VaultError::KdfParamsOutOfBounds("memory")
    ));
    // Downgrade below the floor.
    let mut file = seal(shared_key(), b"x").expect("seal");
    file[20..24].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        parse_header(&file).unwrap_err(),
        VaultError::KdfParamsOutOfBounds("iterations")
    ));
}

#[test]
fn length_must_match_exactly() {
    let mut file = seal(shared_key(), b"abc").expect("seal");
    file.push(0);
    assert!(matches!(
        parse_header(&file).unwrap_err(),
        VaultError::LengthMismatch
    ));
    file.truncate(file.len() - 2);
    assert!(matches!(
        parse_header(&file).unwrap_err(),
        VaultError::LengthMismatch
    ));
}

#[test]
fn empty_password_rejected() {
    let err = VaultKey::derive_new(b"", KdfParams::MINIMUM, ContentType::ViewWallet).unwrap_err();
    assert!(matches!(err, VaultError::EmptyPassword));
}

#[test]
fn key_from_other_file_rejected() {
    let other =
        VaultKey::derive_new(PW, KdfParams::MINIMUM, ContentType::ViewWallet).expect("derive");
    let file = seal(shared_key(), b"x").expect("seal");
    assert!(matches!(
        open_with_key(&other, &file).unwrap_err(),
        VaultError::KeyMismatch
    ));
}

#[test]
fn key_debug_is_redacted() {
    let s = format!("{:?}", shared_key());
    assert!(s.contains("REDACTED"));
    assert!(!s.contains("salt"));
}

#[test]
fn atomic_write_and_bounded_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wallet.ztv");
    write_atomic(&path, b"first").expect("write");
    write_atomic(&path, b"second").expect("overwrite");
    assert_eq!(read_bounded(&path).expect("read"), b"second");
    let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("readdir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_round_trip(pt in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let file = seal(shared_key(), &pt).expect("seal");
        prop_assert_eq!(file.len(), HEADER_LEN + pt.len() + TAG_LEN);
        let got = open_with_key(shared_key(), &file).expect("open");
        prop_assert_eq!(got.as_slice(), pt.as_slice());
    }

    /// Tamper detection: flipping any single bit anywhere in the file must
    /// make it fail to open (header bound via AAD, body/tag via Poly1305).
    #[test]
    fn prop_any_bit_flip_rejected(
        pt in proptest::collection::vec(any::<u8>(), 1..256),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let mut file = seal(shared_key(), &pt).expect("seal");
        let i = pos.index(file.len());
        file[i] ^= 1 << bit;
        prop_assert!(open_with_key(shared_key(), &file).is_err());
    }

    /// The header parser never panics on arbitrary input.
    #[test]
    fn prop_parse_header_total(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_header(&bytes);
    }
}
