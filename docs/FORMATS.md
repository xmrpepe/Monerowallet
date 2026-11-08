# On-disk and air-gap formats

All integers are little-endian. Parsers are strict: any deviation from this
specification is rejected, and nothing is "repaired". Both parsers are fuzzed
(`fuzz/fuzz_targets/`).

## 1. Vault file (`kage-vault`), format version 1

```text
offset  size  field
     0     8  magic            "ZTVAULT\0"
     8     2  version          u16 = 1
    10     2  content_type     u16: 1 = SignerSecrets, 2 = ViewWallet
    12     1  kdf_id           u8  = 1 (Argon2id, version 0x13)
    13     1  aead_id          u8  = 1 (XChaCha20-Poly1305)
    14     2  reserved         must be 0
    16     4  m_cost_kib       u32, 65 536 ..= 4 194 304   (64 MiB .. 4 GiB)
    20     4  t_cost           u32, 3 ..= 64
    24     4  p_cost           u32, 1 ..= 16
    28    32  salt             random, per vault (new salt = new password/key)
    60    24  nonce            random, fresh on EVERY write
    84     8  ciphertext_len   u64, <= 268 435 456 (256 MiB); must equal file_len - 92 - 16
    92     n  ciphertext
  92+n    16  Poly1305 tag
```

- `key = Argon2id(password, salt, m_cost, t_cost, p_cost, out = 32 bytes)`
- `ciphertext || tag = XChaCha20-Poly1305(key, nonce, aad = header[0..92], plaintext)`
- **Order of checks when opening:** length ≥ 108, then magic, version,
  content type (must match what the caller asked for), algorithm IDs, reserved
  bytes, KDF bounds, and exact length. Only then is the KDF run, then the
  AEAD is verified. Unauthenticated plaintext is zeroized and never returned.
- **Errors** do not distinguish "wrong password" from "tampered file".
- **Writes** are atomic (temp file with `O_EXCL`, mode `0600`, fsync, rename,
  directory fsync).
- **Defaults** for new vaults: `m = 256 MiB, t = 4, p = 1` (ADR-004).
- The plaintext layout is defined by the owning crate and carries its own
  version number (`kage-core`, Stage 3; `kage-signer`, Stage 4).

## 2. Air-gap envelope (`kage-airgap`), version 1

```text
offset  size  field
     0     4  magic         "ZTAG"
     4     1  version       u8 = 1
     5     1  kind          1 = UnsignedTx     (hot → signer)
                            2 = OutputsExport  (hot → signer)
                            3 = SignedTx       (signer → hot)
                            4 = KeyImages      (signer → hot)
     6     1  network       2 = testnet, 3 = stagenet   (1 = mainnet: REJECTED, ADR-002)
     7     1  reserved      must be 0
     8     4  payload_len   u32, <= 8 MiB; must equal input_len - 12
    12     n  payload       decoded strictly by the receiver (Stage 4)
```

- Receivers must call `Envelope::parse_for(bytes, side, network)`, which also
  enforces **direction** (the signer accepts only kinds 1–2, the hot wallet
  only 3–4) and **network**.
- There is no checksum or MAC, by design (ADR-006). Over QR, the envelope is
  carried in BC-UR, which has its own CRC32 and fountain-coded chunking
  (Stage 4).
