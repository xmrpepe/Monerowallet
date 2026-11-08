# Audit index

Scope guide for third-party security review. Files are grouped by criticality.
Each entry states what the file is responsible for, so reviewers can check
that claim directly. Threat IDs refer to `docs/THREAT_MODEL.md` and ADRs to
`docs/DECISIONS.md`.

Current stage: **2 (skeleton + foundations)**. Protocol logic (Stage 3–4) is
not yet present. Its files will be added here as they land.

## Critical: memory safety and secret handling

| File | Responsibility | Threats / ADRs |
|---|---|---|
| `crates/kage-sys/src/locked.rs` | **The only `unsafe` in ZeroTrace.** Guard-paged, `mlock`ed, `MADV_DONTDUMP`/`MADV_WIPEONFORK` secret buffers; zeroize, unlock, unmap on drop | T-MEM-*, ADR-013 |
| `crates/kage-sys/src/lib.rs`, `crates/kage-sys/Cargo.toml` | Crate-level `deny(unsafe_code)`; clippy `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block` | ADR-013 |
| `crates/kage-harden/src/lib.rs` | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, signer `mlockall`, fail-closed | T-MEM-DUMP, T-MEM-PTRACE, T-MEM-SWAP |
| `crates/kage-harden/src/swap.rs` | `/proc/swaps` parsing; zram/dm-crypt classification; signer swap refusal | T-MEM-HIBERNATE, ADR-008 |

## Critical: storage cryptography

| File | Responsibility | Threats / ADRs |
|---|---|---|
| `crates/kage-vault/src/lib.rs` | Argon2id → XChaCha20-Poly1305 composition; AAD = full header; nonce freshness; zeroize on auth failure; key bound to salt, params and content type | T-VAULT-*, ADR-004 |
| `crates/kage-vault/src/format.rs` | Header layout, strict parser, KDF bounds (downgrade/DoS) | T-VAULT-DOWNGRADE, T-VAULT-DOS |
| `crates/kage-vault/src/atomic.rs` | Atomic `0600` writes, bounded reads | T-VAULT-TORN, T-VAULT-PERM |
| `docs/FORMATS.md` §1 | Normative format spec | |

## Critical: air gap and signer isolation

| File | Responsibility | Threats / ADRs |
|---|---|---|
| `crates/kage-airgap/src/lib.rs` | Envelope parser; direction and network enforcement; mainnet `compile_error!` gate | T-SIGN-PARSE, T-SIGN-DIR, T-SIGN-NETMIX, ADR-002 |
| `crates/kage-signer/src/lib.rs`, `src/bin/kage-signer.rs` | Signer entry: hardening before anything else | T-SIGN-* |
| `crates/kage-signer/Cargo.toml` | Signer's direct dependencies | ADR-012 |
| `crates/kage-signer/ALLOWED_DEPS` | **Allowlist** of every crate the signer may link, with justification | T-SIGN-NET, T-SUP-NEWDEP |
| `crates/kage-signer/deny.toml` | Networking denylist (cargo-deny) | T-SIGN-NET |
| `scripts/check-signer-deps.sh` | Allowlist, feature and source scans | T-SIGN-NET |
| `clippy.toml` | Workspace-wide socket-type ban; `std::mem::forget` and `Command::new` bans | T-SIGN-NET, T-MEM-FORK |

## High: network policy

| File | Responsibility | Threats / ADRs |
|---|---|---|
| `crates/kage-node/src/policy.rs` | Host parsing; Tor-only for non-local and remote hosts; onion validation | T-NODE-IPLEAK, T-NODE-FALLBACK, ADR-005 |

## High: supply chain and build

| File | Responsibility |
|---|---|
| `Cargo.toml` | Exact version pins; workspace lints (`unsafe_code = forbid`); release profile (overflow checks on, `panic = abort`) |
| `Cargo.lock` | Dependency checksums |
| `deny.toml`, `.cargo/audit.toml` | Advisory, license, source and ban policy; the single scoped advisory exception (ADR-010) |
| `supply-chain/` | `cargo vet` config, imports, audits; **exemptions = unreviewed debt** |
| `scripts/check-policy.sh` | Unsafe confinement, `forbid(unsafe_code)` on every crate root, RNG policy, no logging in secret crates, mainnet gate present |
| `scripts/build-release.sh`, `rust-toolchain.toml` | Reproducible static build |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml` | SHA-pinned actions; least-privilege tokens; runtime fail-closed tests; guard self-test |

## Fuzzing and tests

| File | Covers |
|---|---|
| `fuzz/fuzz_targets/vault_header.rs` | Vault header parser totality and round-trip |
| `fuzz/fuzz_targets/airgap_envelope.rs` | Envelope parser totality and round-trip; direction/network checks |
| `fuzz/fuzz_targets/node_host.rs` | Host parsing and policy validation |
| `crates/kage-vault/src/tests.rs` | Property tests: round-trip; **every single-bit flip rejected**; parser totality |

## How to check the main claims

```sh
./scripts/check-policy.sh                 # unsafe only in kage-sys/src/locked.rs, etc.
./scripts/check-signer-deps.sh            # signer graph allowlisted; no net features or socket APIs
cargo deny --config crates/kage-signer/deny.toml --manifest-path crates/kage-signer/Cargo.toml check bans
cargo deny check && cargo audit && cargo vet --locked
cargo test --workspace --locked
cargo check -p kage-airgap --features mainnet   # must FAIL (ADR-002)
./scripts/build-release.sh                # compare SHA256SUMS across machines
```

## Known open items for auditors

- monero-oxide `0.2.0` vs the audited snapshot: delta review not yet done (ADR-001).
- RUSTSEC-2026-0387 accepted risk analysis (ADR-010): please confirm that
  `crypto-bigint` is reachable only from `monero-ed25519::Point::biased_hash`.
- 89 `cargo vet` exemptions (`supply-chain/config.toml`).
