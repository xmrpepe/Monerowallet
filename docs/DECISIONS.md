# Architecture Decision Records

Each ADR records a security-relevant decision, the safer default chosen, and
what would make us revisit it. Code and config reference these IDs. Stage 1
questions Q1–Q5 (`docs/RESEARCH.md` §7) were resolved with the recommended
safer defaults (ADR-001, -002, -003, -004, -006).

Status values: **Accepted** (in force) · **Deferred** (deliberately not done yet)
· **Accepted-risk** (a known weakness we tolerate, with an exit criterion).

---

## ADR-001: Protocol library is monero-oxide; wallet2 is a test oracle only

**Status:** Accepted

**Decision:** Use `monero-wallet` / `monero-oxide` (pinned `=0.2.0` / `=0.1.0`)
for all Monero protocol logic. The official C++ wallet2 is **never linked**.
It runs only as a separate `monero-wallet-rpc` process on stagenet, as the
oracle for differential tests (decoy selection, fees, tx construction, seed
restore).

**Why:** pure Rust, so `forbid(unsafe_code)` is meaningful. Its dependency tree
was verified network-free, which makes the signer's isolation *checkable*.
Linking wallet2 would bring in a large C++ surface, including its own HTTP and
networking stack, that `cargo deny` cannot see.

**Obligations:**
- Delta review: the Cypher Stack audit (May 2025) covered Serai's
  `networks/monero` snapshot, not `0.2.0`. Before any mainnet enablement we
  review the diff from the audited commit to the pinned version and record it
  in `supply-chain/audits.toml`. Until then the monero crates are `cargo vet`
  **exemptions**, which marks them as unreviewed.
- Decoy selection and fee calculation are not explicitly in audit scope, so
  differential tests against `monero-wallet-rpc` are mandatory (Stage 3).
- `monero-wallet` is not a wallet (no state, no output selection). That code is
  ours, in `kage-core`, and is security-critical.

**Revisit if:** monero-oxide stalls on FCMP++, or a delta review finds problems
we cannot resolve upstream.

## ADR-002: Stagenet/testnet only; mainnet is compile-time disabled

**Status:** Accepted

**Decision:** `kage_airgap::Network` has no mainnet variant. The wire value for
mainnet is rejected. Enabling the `mainnet` feature is a `compile_error!`, and
CI asserts that it fails to compile.

**Why:** FCMP++/Carrot will replace CLSAG around March–April 2027 (non-binding
drafts). Released monero-oxide has no FCMP++/Carrot support. A CLSAG-only
mainnet wallet would put real funds behind new, unaudited wallet logic for a
few months.

**Exit criteria:** monero-oxide publishes FCMP++/Carrot support, our delta
review (ADR-001) is complete, and the Stage 3/4 differential tests pass on the
FCMP++ stressnet.

## ADR-003: Ledger support (`kage-hw`) is deferred

**Status:** Deferred

**Decision:** `kage-hw` is an empty crate that nothing depends on.

**Why:** no evidence of a Ledger Monero app with FCMP++/Carrot support. Writing
the host side of the current CLSAG protocol now would be new security-critical
protocol code that stops working at the fork.

**Revisit when:** Ledger publishes an FCMP++/Carrot-capable app. Then implement
and test against Speculos (monero PR #10421). If no Rust host implementation is
viable, a separate ADR must weigh a wallet2-based bridge isolated in `kage-hw`.

## ADR-004: Vault cryptography: Argon2id + XChaCha20-Poly1305 (RustCrypto)

**Status:** Accepted (relaxes "audited crates only" for `argon2`, see below)

**Decision:** Wallet files use the `kage-vault` format (`docs/FORMATS.md`):
Argon2id v1.3 → 32-byte key, then XChaCha20-Poly1305 with a fresh random
192-bit nonce per write, and the whole header as AAD. Default parameters are
256 MiB, t=4, p=1. The accepted floor is RFC 9106's second recommendation
(64 MiB, t=3). The ceiling (4 GiB, t=64, p=16) prevents memory-exhaustion DoS
from hostile files.

**Why RustCrypto `argon2`:** pure Rust, no `unsafe` in our code. The alternative
(libsodium via FFI) is audited, but it would put C code and FFI `unsafe` in the
storage path. To my knowledge `argon2` has no formal third-party audit. That is
the one place we relax the brief's rule. Mitigations: RFC 9106 known-answer
tests (added in Stage 3), conservative parameters, and composition only, with
no custom cryptography.

**Revisit if:** an audited pure-Rust Argon2 becomes available, or an advisory
affects `argon2`.

## ADR-005: Node connection policy

**Status:** Accepted

**Decision:** (implemented in `kage_node::policy`)
- The default is the user's own node.
- Direct (non-Tor) connections are allowed only to loopback, private and
  link-local addresses. **Even a user-owned node on a public IP must be reached
  over Tor.**
- Third-party ("remote") nodes always go over Tor via embedded arti.
- `.onion` hosts require Tor. DNS names are allowed only over Tor, so they are
  resolved at the exit and never by the local resolver.
- **No silent fallback.** If the node is unavailable, the wallet reports it and
  waits. Changing nodes is always an explicit user action.
- TLS, where used, is rustls. OpenSSL and native-tls are banned in `deny.toml`.

**Trade-off made toward safety:** a user with a VPS-hosted node must use Tor
or a VPN that presents it as a private address. This is documented in the UI
(Stage 3).

## ADR-006: Signer input channel and review rules

**Status:** Accepted

**Decision:**
- Default input to the signer is **file** (removable media). A camera-based QR
  reader is an optional feature, **off by default**, and sandboxed separately
  when enabled (Stage 4/5). Signer **output** via displayed animated QR is
  always available.
- Animated, chunked QR uses **BC-UR** (an existing standard), not a home-grown
  chunking scheme.
- The signer fully decodes every input, rejects anything it cannot decode,
  and before signing shows: every destination address in full, each amount,
  the change (verified by the signer to return to its own wallet), the fee, and
  the total leaving the wallet.
- The air-gap envelope has no checksum or MAC. The security model does not rely
  on transport integrity, because the user verifies on the signer's own screen.

**Why:** image decoding on the most sensitive machine is a large attack
surface. File input keeps parsing confined to our own fuzzed parsers.

## ADR-007: Linux only

**Status:** Accepted

**Decision:** `kage-sys` fails to compile on non-Linux, and supply-chain checks
target `x86_64`/`aarch64` Linux only. Hardening relies on Linux primitives
(`MADV_WIPEONFORK`, `PR_SET_DUMPABLE`, Landlock, seccomp, namespaces).

## ADR-008: Swap and hibernation policy

**Status:** Accepted

**Decision:** the signer locks all memory (`mlockall(MCL_CURRENT|MCL_FUTURE)`)
and **refuses to start** if any active swap is not provably safe. Safe means
zram (RAM-backed) or a dm-crypt device (`CRYPT-` UUID). Swap files whose
backing device cannot be resolved (e.g. btrfs) count as unsafe. Online
processes only warn, and keep the view key in per-allocation locked pages
(`kage_sys::LockedBytes`).

**Why:** `mlock` does not stop hibernation from writing RAM to swap. The signer
is meant for a dedicated, ideally live-booted, offline machine where turning
swap off costs nothing.

**Trade-off made toward safety:** some legitimate encrypted setups (btrfs swap
files on LUKS) are refused. The user runs `swapoff -a` before using the signer.

## ADR-009: Seed format

**Status:** Accepted (implementation in Stage 4)

**Decision:** standard 25-word Monero (Electrum-style) mnemonic, implemented
against the reference `electrum-words.cpp`. It is verified by differential
restore tests against `monero-wallet-rpc` and Monero's own test vectors. The
optional passphrase follows wallet2's "seed offset" semantics **exactly**, and
ships only once differential tests prove it matches. The verified-backup flow
is mandatory before the first receive address is shown.

## ADR-010: Accepted risk: RUSTSEC-2026-0387 (crypto-bigint 0.5.5)

**Status:** Accepted-risk

**Finding:** `crypto-bigint < 0.7.6` has timing variability in operations
meant to be constant-time. It is pulled in by `monero-ed25519 0.1.0`
(monero-oxide). The fix requires 0.7.6, which no monero-oxide release uses yet.

**Analysis:** in `monero-ed25519` the crate is used **only** in
`Point::biased_hash`, Monero's hash-to-point (`Hp`), an Elligator 2 map over
`Keccak256(bytes)`. Its input is a compressed **public** point (an output's
one-time key), so the variable-time operations process public data. Exploiting
it would need fine-grained timing measurements of the signer machine *while it
signs*. On an air-gapped signer that requires local code execution, which
already defeats every other protection. `kage-core` does not compute `Hp`
(key images come from the signer). **Stage 3 must re-verify this** once
scanning and unsigned-tx construction are wired in.

**Controls:** the ignore is scoped to this one ID in `deny.toml` and
`.cargo/audit.toml`. All other advisories still fail CI, and a daily scheduled
CI run catches new ones.

**Exit:** remove the ignore when monero-oxide releases on `crypto-bigint >=
0.7.6`. We will **not** patch curve code locally.

## ADR-011: Randomness

**Status:** Accepted

**Decision:** ZeroTrace code uses only the OS CSPRNG (`getrandom`, or
`OsRng` where a `CryptoRng` is required). `scripts/check-policy.sh` rejects
`thread_rng`, `StdRng`, `SmallRng`, `from_entropy`, `seed_from_u64`, etc. in our
sources.

**Note:** `monero-wallet` takes its RNG from the caller (we pass the OS CSPRNG).
It also derives transaction keys *deterministically* with a `ChaCha20Rng`
seeded by Keccak over the transaction transcript. That is deliberate protocol
design inside the audited library (it lets the outgoing view key recover tx
keys), not a general-purpose RNG, and we do not change it.

## ADR-012: Signer network isolation is layered and verified

**Status:** Accepted

**Controls:**
1. **Allowlist** (`crates/kage-signer/ALLOWED_DEPS`, `scripts/check-signer-deps.sh`):
   any crate not explicitly listed fails CI.
2. **Denylist** (`crates/kage-signer/deny.toml`, cargo-deny): async runtimes,
   sockets, HTTP, TLS, DNS, Tor, and our own `kage-node` / `kage-core` / `kage-tui`.
3. **Feature scan:** networking features (e.g. rustix `net`) must not be enabled.
4. **Source scan:** no socket APIs in any workspace crate the signer links.
5. **Lints:** `clippy.toml` `disallowed-types` bans socket types workspace-wide.
6. **CI self-test:** CI injects `kage-node` into the signer and asserts that
   both the allowlist and cargo-deny fail.
7. **Runtime (Stage 5):** the signer runs in an empty network namespace with
   seccomp denying `socket(2)` for `AF_INET`/`AF_INET6`/`AF_UNIX`/`AF_NETLINK`.

**Why layered:** `libc` and `linux-raw-sys` (needed for memory locking) declare
socket functions, so a dependency check alone cannot prove that no socket is
ever opened. Only the runtime confinement in layer 7 can.

## ADR-013: Workspace shape: one `unsafe` island, three shared network-free crates

**Status:** Accepted

**Decision:** in addition to the five crates in the brief:
- `kage-sys` is the **only** crate permitted `unsafe`: page-locked,
  guard-paged, `MADV_DONTDUMP`/`MADV_WIPEONFORK` secret buffers via `rustix`.
  It is about 150 lines, every `unsafe` block carries a `SAFETY:` comment, and
  clippy denies undocumented or multi-op unsafe blocks. CI proves `unsafe`
  appears nowhere else.
- `kage-harden`: process hardening, shared by every binary.
- `kage-vault`: encrypted storage, shared by signer and core.
- `kage-airgap`: the envelope format, the only protocol the two sides share.

The signer never depends on `kage-core`, and vice versa. They share only
`kage-airgap`, `kage-vault`, `kage-harden` and `kage-sys`, all network-free.

## ADR-014: Dependencies pinned and locked; vendoring at release time

**Status:** Accepted

**Decision:** every external dependency is pinned with `=x.y.z`. `Cargo.lock`
is committed, and every CI and release build uses `--locked`. The lockfile pins
a SHA-256 checksum for every crate, which gives the same **integrity**
guarantee as vendoring. Vendored sources are produced at release time for the
source tarball (offline rebuilds) rather than committed (hundreds of MB once
arti lands). `cargo vet` tracks review state, `cargo deny` bans unknown
registries and git sources, and `cargo audit` runs on every push plus daily.

## ADR-015: Releases: reproducible, provenance-attested, signed offline

**Status:** Accepted

**Decision:** `scripts/build-release.sh` produces static-pie musl binaries
reproducibly. This was verified bit-for-bit across build directories. CI does
the same on every push. Release CI publishes a **draft** with `SHA256SUMS` and a
Sigstore build-provenance attestation. The maintainer independently rebuilds,
compares checksums, and signs `SHA256SUMS` with **minisign offline**. The
signing key never enters CI. Static linking also removes the dynamic loader, so
`LD_PRELOAD` and `LD_LIBRARY_PATH` injection does not apply.
