# ZeroTrace Threat Model (STRIDE)

Version 0.1 (Stage 2). Living document: every stage updates the **Status**
column. Threat IDs are referenced from code and config.

Status legend: ✅ implemented and tested · 🟡 partially implemented · 🔜 planned
(stage noted) · ⚠️ accepted residual risk

---

## 1. System overview

```text
                 ONLINE MACHINE (Hyprland / Omarchy)                      ║   OFFLINE MACHINE
 ┌───────────────────────────────────────────────────────────────┐      ║  ┌───────────────────────────┐
 │  zerotrace (kage-tui)                                         │      ║  │ kage-signer               │
 │   ├─ kage-core  (view key + public spend key)                 │  file / animated QR    │  (seed, spend key)        │
 │   │    └─ vault: ViewWallet  ──────────────── TB-2 ───────────╫──────►│   └─ vault: SignerSecrets │
 │   └─ kage-node ── TB-3 ──► own node (loopback/LAN)            │◄─────╫──│  no network, mlockall,    │
 │                    └──────► Tor (arti) ──► remote node        │      ║  │  swap refused             │
 └───────────────────────────────────────────────────────────────┘      ║  └───────────────────────────┘
        TB-1: user ⇄ terminal (screen, keyboard, clipboard)              ║   TB-4: user ⇄ signer screen
        TB-5: process ⇄ OS (disk, swap, other processes)                 ║   TB-5 (signer host)
        TB-6: build & supply chain (crates.io, CI, release)              ║
```

### Assets (by severity)

| ID | Asset | Where | Impact if lost |
|---|---|---|---|
| A1 | Seed / spend key | signer only | **Theft of all funds** |
| A2 | Signer vault password | user / signer RAM | Leads to A1 if the vault file also leaks |
| A3 | Private view key | core (online) | Privacy loss: all incoming tx, amounts, balance |
| A4 | Wallet cache (tx history, subaddress labels, key images) | core vault | Privacy loss |
| A5 | Transaction intent (destination, amount) | core → signer | Funds misdirected if altered undetected |
| A6 | Network metadata (IP ⇄ wallet linkage, tx broadcast origin) | node link | Deanonymisation |
| A7 | Integrity of the released binaries | supply chain | Compromise of everything above |

### Adversaries

| ID | Adversary | Capabilities assumed |
|---|---|---|
| ADV-NET | Network observer / malicious remote node | Sees or answers node traffic; can lie about chain data |
| ADV-HOT | Malware on the online machine | Full control of the hot side as the user's UID (incl. reading the screen, altering files, the clipboard, crafting air-gap messages) |
| ADV-PHYS | Thief of a powered-off device or disk | Offline access to vault files and swap |
| ADV-SUPPLY | Supply-chain attacker | Publishes a malicious crate version, compromises a CI action |
| ADV-SHOULDER | Bystander / screen recorder | Sees the terminal |

**Out of scope:** malware running on the signer machine, and attacks on the
user's hardware or firmware. If the offline machine is compromised, A1 is lost.
ZeroTrace reduces the ways that can happen but cannot defend against it.

### Core security claim

> An attacker with full control of the online machine (ADV-HOT) **cannot steal
> funds**, provided the user checks the destination and amount shown **on the
> signer's screen** against an independent source before approving.

---

## 2. STRIDE by component

### 2.1 kage-signer (offline)

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-SIGN-NET | I, E | Signer exfiltrates keys over a network (malicious dependency or bug) | Layered isolation, ADR-012: allowlist, cargo-deny denylist, feature + source scans, clippy bans, CI self-test; runtime empty netns + seccomp | ✅ build-time · 🔜 runtime (S5) |
| T-SIGN-TAMPER | T | ADV-HOT alters the unsigned tx (destination, amount, fee) | Signer fully decodes and **shows every destination in full, amounts, fee, change verified as its own**; rejects anything undecodable (ADR-006) | 🔜 S4 |
| T-SIGN-CHANGE | T | Hot side marks an attacker's output as "change" to hide it | Signer recomputes ownership of change outputs from its own keys; counts unowned outputs as spent | 🔜 S4 |
| T-SIGN-PARSE | T, D, E | Malformed air-gap input exploits the parser | Strict envelope parser (exact length, bounded size, known values) ✅, fuzzed ✅. Payload decoders fuzzed in S4. No camera/image parsing by default (ADR-006) | 🟡 |
| T-SIGN-DIR | S | Hot side sends a signer→hot message kind to confuse the signer | Envelope `parse_for` enforces direction and network | ✅ |
| T-SIGN-NETMIX | S, T | Testnet/stagenet message accepted as another network | Network bound in envelope; mismatch rejected | ✅ |
| T-SIGN-INJECT | E | `LD_PRELOAD` / library injection into the signer | Static-pie musl release binaries (no dynamic loader) | ✅ |
| T-SIGN-REPLAY | T | Old unsigned tx replayed for a second signing | Signing spends specific outputs; double-spend prevented by consensus. Signer shows inputs being spent. Key-image-based "already signed" warning | 🔜 S4 |
| T-SIGN-SEED-UI | I | Seed displayed or captured (ADV-SHOULDER) | Seed shown only on the explicit seed-reveal screen with a warning; never logged | 🔜 S4 |
| T-SIGN-LOG | I | Secrets reach logs or stderr | No logging frameworks in secret-handling crates (CI policy) ✅. `Debug` of secret types is redacted ✅ | ✅ |

### 2.2 Memory and process (signer and online)

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-MEM-SWAP | I | Secrets paged to disk | Signer: `mlockall(CURRENT|FUTURE)`, fail-closed ✅. Online: `LockedBytes` (mlocked) for key material ✅ | ✅ |
| T-MEM-HIBERNATE | I | Hibernation writes locked RAM to swap | Signer refuses unless all swap is zram or dm-crypt (ADR-008) ✅; online warns ✅ | ✅ |
| T-MEM-DUMP | I | Core dump contains secrets | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `MADV_DONTDUMP` on secret pages | ✅ |
| T-MEM-PTRACE | I, E | Same-UID process reads memory (ptrace, `/proc/pid/mem`) | `PR_SET_DUMPABLE=0` (blocks non-`CAP_SYS_PTRACE` attach); Yama `ptrace_scope` recommended in INSTALL | ✅ / doc |
| T-MEM-FORK | I | Child process inherits secrets | `MADV_WIPEONFORK` on secret pages; no process spawning (clippy ban on `Command::new`) | ✅ |
| T-MEM-REMNANT | I | Secrets left in freed memory | `zeroize` on drop. `LockedBytes` pages are zeroized then unmapped (never returned to the allocator) | ✅ |
| T-MEM-COPIES | I | Temporary copies inside dependencies (stack, registers, `monero-wallet` internals) escape `LockedBytes` | Signer: `mlockall` covers swap. Remaining risk: transient copies in RAM | ⚠️ residual |
| T-MEM-OVERFLOW | T, E | Overflow out of a secret buffer | Guard pages (`PROT_NONE`) around every `LockedBytes`, data end-aligned to the trailing guard | ✅ |
| T-OS-SANDBOX | E | A parser bug in the TUI/node escalates to the whole user account | seccomp-bpf + Landlock (filesystem limited to the wallet dir) for the TUI and node | 🔜 S5 |
| T-OS-NNP | E | Privilege gain via setuid helpers | `PR_SET_NO_NEW_PRIVS` alongside seccomp | 🔜 S5 |

### 2.3 kage-vault (storage)

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-VAULT-BRUTE | I | Offline password guessing on a stolen vault (ADV-PHYS) | Argon2id, 256 MiB / t=4 default, floor 64 MiB / t=3 (ADR-004). Password-strength guidance in UI (S3) | ✅ / 🔜 |
| T-VAULT-TAMPER | T | Modified ciphertext, header or KDF params | XChaCha20-Poly1305 with the entire header as AAD. Property test: every single-bit flip is rejected | ✅ |
| T-VAULT-DOWNGRADE | T | Header rewritten to weak KDF params | Params below the floor are rejected before KDF; params are also authenticated | ✅ |
| T-VAULT-DOS | D | Hostile params/length exhaust memory | Bounds checked before KDF or allocation; `read_bounded` caps file size; fuzzed | ✅ |
| T-VAULT-CONFUSE | S, T | View-wallet file opened as signer secrets or vice versa | Content type in AAD and checked before the KDF | ✅ |
| T-VAULT-TORN | D | Crash mid-write corrupts the wallet | Atomic write: `O_EXCL` 0600 temp, fsync, rename, dir fsync | ✅ |
| T-VAULT-NONCE | I | Nonce reuse breaks the AEAD | Fresh 192-bit random nonce on every seal (XChaCha: collision-safe); tested | ✅ |
| T-VAULT-ROLLBACK | T | Replace the vault with an older valid version (e.g. resurrect a stale cache) | Not detectable by the file alone. Impact limited: the cache is rebuilt from the chain, and the signer vault has no mutable state | ⚠️ residual |
| T-VAULT-PERM | I | World-readable files | Created `0600`; the TUI warns on wider modes (S3) | ✅ / 🔜 |

### 2.4 kage-core (online, view-only)

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-CORE-VIEWKEY | I | ADV-HOT reads the view key | Inherent to an online view-only wallet. Locked memory narrows passive leaks. **Cannot spend** | ⚠️ residual (privacy only) |
| T-CORE-SPEND | E | Spend key ever reaches the online side | No code path accepts it. `SignerSecrets` vault rejected as `ViewWallet`. Signer never depends on core (and vice versa) | ✅ |
| T-CORE-DECOY | I | Non-reference decoy selection fingerprints our txs | Use monero-wallet's wallet2-identical selection; differential tests vs `monero-wallet-rpc` (ADR-001) | 🔜 S3 |
| T-CORE-BALANCE | T | Lying node or missing key images give a wrong balance (pre-FCMP++ view-only cannot see spends) | Key-image import from the signer; balance marked "unverified" until imported | 🔜 S3 |
| T-CORE-ADDR | T | ADV-HOT swaps the displayed receive address | Mandatory address re-display; the signer can independently display/verify a subaddress | 🔜 S3/S4 |
| T-CORE-PARSE | D, E | Malicious node data crashes or exploits the scanner | monero-oxide strict deserialisation; our wrappers fuzzed; sandbox (T-OS-SANDBOX) | 🔜 S3/S5 |

### 2.5 kage-node (network)

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-NODE-FALLBACK | S, I | Silent switch to an untrusted node | No automatic fallback; switching is an explicit user action (ADR-005) | ✅ policy · 🔜 S3 client |
| T-NODE-IPLEAK | I | IP linked to wallet or tx broadcast | Non-local hosts must use Tor. DNS only via Tor. Direct only to loopback/private | ✅ policy |
| T-NODE-LIE | T | Node lies about chain state, fees, decoy outputs | Own-node default. Sanity checks on fees/heights. Decoy data validated by monero-wallet. Remaining risk with untrusted nodes is shown in the UI | 🔜 S3 |
| T-NODE-DOS | D | Node floods or stalls | Timeouts and response size limits | 🔜 S3 |
| T-NODE-TLS | S | MITM on a clearnet LAN node | Loopback/LAN only, or Tor (onion services are end-to-end authenticated). rustls only; OpenSSL banned | ✅ policy |

### 2.6 kage-tui (user interface)

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-UI-CLIP | I, T | Clipboard read or hijacked | Clipboard auto-clear after 15 s. Destination re-display before signing; the signer screen is authoritative | 🔜 S3 |
| T-UI-SHOULDER | I | Secrets on screen | No secrets rendered except the seed-reveal screen; screen lock with idle timeout | 🔜 S3 |
| T-UI-TRUST | S | User unsure whether they are in view-only or signer-attached state | Colour-coded trust state in the status bar | 🔜 S3 |
| T-UI-THEME | T, D | Hostile theme TOML (Omarchy theme dir) exploits the parser | Strict, bounded TOML parsing of colours only; fuzzed | 🔜 S3 |
| T-UI-TERM | T | Escape-sequence injection via tx notes or labels | Sanitise control characters before rendering | 🔜 S3 |

### 2.7 Supply chain and build

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T-SUP-CRATE | T, E | Malicious or compromised crate version | Exact pins, committed lockfile with checksums, `--locked`. `cargo vet` (imports + exemptions as tracked debt). `cargo deny` sources (crates.io only). Daily `cargo audit` | ✅ |
| T-SUP-NEWDEP | T | A new transitive dependency slips into the signer | Signer allowlist: CI fails on any unlisted crate | ✅ |
| T-SUP-ACTION | T, E | Compromised GitHub Action | Every action pinned to a commit SHA. `contents: read` default. `persist-credentials: false` | ✅ |
| T-SUP-BUILD | T | Tampered release binary | Reproducible builds (verified bit-for-bit, CI-checked). Sigstore provenance. Offline minisign signature (ADR-015) | ✅ |
| T-SUP-ADVISORY | I, E | Known-vulnerable dependency | `cargo audit` + `cargo deny advisories` on every push and daily. One scoped accepted risk: RUSTSEC-2026-0387 (ADR-010) | ✅ / ⚠️ |
| T-SUP-SIGNKEY | S | Release signing key stolen from CI | Key never in CI; signing offline | ✅ |

---

## 3. Residual risks (accepted, tracked)

| Ref | Risk | Why accepted | Exit / review trigger |
|---|---|---|---|
| T-MEM-COPIES | Transient secret copies outside locked buffers | Not fully controllable in Rust. Signer `mlockall` covers swap | Review at the S5 hardening pass |
| T-VAULT-ROLLBACK | Vault rollback undetectable | Low impact (cache rebuildable, signer vault static) | If mutable signer state is ever added |
| T-CORE-VIEWKEY | View key on an online machine | Inherent to view-only design | Carrot view-balance key split (post-FCMP++) |
| ADR-010 | crypto-bigint timing variability | Public-input-only use | monero-oxide on crypto-bigint ≥ 0.7.6 |
| ADR-004 | `argon2` crate not formally audited | Safer than C FFI; KATs | An audited pure-Rust Argon2 becomes available |
| ADR-001 | monero-oxide `0.2.0` ≠ audited snapshot | Delta review pending, mainnet disabled | Delta review complete (required before mainnet) |
