# ZeroTrace — Stage 1 Research Report

Status: **accepted**. Research date: 2026-11-08.
The §7 questions were resolved with the recommended defaults. See
`docs/DECISIONS.md` (ADR-001 to ADR-004 and ADR-006).

Evidence labels used below:
- **[verified]**: I checked it myself (crates.io API, `cargo tree`, primary repo/docs).
- **[reported]**: from a primary or secondary source I read but could not check further.
- **[unverified]**: my understanding, still to be checked in Stage 2 before any code depends on it.

---

## 1. Summary

1. **FCMP++ is not live on mainnet.** It is on a public stressnet. Non-binding
   drafts put activation in roughly **March–April 2027**. When it activates,
   ring signatures (CLSAG) and **decoy selection go away entirely**. The Carrot
   addressing scheme and a new transaction proof format replace them. A wallet
   that only does CLSAG has a mainnet shelf life of about 4–6 months from today.
2. **Recommended protocol library: `monero-oxide` (`monero-wallet` crate)**,
   pinned and vendored. The **official wallet2 (`monero-wallet-rpc`) is used only
   as a differential-test oracle on stagenet and is never linked** into any
   ZeroTrace binary.
3. **monero-oxide's audit covers an earlier snapshot, not the current release.**
   The Cypher Stack audit (May 2025) covered Serai's `networks/monero`, the
   code monero-oxide came from. The published crates (`monero-wallet 0.2.0`,
   July 2026) are pre-1.0 and have changed since. We have to review that
   difference ourselves.
4. **monero-oxide has no released FCMP++/Carrot support.** That work is on an
   unreleased `fcmp++` branch. The Rust Carrot crate (`carrot-rs`) has only
   been *proposed* for merging (Sept 2026).
5. **Ledger and FCMP++:** I found no evidence that Ledger's Monero app supports
   Carrot or FCMP++. Monero's draft timeline puts hardware wallet support in a
   later release (around Dec 2026). I recommend **deferring `kage-hw`** (see §7).
6. **Proposed consequence:** build Stages 2–4 on **stagenet only**, with the
   key hierarchy and transaction types designed to accommodate Carrot. Mainnet
   is a compile-time-disabled feature until monero-oxide ships FCMP++/Carrot
   and it has been reviewed.

---

## 2. Network status: FCMP++ / Carrot

| Item | Status | Label |
|---|---|---|
| Mainnet activation | Not activated; no binding date. getmonero.org had not announced a fork-enabled release as of 2026-10-23. | [reported] |
| Draft timeline (non-binding) | Fork-enabled release Oct 14–21 2026. Fully featured release with **hardware wallet + multisig** in early Dec 2026. Activation around the first week of March 2027. | [reported] |
| jeffro256 work-breakdown planner | Activation "week 17 of 2027" (non-binding). | [reported] |
| Stressnet | `v0.19.0.0-beta.3.0` released 2026-09-25. Stressnet fork at block 3102800 on 2026-10-05. | [reported] |
| Consensus integration | monero PR #11440, described as the final PR of Phase 3 of the FCMP++ integration audit (audit still pending). | [reported] |
| Reference hot/cold wallet | `seraphis-migration/monero` PR #52: full hot/cold implementation for Carrot/FCMP++. | [reported] |
| Wallet RPC | PR #10819 moves `monero-wallet-rpc` from `wallet2` onto the Wallet API. | [reported] |

Several blog posts (xgram.io, changee.com, secureshift.io) say FCMP++ is already
on mainnet. They contradict each other and every primary source, so I have
**discarded** them. I could not find any news dated after 2026-10-23. The
fork-enabled release may have shipped since then; please tell me if you know.

### What FCMP++/Carrot changes for our design

- **No decoys after the fork.** The membership proof covers the whole chain.
  The requirement "decoy selection must match the reference wallet exactly"
  applies **only to pre-fork CLSAG transactions**. We still meet it for
  stagenet and pre-fork use, with differential tests.
- **New key hierarchy (Carrot).** [unverified, check against the Carrot spec
  in Stage 2] Carrot splits spend authority into separate keys:
  prove-spend, generate-image, view-incoming, and view-balance. For
  **Carrot-native** accounts, a wallet holding only the view-balance and
  generate-image keys can detect outgoing spends and compute key images
  without being able to spend. That fits `kage-core` very well. For
  **legacy (25-word seed) accounts**, my understanding is that the key-image
  key *is* the legacy spend key. Legacy wallets would then keep today's
  cold-wallet flow: export outputs → signer computes key images → import into
  the view-only wallet.
- **Today's (pre-fork) view-only limitation:** a wallet with only the view key
  sees incoming funds but **not spends**, so its balance can be too high.
  `kage-signer` must therefore also support **key-image export**, not only
  signing. Stage 3 adds this to the air-gap protocol.

---

## 3. Library options

### Option A — `monero-oxide` (Rust) ✅ recommended

| Property | Finding | Label |
|---|---|---|
| Provenance | Successor to `monero-serai`. Moved to the neutral `monero-oxide` org (announced 2025-09-09), led by boog900 (Cuprate) and kayabaNerve (Serai). | [reported] |
| Audit | Cypher Stack. Repo README: "Audit of Serai's `/networks/monero`, which became the `monero-oxide` folder … PDF yielded in May 2025, PDF published in August, 2025". The CCS funding milestone was completed 2025-09-18. | [verified: repo] |
| Audit scope (CCS) | **monero-serai:** v1/v2 txs; ring sig/MLSAG/CLSAG *verification*; Borromean/BP/BP+ *verification*. **monero-wallet:** CLSAG/BP/BP+ *proving*, outgoing view keys, FROST-inspired multisig. Decoy selection, fee algorithm and TX extra are said to be "checked to match" Monero, but are **not explicitly listed as audit items**. Scanning and RPC are **not mentioned**. | [reported] |
| Multisig proof | FROSTLASS proven secure by Cypher Stack. Not needed by us. | [reported] |
| Bug bounty | $100k XMR (Power Up Privacy). | [reported] |
| Current release | `monero-oxide 0.1.0`, `monero-wallet 0.2.0` (2026-07-31). **Pre-1.0**; the API is not stable yet. | [verified: crates.io] |
| Functionality | Scanning, sending, CLSAG only. Docs: "Create on-chain transactions identical to how wallet2 would (unless told not to)". Explicitly **not** a wallet: no state and no output selection, so those are ours to build. | [verified: docs.rs] |
| FCMP++ / Carrot | Not in any release. On the unreleased `fcmp++` branch. `monero-fcmp-plus-plus` on crates.io is a stale 0.0.1 (Dec 2024). `carrot-rs` merge proposed in issue #204 (2026-09-22) with no maintainer reply. | [verified: crates.io; reported: issue] |
| Dependency tree | `monero-wallet 0.2.0` (default features) has 129 lines in `cargo tree`. **No tokio/hyper/mio/sockets/TLS/HTTP.** The RPC is a trait (`monero-interface`); the HTTP client is a separate crate (`monero-simple-request-rpc`). Pins `curve25519-dalek 4.1.3`, `rand 0.8`, `getrandom 0.2`, `zeroize 1.9`. | [verified: `cargo tree`] |
| Unsafe / FFI | Pure Rust. Our `#![forbid(unsafe_code)]` holds in our own crates, with no C++ in the binary. | [verified: tree] |

**Gaps we have to cover ourselves:**
1. Review the difference between the audited Serai snapshot and the pinned
   `0.2.0` (Stage 2 supply-chain task; results recorded in `supply-chain/`
   via `cargo vet`).
2. Decoy selection and fee calculation are not explicitly in audit scope.
   Differential tests against `monero-wallet-rpc` on stagenet are mandatory,
   not optional.
3. Output selection, wallet state and subaddress bookkeeping are new code in
   `kage-core`. That is wallet logic, not cryptography, but it is
   security-relevant.
4. Seed handling is **not** in monero-oxide. The only 25-word seed crate,
   `monero-seed 0.0.1`, lives in `kayabaNerve/monero-wallet-util`, is outside
   the audit, and dates from 2024-12. See §5.

### Option B — official wallet2 / Wallet API via FFI ❌ test oracle only

| Property | Finding |
|---|---|
| Correctness | It *is* the reference, so decoy selection matches by definition. FCMP++/Carrot (PR #52) and Ledger support arrive here first. |
| Precedent | `monero_c` (a C wrapper over `wallet2_api.h`, used by Dart wallets) and eigenwallet's `monero-sys` (statically links wallet2). Reported problems: the wrapper is "as low level as wallet2_api.h" and callers can pass invalid pointers. There are build breakages against newer upstream. [reported] |
| Security cost | Statically links a large C++ codebase (Boost, epee **including its HTTP/networking stack**, libunbound, ZMQ, OpenSSL). (1) Linking that into `kage-signer` breaks the *verifiable* "no networking in the signer" guarantee: `cargo deny` cannot see inside it. (2) Adds a large memory-unsafe surface. (3) wallet2 as a whole has no third-party audit; only the FCMP++ integration is being audited. (4) A "thin" FFI over wallet2 is not thin in practice: the API is broad and stateful. |

**Verdict:** Option A for the product. Option B (`monero-wallet-rpc` as a
separate process on stagenet) is the **differential-test oracle** in CI and
integration tests.

### Option C — hybrid (wallet2 only inside `kage-hw` for Ledger)

Considered for Ledger support, since wallet2 already has `device_ledger`. It
brings the C++ cost back into one crate. It may become the pragmatic route
after the fork if no Rust host-side Ledger implementation exists. **Deferred**
(§7, Q3).

---

## 4. Other components

| Need | Candidate | Version | Audit / notes |
|---|---|---|---|
| Tor | `arti-client` | 0.48.0 (2026-11-04) | Tor Project. Arti 2.0 (Feb 2026) marked the `arti` crate APIs experimental; `arti-client` is the library to use. Onion-service *client* feature to be checked in Stage 2. Pin exactly; check TROVE advisories. |
| Node RPC | `monero-simple-request-rpc` or our own over arti streams | 0.1.0 | `kage-node` only. Never a dependency of the signer. |
| AEAD | `chacha20poly1305` (XChaCha20Poly1305) | 0.11.0 | [unverified] RustCrypto `chacha20poly1305` was audited by NCC Group (2020) at an older version. Confirm the scope in Stage 2. |
| KDF | `argon2` (RustCrypto) | 0.6.0 | **No formal third-party audit that I know of.** Conflicts with "audited crates only". See §7, Q4. Will be checked against RFC 9106 known-answer test vectors either way. |
| Curve | `curve25519-dalek` | 4.1.3 (via monero-oxide); 5.0.0 is the latest | Quarkslab audit (2019) of an older major version [unverified scope]. We take the version monero-oxide pins and do not add a second copy. |
| Secrets | `zeroize`, `secrecy` | 1.9 / current | Standard. |
| RNG | `getrandom` (direct) and `rand_core::OsRng` only | 0.2 via deps | `cargo deny` bans `thread_rng`-style generators in our own crates (ban list plus a custom lint). |
| mlock / prctl / rlimit / seccomp / landlock | `rustix` (or `nix`), `landlock`, `seccompiler` | TBD | These system calls need `unsafe` unless a safe wrapper exists. `rustix` and `landlock` expose safe APIs, which keeps our crates at `forbid(unsafe_code)`. Stage 2 picks between them. |
| TUI | `ratatui` + `crossterm` | 0.30.2 | No secrets pass through the rendering path except on the seed-reveal screen. |
| QR display | `qrcode` | TBD | Encoding only; the core and TUI render it. |
| QR transport format | **BC-UR (Blockchain Commons Uniform Resources)** with fountain codes | TBD | An existing standard for animated, chunked QR codes, used by other air-gapped wallets. We adopt it rather than invent a chunking format. Decoders are untrusted-input parsers and get fuzzed. |
| QR scan (signer) | `rqrr` + camera, **or file only** | TBD | Camera and image decoding on the signer is a large untrusted-input attack surface. See §7, Q5. |

---

## 5. Seed (25 words + optional passphrase)

- The 25-word encoding (wordlist + checksum word) is simple, but it **must
  match wallet2 exactly**. The only Rust crate (`monero-seed 0.0.1`) is
  unaudited and outside monero-oxide.
- **Plan:** vendor it (or a minimal re-implementation following the reference
  `electrum-words.cpp`; this is an encoding, not cryptography). Add
  differential tests: restore through `monero-wallet-rpc`
  (`restore_deterministic_wallet`) on stagenet, plus the vectors in Monero's
  own test suite.
- **Passphrase:** I understand the passphrase as wallet2's "seed offset".
  [unverified] Its exact derivation must be read from the wallet2 source and
  matched with differential tests. I will **not** implement it from memory.
  If it cannot be matched and tested, the passphrase feature waits.
- Polyseed (16 words, includes the wallet birthday) is a widely used
  alternative. Not requested; noted only.
- Carrot-native seed format: [unverified] not yet standardised as far as I
  could find. Legacy 25-word seeds keep working after the fork (with the
  key-image caveat in §2).

---

## 6. Proposed revision to the staged plan

| Stage | Original | Proposed |
|---|---|---|
| 2 | Threat model + skeleton + CI | Unchanged. Add: no-network check for `kage-signer` (`cargo deny` bans plus a `cargo tree` script in CI), review of the monero-oxide audited-vs-pinned difference, Carrot key-hierarchy design note. |
| 3 | kage-core (stagenet) + TUI | Unchanged; **stagenet only**. Includes key-image import and differential tests against `monero-wallet-rpc`. |
| 4a | Signer + QR | Signer also handles **key-image export**. BC-UR transport. File transport first, QR second. |
| 4b | Ledger | **Deferred** until Ledger's FCMP++/Carrot app exists. Then test against Speculos (Monero PR #10421 adds Speculos support). |
| 5 | Hardening | Unchanged. |
| 6 (new) | — | FCMP++/Carrot: adopt monero-oxide's release once published, review it, enable the mainnet feature. |

---

## 7. Decisions needed from you

I default to the safer option on each and will proceed on it unless you say otherwise.

**Q1. Protocol library.** Recommended: **monero-oxide**, with wallet2 used only
as a test oracle. The alternative, wallet2 via FFI, gives exact reference
behaviour sooner and FCMP++ sooner. It does so at the cost of a large unsafe
C++ surface and an unverifiable no-network guarantee in the signer.

**Q2. Mainnet gating.** Recommended: **stagenet/testnet only** until
monero-oxide ships FCMP++/Carrot and we have reviewed it. Mainnet is a
compile-time-disabled feature, not just a runtime flag. CLSAG mainnet support
would be usable for only a few months and would add unaudited code paths
(output selection, our own state handling) handling real funds.

**Q3. Ledger (`kage-hw`).** Recommended: **defer**, and keep the crate as a
stub that refuses to build in release mode. Writing a host-side Ledger CLSAG
protocol in Rust now means new, security-critical protocol code for a feature
that stops working at the fork. Alternative: the Option C hybrid later.

**Q4. Argon2.** RustCrypto `argon2` has no formal audit that I know of.
Options: (a) **use it**, with RFC 9106 known-answer tests and conservative
parameters (recommended; pure Rust, no unsafe); (b) libsodium via FFI
(audited, but C code and FFI `unsafe` in the storage path). Option (a) relaxes
your "audited crates only" rule, which is why I am asking.

**Q5. Signer input channel.** Recommended: the signer accepts **file input
(USB stick) and QR via camera**, but the camera path is an optional,
separately sandboxed feature, **off by default**. Image decoding is a large
attack surface on the most sensitive machine. Signer *output* to the hot side
via displayed QR is always available.

---

## Sources

- monero-oxide repo and audits: https://github.com/monero-oxide/monero-oxide, https://github.com/monero-oxide/monero-oxide/tree/main/audits
- monero-oxide announcement: https://serai.exchange/2025/09/09/monero-serai-oxide.html
- CCS audit proposal: https://ccs.getmonero.org/proposals/monero-serai-wallet-audit.html
- monero-wallet docs: https://docs.rs/monero-wallet/0.2.0/monero_wallet/
- carrot-rs merge proposal: https://github.com/monero-oxide/monero-oxide/issues/204
- FCMP++ draft timeline (reported): https://www.kucoin.com/news/flash/monero-privacy-upgrade-fcmp-to-replace-ring-signatures
- Stressnet fork: https://cryptoticker.io/en/monero-fcmp-stressnet-fork-october-2026/, https://www.tokenpost.com/news/technology/25090
- Work breakdown plan: https://github.com/jeffro256/fcmp-carrot-plan
- Consensus integration PR: https://github.com/monero-project/monero/pull/11440
- Hot/cold Carrot/FCMP++: https://github.com/seraphis-migration/monero/pull/52
- Wallet RPC → Wallet API: https://github.com/monero-project/monero/pull/10819
- Ledger Speculos support: https://github.com/monero-project/monero/pull/10421
- Arti 2.0 / 2.2: https://blog.torproject.org/arti_2_0_0_released/, https://blog.torproject.org/arti_2_2_0_released/
- monero_c and monero-sys precedent: https://awesome.ecosyste.ms/projects/github.com%2Fmrcyjanek%2Fmonero_c, https://github.com/comit-network/xmr-btc-swap
