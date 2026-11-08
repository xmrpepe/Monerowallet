# ZeroTrace

A security-first Monero wallet for the terminal. It is keyboard-driven,
tiling-friendly, and built to sit in an [Omarchy](https://omarchy.org)
/ Hyprland layout.

> **Status: pre-alpha, Stage 2 of 5. Stagenet/testnet only. Mainnet is
> compile-time disabled until FCMP++/Carrot support lands
> ([ADR-002](docs/DECISIONS.md#adr-002-stagenettestnet-only-mainnet-is-compile-time-disabled)).**

## Design in one paragraph

The **online** wallet (`zerotrace`) holds only the view key. It scans the chain
through your own node, or a remote node strictly over Tor, and builds
*unsigned* transactions. The **offline** signer (`kage-signer`) is the only
program that ever touches your seed. It has no networking code (verified in CI
by an allowlist and a denylist), locks all its memory, refuses to run with
unencrypted swap, and shows you every destination, amount and fee before
signing. The two sides exchange data by file or animated QR. Monero protocol
logic comes from the audited-lineage
[monero-oxide](https://github.com/monero-oxide/monero-oxide) libraries. No
cryptography is implemented here.

## Workspace

| Crate | Role | Network? | `unsafe`? |
|---|---|---|---|
| `kage-signer` | Offline signer (spend key) | **never** | forbidden |
| `kage-core` | View-only wallet logic | no | forbidden |
| `kage-node` | Node connection policy / RPC / Tor | yes | forbidden |
| `kage-tui` | Terminal UI (`zerotrace` binary) | via kage-node | forbidden |
| `kage-hw` | Ledger signing (deferred, ADR-003) | no | forbidden |
| `kage-airgap` | Air-gap envelope format | no | forbidden |
| `kage-vault` | Encrypted wallet files | no | forbidden |
| `kage-harden` | Process hardening | no | forbidden |
| `kage-sys` | Locked secret memory | no | **only here**, documented |

## Documents

- [Stage 1 research report](docs/RESEARCH.md): library choice, audit status, FCMP++ readiness
- [Decisions (ADRs)](docs/DECISIONS.md)
- [Threat model (STRIDE)](docs/THREAT_MODEL.md)
- [Audit index](AUDIT.md)
- [File formats](docs/FORMATS.md) · [Reproducible builds & releases](docs/RELEASE.md) · [Install notes](docs/INSTALL.md)
- [Security policy](SECURITY.md)

## Building and checking

```sh
cargo test --workspace --locked
./scripts/check-policy.sh && ./scripts/check-signer-deps.sh
cargo deny check && cargo audit && cargo vet --locked
./scripts/build-release.sh        # reproducible static binaries
```

## License

GPL-3.0-only.
