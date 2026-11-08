# Security policy

ZeroTrace is **pre-alpha** and **mainnet is disabled** (docs/DECISIONS.md,
ADR-002). Do not use it with real funds.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") on this repository.
Include the affected commit, the steps to reproduce, and the impact.

## Scope

In scope: everything in this repository. `AUDIT.md` lists the most critical
files, and `docs/THREAT_MODEL.md` defines what ZeroTrace does and does not
defend against.

Issues in upstream dependencies (e.g. monero-oxide, RustCrypto, arti) should
also be reported upstream. We track them through `cargo audit` and
`cargo deny`.
