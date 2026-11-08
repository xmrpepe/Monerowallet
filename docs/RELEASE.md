# Reproducible builds and release signing

## Build

```sh
./scripts/build-release.sh            # → dist/x86_64-unknown-linux-musl/{kage-signer,zerotrace,SHA256SUMS}
```

Inputs that determine the output bytes, all pinned in the repository:

| Input | Pinned by |
|---|---|
| Compiler | `rust-toolchain.toml` (`1.97.0`) |
| Dependencies | `Cargo.lock` (versions + SHA-256), `--locked` |
| Flags | `scripts/build-release.sh` (`--remap-path-prefix` for repo, `CARGO_HOME`, sysroot; `+crt-static`) |
| Profile | `[profile.release]`: `codegen-units = 1`, `lto = "fat"`, `panic = "abort"`, `strip = "symbols"` |
| Timestamp | `SOURCE_DATE_EPOCH` = commit time |

Outputs are **static-pie** binaries with no dynamic loader, which defeats
`LD_PRELOAD` and `LD_LIBRARY_PATH` injection (T-SIGN-INJECT).

Verified in Stage 2: two builds from different absolute paths were
bit-for-bit identical. CI (`reproducible` job) repeats this on every push.

## Release procedure (ADR-015)

1. Tag `vX.Y.Z` on a commit where CI is green.
2. `release.yml` runs the tests, builds, creates a **Sigstore build-provenance
   attestation**, and publishes a **draft** release with `SHA256SUMS`.
3. The maintainer, on their own machine, checks out the tag, runs
   `./scripts/build-release.sh`, and confirms that `SHA256SUMS` matches the
   draft byte for byte.
4. The maintainer signs offline: `minisign -Sm SHA256SUMS`. They upload
   `SHA256SUMS.minisig` and publish the release.

The minisign secret key never enters CI.

## Verifying a release (users)

```sh
minisign -Vm SHA256SUMS -P <ZeroTrace public key from README>
sha256sum -c SHA256SUMS
gh attestation verify kage-signer --repo xmrpepe/Monerowallet   # optional: provenance
```

For the strongest assurance, rebuild from the tag with
`./scripts/build-release.sh` and compare checksums.
