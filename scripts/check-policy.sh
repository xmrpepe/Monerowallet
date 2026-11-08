#!/usr/bin/env bash
# Workspace source-policy checks that the compiler/clippy cannot express.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
err() { echo "ERROR: $*" >&2; fail=1; }

UNSAFE_ISLAND="crates/kage-sys/src/locked.rs"

# 1. Every crate except kage-sys inherits workspace lints (unsafe_code = forbid).
for toml in crates/*/Cargo.toml; do
  crate=$(basename "$(dirname "$toml")")
  [[ "$crate" == "kage-sys" ]] && continue
  if ! grep -Pzq '\[lints\]\s*\nworkspace\s*=\s*true' "$toml"; then
    err "$toml must contain '[lints] workspace = true'"
  fi
done

# 2. Every crate root (lib.rs, main.rs, src/bin/*.rs) except kage-sys declares
#    #![forbid(unsafe_code)] explicitly (visible to auditors).
while IFS= read -r root; do
  [[ "$root" == crates/kage-sys/* ]] && continue
  grep -q '^#!\[forbid(unsafe_code)\]' "$root" || err "$root lacks #![forbid(unsafe_code)]"
done < <(find crates -path '*/src/*' \( -name lib.rs -o -name main.rs -o -path '*/src/bin/*.rs' \) | sort)

# 3. `unsafe` code appears only in the documented island.
hits=$(grep -rnE '\bunsafe[[:space:]]*(\{|fn\b|impl\b|trait\b|extern\b)' crates fuzz 2>/dev/null \
  | grep -v "^$UNSAFE_ISLAND:" || true)
[[ -z "$hits" ]] || err "unsafe code outside $UNSAFE_ISLAND:"$'\n'"$hits"
grep -q '^#!\[deny(unsafe_code)\]' crates/kage-sys/src/lib.rs || err "kage-sys must deny unsafe_code at the crate root"
allows=$(grep -rn --include='*.rs' 'allow(unsafe_code)' crates | grep -v "^$UNSAFE_ISLAND:" || true)
[[ -z "$allows" ]] || err "allow(unsafe_code) outside $UNSAFE_ISLAND:"$'\n'"$allows"

# 4. Randomness: only the OS CSPRNG (getrandom / OsRng) in our code (ADR-011).
rng=$(grep -rnE 'thread_rng|ThreadRng|rand::random|SmallRng|StdRng|from_entropy|seed_from_u64|rand::rng\(' crates || true)
[[ -z "$rng" ]] || err "non-OS RNG referenced (ADR-011):"$'\n'"$rng"

# 5. No logging/tracing frameworks in signer-linked crates (secrets must never
#    reach a log sink). The allowlist already excludes them; this is a source
#    check for macros.
for d in crates/kage-signer crates/kage-vault crates/kage-sys crates/kage-airgap crates/kage-harden; do
  logs=$(grep -rnE '\b(log|tracing)::|\b(info|debug|trace|warn|error)!\(' "$d/src" || true)
  [[ -z "$logs" ]] || err "logging macros in $d (secret-handling crate):"$'\n'"$logs"
done

# 6. Mainnet stays compile-time disabled (ADR-002).
grep -q 'compile_error!' crates/kage-airgap/src/lib.rs || err "mainnet compile_error! gate missing in kage-airgap"

if [[ $fail -ne 0 ]]; then echo "policy check: FAILED" >&2; exit 1; fi
echo "policy check: OK"
