#!/usr/bin/env bash
# Enforces that kage-signer (the only crate touching the spend key) has NO
# networking capability (ADR-012, T-SIGN-NET). Three independent checks:
#
#  1. ALLOWLIST: every crate in the signer's dependency graph (normal + build,
#     all supported Linux targets) must be listed in crates/kage-signer/ALLOWED_DEPS.
#     Adding any dependency requires an explicit, reviewed allowlist change.
#  2. FEATURES: networking features of allowed crates are not enabled
#     (e.g. rustix "net", std-shims/any "net"-named feature).
#  3. SOURCE: no socket APIs are referenced by any workspace crate the signer
#     links.
#
# The cargo-deny DENYLIST (crates/kage-signer/deny.toml) runs separately in CI.
set -euo pipefail
cd "$(dirname "$0")/.."

ALLOW_FILE=crates/kage-signer/ALLOWED_DEPS
TARGETS=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)
LOCKED=(--locked)
if [[ "${SIGNER_GUARD_SELF_TEST:-0}" == "1" ]]; then LOCKED=(); fi
fail=0

tree() {
  local t
  for t in "${TARGETS[@]}"; do
    cargo tree "${LOCKED[@]}" -p kage-signer --target "$t" "$@"
  done
}

# --- 1. allowlist ------------------------------------------------------------
actual=$(tree -e normal,build --prefix none --format '{p}' \
  | awk '{print $1}' | sort -u)
allowed=$(grep -vE '^\s*(#|$)' "$ALLOW_FILE" | awk '{print $1}' | sort -u)

unexpected=$(comm -23 <(echo "$actual") <(echo "$allowed"))
if [[ -n "$unexpected" ]]; then
  echo "ERROR: crates in kage-signer's dependency graph that are not in $ALLOW_FILE:" >&2
  echo "$unexpected" | sed 's/^/  - /' >&2
  echo "Review them for networking/async capability, then add them with a justification." >&2
  fail=1
fi
stale=$(comm -13 <(echo "$actual") <(echo "$allowed"))
if [[ -n "$stale" ]]; then
  echo "NOTE: allowlisted crates no longer in the graph (consider removing):" >&2
  echo "$stale" | sed 's/^/  - /' >&2
fi

# --- 2. features -------------------------------------------------------------
net_features=$(tree -e features --prefix none \
  | grep -E 'feature "(net|socket|sockets|tokio|async|http|tls|rustls|std-net)"' \
  | sort -u || true)
if [[ -n "$net_features" ]]; then
  echo "ERROR: networking-related features enabled in kage-signer's graph:" >&2
  echo "$net_features" | sed 's/^/  - /' >&2
  fail=1
fi

# --- 3. source ---------------------------------------------------------------
local_dirs=$(tree -e normal,build --prefix none --format '{p}' \
  | sed -nE 's/.*\((\/[^)]*)\).*/\1/p' | sort -u)
pattern='std::net::|std::os::unix::net|TcpStream|TcpListener|UdpSocket|UnixStream|UnixListener|UnixDatagram|rustix::net|libc::(socket|connect|bind)'
for d in $local_dirs; do
  if hits=$(grep -rnE "$pattern" "$d/src" 2>/dev/null); then
    echo "ERROR: socket API referenced in signer-linked crate $d:" >&2
    echo "$hits" | sed 's/^/  /' >&2
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "kage-signer network-isolation check: FAILED" >&2
  exit 1
fi
echo "kage-signer network-isolation check: OK ($(echo "$actual" | wc -l) crates, all allowlisted; no net features; no socket APIs)"
