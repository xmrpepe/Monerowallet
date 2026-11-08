#!/usr/bin/env python3
"""Release-cooldown check (ADR-017).

Every crates.io package in the given Cargo.lock files must have been
published at least MIN_AGE_DAYS ago. A cooldown gives the ecosystem time to
detect and yank malicious or broken releases before we pick them up.

Publish times come from the crates.io sparse index (`pubtime`), one request
per crate name. Versions published before `pubtime` existed (2025) have no
field and are, by definition, old enough.

Usage: scripts/check-dep-age.py [--min-age-days N] Cargo.lock [more.lock ...]
Stdlib only, run with `python3 -I`.
"""

import argparse
import datetime as dt
import json
import sys
import tomllib
import urllib.request

INDEX = "https://index.crates.io"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def index_path(name: str) -> str:
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def pubtimes(name: str) -> dict:
    req = urllib.request.Request(
        f"{INDEX}/{index_path(name)}", headers={"User-Agent": "zerotrace-dep-age-check"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        lines = resp.read().decode().splitlines()
    out = {}
    for line in lines:
        entry = json.loads(line)
        out[entry["vers"]] = entry.get("pubtime")
    return out


def suggest(times: dict, current: str, cutoff: dt.datetime) -> str:
    """Newest version with the same major.minor (or same major, for >=1.0) that is
    older than the cutoff. Semver-compatible, so `cargo update --precise` works."""
    def key(v: str):
        core = v.split("+")[0].split("-")[0]
        return tuple(int(x) for x in core.split("."))
    cur = key(current)
    compat = (lambda k: k[0] == cur[0]) if cur[0] >= 1 else (lambda k: k[:2] == cur[:2])
    best = None
    for v, t in times.items():
        if "-" in v.split("+")[0]:
            continue  # skip pre-releases
        k = key(v)
        if not compat(k) or k > cur:
            continue
        if t is not None and dt.datetime.fromisoformat(t.replace("Z", "+00:00")) > cutoff:
            continue
        if best is None or k > key(best):
            best = v
    return best or "<none: needs a manual decision>"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-age-days", type=int, default=14)
    ap.add_argument("--suggest", action="store_true", help="print `cargo update --precise` fixes")
    ap.add_argument("lockfiles", nargs="+")
    args = ap.parse_args()

    wanted: dict[str, set[str]] = {}
    for lf in args.lockfiles:
        with open(lf, "rb") as f:
            lock = tomllib.load(f)
        for pkg in lock.get("package", []):
            if pkg.get("source") == REGISTRY:
                wanted.setdefault(pkg["name"], set()).add(pkg["version"])

    now = dt.datetime.now(dt.timezone.utc)
    limit = dt.timedelta(days=args.min_age_days)
    too_new, missing = [], []
    for name in sorted(wanted):
        times = pubtimes(name)
        for ver in sorted(wanted[name]):
            if ver not in times:
                missing.append(f"{name} {ver}")
                continue
            t = times[ver]
            if t is None:
                continue  # predates pubtime: old enough
            age = now - dt.datetime.fromisoformat(t.replace("Z", "+00:00"))
            if age < limit:
                too_new.append(f"{name} {ver} (published {t}, {age.days}d ago)")
                if args.suggest:
                    print(f"cargo update -p {name}@{ver} --precise {suggest(times, ver, now - limit)}")

    for m in missing:
        print(f"ERROR: {m} not found in the crates.io index (yanked or fabricated?)", file=sys.stderr)
    for t in too_new:
        print(f"ERROR: {t} is younger than {args.min_age_days} days", file=sys.stderr)
    if too_new or missing:
        print("dependency cooldown check: FAILED (pin an older version; see ADR-017)", file=sys.stderr)
        return 1
    total = sum(len(v) for v in wanted.values())
    print(f"dependency cooldown check: OK ({total} crate versions, all >= {args.min_age_days} days old)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
