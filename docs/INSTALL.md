# Installation notes (security-relevant)

Full packaging (AUR PKGBUILD, desktop entry, Omarchy install script) arrives in
Stage 5. This page records the platform requirements that the code already
enforces.

## Signer memory locking

`kage-signer` locks **all** of its memory (`mlockall`) and refuses to start if
it cannot (fail-closed, ADR-008). Most distributions default to an 8 MiB
`RLIMIT_MEMLOCK`, which is enough today (verified unprivileged in Stage 2).
Later stages will need more, so give the signer user 64 MiB:

```sh
# /etc/security/limits.d/zerotrace-signer.conf
<signer-user>  hard  memlock  65536
<signer-user>  soft  memlock  65536
```

or, if launched from systemd: `LimitMEMLOCK=64M`.

## Signer swap policy

The signer refuses to run while any swap is active that is not zram or dm-crypt
(ADR-008). On the offline machine:

```sh
sudo swapoff -a
```

Prefer a live-booted, diskless signer environment.

## Recommended kernel settings (both machines)

- `kernel.yama.ptrace_scope = 2` (or 3). ZeroTrace already sets itself
  non-dumpable, which blocks same-UID ptrace; this setting extends that
  protection system-wide.
- Encrypted disk (LUKS) on the online machine. Vault files are encrypted, but
  the terminal scrollback and shell history are not.
- On the offline machine: no network interfaces up, Wi-Fi/Bluetooth hardware
  disabled or removed. ZeroTrace's signer additionally confines itself
  (ADR-012).
