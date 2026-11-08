//! # kage-harden: process hardening
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! [`harden_process`] must be the first thing every ZeroTrace binary does,
//! before any secret is read or derived. It:
//!
//! 1. sets `PR_SET_DUMPABLE=0`. That disables core dumps, makes
//!    `/proc/<pid>/mem` and friends root-owned, and blocks `ptrace` attach from
//!    same-UID processes that lack `CAP_SYS_PTRACE`;
//! 2. sets `RLIMIT_CORE=0` (soft and hard);
//! 3. for [`Profile::Signer`], locks *all* current and future pages
//!    (`mlockall(MCL_CURRENT | MCL_FUTURE)`), raising the soft
//!    `RLIMIT_MEMLOCK` to the hard limit first;
//! 4. assesses swap and hibernation exposure. The signer **refuses to run**
//!    when disk-backed swap that cannot be shown to be encrypted is active,
//!    because hibernation writes locked pages to swap (ADR-008).
//!
//! Seccomp-bpf and Landlock confinement are added in Stage 5 (see
//! `docs/THREAT_MODEL.md`, T-OS-*).

#![forbid(unsafe_code)]

mod swap;

pub use swap::{SwapEntry, SwapKind, classify_swaps};

use rustix::mm::{MlockAllFlags, mlockall};
use rustix::process::{
    DumpableBehavior, Resource, Rlimit, getrlimit, set_dumpable_behavior, setrlimit,
};

/// Which hardening policy to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// The offline signer: holds the spend key. Strictest policy, fail-closed.
    Signer,
    /// Online processes (TUI, node): hold at most the view key. Secrets use
    /// per-allocation locking via `kage_sys::LockedBytes`.
    Online,
}

/// How process memory is protected from swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryLock {
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` is in effect.
    AllPages,
    /// Only individual secret allocations are locked.
    PerSecret,
}

/// What hardening achieved. Warnings must be shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Memory-locking mode in effect.
    pub memory: MemoryLock,
    /// Active swap areas and their classification.
    pub swaps: Vec<SwapEntry>,
    /// Whether the kernel advertises suspend-to-disk.
    pub hibernation_available: bool,
    /// Human-readable warnings (never contain secrets).
    pub warnings: Vec<String>,
}

/// Hardening failures. All of them are fatal for the caller.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HardenError {
    /// `prctl(PR_SET_DUMPABLE, 0)` failed.
    #[error("could not disable core dumps / ptrace (PR_SET_DUMPABLE): {0}")]
    Dumpable(rustix::io::Errno),
    /// `setrlimit(RLIMIT_CORE, 0)` failed.
    #[error("could not set RLIMIT_CORE=0: {0}")]
    CoreLimit(rustix::io::Errno),
    /// `mlockall` failed.
    #[error(
        "could not lock memory (mlockall): {errno}. RLIMIT_MEMLOCK hard limit is {hard}. \
         The signer requires all memory locked; see docs/INSTALL.md (\"Signer memory locking\")"
    )]
    MemoryLock {
        /// The OS error.
        errno: rustix::io::Errno,
        /// The hard memlock limit, for the error message.
        hard: String,
    },
    /// Disk-backed swap that is not provably encrypted is active.
    #[error(
        "refusing to run the signer: active swap that is not provably encrypted: {0}. \
         Hibernation or memory pressure could write secrets to disk. Disable it (`swapoff -a`) \
         or use zram / dm-crypt swap. See ADR-008"
    )]
    UnsafeSwap(String),
}

/// Applies the hardening policy for `profile`. Call once, at startup, before
/// handling any secret.
///
/// # Errors
/// Fails closed: any step that cannot be applied returns an error, and the
/// caller must exit.
pub fn harden_process(profile: Profile) -> Result<Report, HardenError> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(HardenError::Dumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(HardenError::CoreLimit)?;

    let memory = match profile {
        Profile::Signer => {
            lock_all_memory()?;
            MemoryLock::AllPages
        }
        Profile::Online => MemoryLock::PerSecret,
    };

    let swaps = std::fs::read_to_string("/proc/swaps").map_or_else(
        // If /proc/swaps is unreadable we cannot prove safety: fail closed.
        |_| {
            vec![SwapEntry {
                path: "<unreadable /proc/swaps>".into(),
                kind: SwapKind::Unknown,
            }]
        },
        |s| classify_swaps(&s, swap::resolve_kind),
    );
    let hibernation_available = std::fs::read_to_string("/sys/power/state")
        .is_ok_and(|s| s.split_whitespace().any(|w| w == "disk"));

    let unsafe_swaps: Vec<&str> = swaps
        .iter()
        .filter(|e| !e.kind.is_safe())
        .map(|e| e.path.as_str())
        .collect();

    let mut warnings = Vec::new();
    if !unsafe_swaps.is_empty() {
        match profile {
            Profile::Signer => return Err(HardenError::UnsafeSwap(unsafe_swaps.join(", "))),
            Profile::Online => warnings.push(format!(
                "swap that is not provably encrypted is active ({}); the view key is locked in \
                 memory but other wallet data may be swapped",
                unsafe_swaps.join(", ")
            )),
        }
    }
    if hibernation_available && !swaps.is_empty() {
        warnings.push(
            "suspend-to-disk is available: hibernating writes RAM (including locked pages) to swap"
                .into(),
        );
    }

    Ok(Report {
        memory,
        swaps,
        hibernation_available,
        warnings,
    })
}

fn lock_all_memory() -> Result<(), HardenError> {
    let limit = getrlimit(Resource::Memlock);
    // Raise the soft limit as far as the hard limit allows. No privilege needed.
    let raised = setrlimit(
        Resource::Memlock,
        Rlimit {
            current: limit.maximum,
            maximum: limit.maximum,
        },
    );
    // A failure to raise is not fatal by itself; `mlockall` decides.
    let _: rustix::io::Result<()> = raised;

    mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_err(|errno| {
        HardenError::MemoryLock {
            errno,
            hard: limit
                .maximum
                .map_or_else(|| "unlimited".to_owned(), |b| format!("{b} bytes")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // `harden_process(Profile::Online)` is safe to run inside the test
    // process: it only removes capabilities (dumpability, core files).
    #[test]
    fn online_profile_applies() {
        let report = harden_process(Profile::Online).expect("hardening must succeed");
        assert_eq!(report.memory, MemoryLock::PerSecret);
        assert_eq!(getrlimit(Resource::Core).current, Some(0));
        assert_eq!(
            rustix::process::dumpable_behavior().ok(),
            Some(DumpableBehavior::NotDumpable)
        );
    }
}
