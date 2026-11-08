//! Page-locked, guard-paged, dump-excluded memory for secrets.
//!
//! Each [`LockedBytes`] owns a private anonymous mapping laid out as:
//!
//! ```text
//! +------------+---------------------------------+------------+
//! | guard page |  data pages (RW, mlocked,       | guard page |
//! | PROT_NONE  |  MADV_DONTDUMP, MADV_WIPEONFORK)| PROT_NONE  |
//! +------------+---------------------------------+------------+
//!                              ^ data ends exactly at the trailing guard,
//!                                so a linear overflow faults immediately.
//! ```
//!
//! Properties:
//! - **No swap:** data pages are `mlock`ed. Construction fails (fail-closed) if
//!   locking is not possible, e.g. `RLIMIT_MEMLOCK` is exhausted.
//! - **No core dumps:** `MADV_DONTDUMP` (defence in depth; the process also sets
//!   `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0`, see `kage-harden`).
//! - **No leak to children:** `MADV_WIPEONFORK`: a forked child sees zeroes.
//! - **Overflow detection:** `PROT_NONE` guard pages on both sides.
//! - **Erasure:** on drop, all data pages are zeroized with volatile writes
//!   (`zeroize`), then unlocked and unmapped. The pages go back to the kernel,
//!   never to the userspace allocator.
//!
//! Not provided (documented limitation, see `docs/THREAT_MODEL.md`, `T-MEM-*`): copies of
//! secret material made *by other code* (e.g. temporaries inside `monero-wallet`
//! or registers/stack) are outside this mapping. The signer additionally uses
//! `mlockall` (see `kage-harden`) to cover those against swap.

#![allow(unsafe_code)] // The ONLY module in the workspace allowed to use `unsafe`.

use core::ffi::c_void;
use core::fmt;
use core::ptr::NonNull;

use rustix::mm::{self, Advice, MapFlags, MprotectFlags, ProtFlags};
use zeroize::Zeroize;

/// Errors creating a [`LockedBytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockError {
    /// A zero-length secret was requested.
    Empty,
    /// The requested size overflows when rounded to pages.
    TooLarge,
    /// `mmap` failed.
    Map(rustix::io::Errno),
    /// `mprotect` failed.
    Protect(rustix::io::Errno),
    /// `mlock` failed. Usually `RLIMIT_MEMLOCK` is too low.
    Lock(rustix::io::Errno),
    /// `madvise` failed (kernel too old or advice unsupported).
    Advise(rustix::io::Errno),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("zero-length locked buffer requested"),
            Self::TooLarge => f.write_str("locked buffer size overflow"),
            Self::Map(e) => write!(f, "mmap failed: {e}"),
            Self::Protect(e) => write!(f, "mprotect failed: {e}"),
            Self::Lock(e) => write!(
                f,
                "mlock failed: {e} (raise RLIMIT_MEMLOCK; see docs/INSTALL.md)"
            ),
            Self::Advise(e) => write!(f, "madvise failed: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

/// An owned private anonymous mapping. Unmapped exactly once, on drop.
struct Mapping {
    base: NonNull<c_void>,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` describe a mapping returned by a successful
        // `mmap_anonymous` in `LockedBytes::new_zeroed`. `Mapping` is not
        // `Clone`, so this is the only unmap of it, and no references into it
        // outlive `self` (`LockedBytes` hands out borrows tied to `&self`).
        // Nothing useful can be done on failure during drop; the mapping then
        // stays locked until process exit, which is the safe direction.
        let _: rustix::io::Result<()> = unsafe { mm::munmap(self.base.as_ptr(), self.len) };
    }
}

/// A fixed-size byte buffer held in locked, guard-paged, dump-excluded memory.
///
/// Its `Debug` output is redacted. It is not `Clone` (copying a secret must be
/// explicit). Contents are zeroized on drop.
pub struct LockedBytes {
    /// RAII owner of the whole mapping; unmaps on drop (after `Drop for
    /// LockedBytes` has zeroized and unlocked the data pages).
    _mapping: Mapping,
    /// Start of the RW data pages (just after the leading guard page).
    pages: NonNull<u8>,
    /// Length of the RW data pages (a multiple of the page size).
    pages_len: usize,
    /// Start of the caller-visible data (end-aligned within `pages`).
    data: NonNull<u8>,
    /// Caller-visible length (`1..=pages_len`).
    len: usize,
}

// SAFETY: `LockedBytes` exclusively owns its mapping (like `Box<[u8]>`): no
// other handle aliases it, so moving it to another thread is sound.
unsafe impl Send for LockedBytes {}
// SAFETY: shared access only yields `&[u8]` (via `&self`); mutation requires
// `&mut self`. That is the same aliasing discipline as `Box<[u8]>`.
unsafe impl Sync for LockedBytes {}

impl LockedBytes {
    /// Allocates `len` zeroed bytes of locked memory.
    ///
    /// # Errors
    /// Fails closed if the memory cannot be mapped, protected, locked or
    /// advised. In particular this fails if `RLIMIT_MEMLOCK` is too low; callers
    /// must not fall back to unlocked memory for secrets.
    pub fn new_zeroed(len: usize) -> Result<Self, LockError> {
        if len == 0 {
            return Err(LockError::Empty);
        }
        let page = rustix::param::page_size();
        let pages_len = len
            .checked_next_multiple_of(page)
            .ok_or(LockError::TooLarge)?;
        let guards = page.checked_mul(2).ok_or(LockError::TooLarge)?;
        let map_len = pages_len.checked_add(guards).ok_or(LockError::TooLarge)?;

        // SAFETY: requesting a fresh private anonymous mapping with a null hint
        // cannot alias or invalidate any existing Rust object.
        let raw = unsafe {
            mm::mmap_anonymous(
                core::ptr::null_mut(),
                map_len,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
        }
        .map_err(LockError::Map)?;
        let base = NonNull::new(raw).ok_or(LockError::Map(rustix::io::Errno::NOMEM))?;
        // From here on, `mapping` unmaps on every early return.
        let mapping = Mapping { base, len: map_len };

        // In-bounds: `page < map_len` because `map_len = pages_len + 2 * page`.
        let pages_raw = base.as_ptr().cast::<u8>().wrapping_add(page);
        let pages = NonNull::new(pages_raw).ok_or(LockError::Map(rustix::io::Errno::FAULT))?;

        // SAFETY: `[pages, pages + pages_len)` lies inside the mapping we own
        // (after the leading guard page, before the trailing one). No Rust
        // references into the mapping exist yet.
        unsafe {
            mm::mprotect(
                pages.as_ptr().cast(),
                pages_len,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
        }
        .map_err(LockError::Protect)?;

        // SAFETY: same range as above, inside our mapping. `mlock` only changes
        // paging behaviour; it does not touch memory contents.
        unsafe { mm::mlock(pages.as_ptr().cast(), pages_len) }.map_err(LockError::Lock)?;

        // Construct now so that `Drop` (zeroize + munlock) runs on any later
        // failure. The pages are locked at this point.
        let offset = pages_len.checked_sub(len).ok_or(LockError::TooLarge)?;
        let data_raw = pages.as_ptr().wrapping_add(offset);
        let data = NonNull::new(data_raw).ok_or(LockError::Map(rustix::io::Errno::FAULT))?;
        let this = Self {
            _mapping: mapping,
            pages,
            pages_len,
            data,
            len,
        };

        for advice in [Advice::LinuxDontDump, Advice::LinuxWipeOnFork] {
            // SAFETY: page-aligned range inside our mapping. These advices only
            // set VMA flags; they do not change current contents.
            unsafe { mm::madvise(this.pages.as_ptr().cast(), this.pages_len, advice) }
                .map_err(LockError::Advise)?;
        }
        Ok(this)
    }

    /// Allocates locked memory, copies `src` into it, then zeroizes `src`.
    ///
    /// # Errors
    /// See [`LockedBytes::new_zeroed`]. On error `src` is still zeroized, so a
    /// secret is never left behind in unlocked memory by this call.
    pub fn from_slice_zeroizing(src: &mut [u8]) -> Result<Self, LockError> {
        let result = Self::new_zeroed(src.len()).map(|mut locked| {
            locked.expose_mut().copy_from_slice(src);
            locked
        });
        src.zeroize();
        result
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Always `false`: zero-length buffers cannot be constructed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Borrows the secret bytes. Keep the borrow as short as possible.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: `data..data+len` lies within the RW, locked data pages
        // owned by `self`, which stay mapped while `self` lives. The returned
        // borrow is tied to `&self`, so it cannot outlive the mapping, and no
        // `&mut` can coexist with it.
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    /// Mutably borrows the secret bytes.
    #[must_use]
    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `expose`; `&mut self` guarantees exclusivity.
        unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    fn all_pages_mut(&mut self) -> &mut [u8] {
        // SAFETY: `pages..pages+pages_len` is the RW data region owned by
        // `self`; `&mut self` guarantees exclusivity.
        unsafe { core::slice::from_raw_parts_mut(self.pages.as_ptr(), self.pages_len) }
    }
}

impl Drop for LockedBytes {
    fn drop(&mut self) {
        // Zeroize the entire data region, not only `len`, in case callers ever
        // wrote through a stale view (they cannot in safe code, but be strict).
        self.all_pages_mut().zeroize();
        // SAFETY: same range we locked in `new_zeroed`, still mapped.
        let _: rustix::io::Result<()> =
            unsafe { mm::munlock(self.pages.as_ptr().cast(), self.pages_len) };
        // `self._mapping` is dropped after this function returns, which unmaps.
    }
}

impl fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LockedBytes([REDACTED; {}])", self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_len_rejected() {
        assert_eq!(LockedBytes::new_zeroed(0).unwrap_err(), LockError::Empty);
    }

    #[test]
    fn starts_zeroed_and_round_trips() -> Result<(), LockError> {
        for len in [1usize, 31, 32, 4095, 4096, 4097, 3 * 4096 + 7] {
            let mut b = LockedBytes::new_zeroed(len)?;
            assert_eq!(b.len(), len);
            assert!(b.expose().iter().all(|&x| x == 0));
            for (i, x) in b.expose_mut().iter_mut().enumerate() {
                *x = u8::try_from(i % 251).unwrap_or(0);
            }
            assert!(
                b.expose()
                    .iter()
                    .enumerate()
                    .all(|(i, &x)| Some(x) == u8::try_from(i % 251).ok())
            );
        }
        Ok(())
    }

    #[test]
    fn from_slice_zeroizes_source() -> Result<(), LockError> {
        let mut src = [0xAAu8; 32];
        let b = LockedBytes::from_slice_zeroizing(&mut src)?;
        assert_eq!(src, [0u8; 32]);
        assert_eq!(b.expose(), &[0xAAu8; 32]);
        Ok(())
    }

    #[test]
    fn debug_is_redacted() -> Result<(), LockError> {
        let mut src = *b"supersecretsupersecretsupersecre";
        let b = LockedBytes::from_slice_zeroizing(&mut src)?;
        let s = format!("{b:?}");
        assert_eq!(s, "LockedBytes([REDACTED; 32])");
        Ok(())
    }

    #[test]
    fn many_allocations_release_lock_budget() -> Result<(), LockError> {
        // If munlock/munmap leaked, RLIMIT_MEMLOCK (often 8 MiB) would be
        // exhausted well before 10k pages.
        for _ in 0..10_000 {
            let b = LockedBytes::new_zeroed(64)?;
            drop(b);
        }
        Ok(())
    }
}
