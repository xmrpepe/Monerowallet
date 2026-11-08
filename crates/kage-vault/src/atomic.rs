//! Crash-safe file replacement and bounded reads.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::{HEADER_LEN, MAX_PLAINTEXT_LEN, TAG_LEN};

/// Atomically replaces `path` with `bytes`.
///
/// Steps: create a uniquely named temp file in the **same directory**
/// (`O_EXCL`, mode `0600`, so it never follows a planted symlink), write,
/// `fsync`, `rename` over the target, `fsync` the directory. A crash at any
/// point leaves either the old or the new file, never a torn one.
///
/// # Errors
/// I/O errors. The temp file is removed on failure.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;

    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|_| io::Error::other("OS RNG failed"))?;
    let suffix = rnd.iter().fold(String::with_capacity(16), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".tmp-{suffix}"));
    let tmp = dir.join(tmp_name);

    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        // Best effort; the temp file may already have been renamed.
        let _: io::Result<()> = fs::remove_file(&tmp);
    }
    result
}

/// Reads a vault file, refusing anything larger than a maximal vault, so a
/// hostile file cannot exhaust memory.
///
/// # Errors
/// I/O errors, or `InvalidData` if the file is too large.
pub fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let max = HEADER_LEN
        .saturating_add(MAX_PLAINTEXT_LEN)
        .saturating_add(TAG_LEN);
    let max_u64 = u64::try_from(max).unwrap_or(u64::MAX);
    let f = File::open(path)?;
    let mut out = Vec::new();
    f.take(max_u64.saturating_add(1)).read_to_end(&mut out)?;
    if out.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vault file too large",
        ));
    }
    Ok(out)
}
