//! Swap classification from `/proc/swaps`.
//!
//! Policy (ADR-008): a swap area is only treated as safe when it is provably
//! not persistent plaintext. That means zram (RAM-backed) or a device-mapper
//! target whose UUID marks it as dm-crypt (`CRYPT-` prefix). Everything else,
//! including swap *files* whose backing device cannot be resolved (e.g. on
//! btrfs), is `Unknown` and treated as unsafe.

use std::path::Path;

/// Classification of one active swap area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapKind {
    /// Compressed RAM (zram): not persisted to disk.
    Ram,
    /// dm-crypt device.
    Encrypted,
    /// A block device or file that is not provably encrypted.
    Unknown,
}

impl SwapKind {
    /// Whether this kind is acceptable for the signer.
    #[must_use]
    pub fn is_safe(self) -> bool {
        matches!(self, Self::Ram | Self::Encrypted)
    }
}

/// One active swap area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapEntry {
    /// Path as listed in `/proc/swaps` (octal escapes decoded).
    pub path: String,
    /// Classification.
    pub kind: SwapKind,
}

/// Parses `/proc/swaps` content and classifies each entry with `resolve`.
///
/// Lines that cannot be parsed are reported as `Unknown` (fail closed), never
/// dropped.
pub fn classify_swaps(proc_swaps: &str, resolve: impl Fn(&str) -> SwapKind) -> Vec<SwapEntry> {
    proc_swaps
        .lines()
        .skip(1) // header: "Filename Type Size Used Priority"
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let path = line.split_whitespace().next().map(unescape_octal);
            match path {
                Some(path) => {
                    let kind = resolve(&path);
                    SwapEntry { path, kind }
                }
                None => SwapEntry {
                    path: line.to_owned(),
                    kind: SwapKind::Unknown,
                },
            }
        })
        .collect()
}

/// Decodes the kernel's `\NNN` octal escapes (used for spaces etc.).
fn unescape_octal(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        let escaped = (b == b'\\')
            .then(|| bytes.get(i.saturating_add(1)..i.saturating_add(4)))
            .flatten()
            .and_then(decode_octal3);
        if let Some(v) = escaped {
            out.push(v);
            i = i.saturating_add(4);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes exactly three octal digits into a byte, if valid and `<= 0o377`.
fn decode_octal3(digits: &[u8]) -> Option<u8> {
    if digits.len() != 3 || !digits.iter().all(|c| (b'0'..=b'7').contains(c)) {
        return None;
    }
    let s = core::str::from_utf8(digits).ok()?;
    u8::from_str_radix(s, 8).ok()
}

/// Resolves a swap path to its kind using `/sys`.
pub(crate) fn resolve_kind(path: &str) -> SwapKind {
    use std::os::unix::fs::MetadataExt;

    let p = Path::new(path);
    let canonical = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let name = canonical
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    if canonical.starts_with("/dev") {
        if name.starts_with("zram") {
            return SwapKind::Ram;
        }
        if name.starts_with("dm-") {
            return dm_kind(&format!("/sys/block/{name}/dm/uuid"));
        }
        return SwapKind::Unknown;
    }

    // A swap file: find its backing block device through st_dev.
    let Ok(meta) = std::fs::metadata(&canonical) else {
        return SwapKind::Unknown;
    };
    let dev = meta.dev();
    let (major, minor) = (rustix::fs::major(dev), rustix::fs::minor(dev));
    dm_kind(&format!("/sys/dev/block/{major}:{minor}/dm/uuid"))
}

fn dm_kind(uuid_path: &str) -> SwapKind {
    match std::fs::read_to_string(uuid_path) {
        Ok(uuid) if uuid.trim_start().starts_with("CRYPT-") => SwapKind::Encrypted,
        _ => SwapKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";

    #[test]
    fn no_swap() {
        assert!(classify_swaps(HEADER, |_| SwapKind::Unknown).is_empty());
    }

    #[test]
    fn classifies_with_resolver() {
        let s = format!(
            "{HEADER}/dev/zram0 partition 8G 0 100\n/dev/dm-1 partition 4G 0 -2\n/swap\\040file file 1G 0 -3\n"
        );
        let got = classify_swaps(&s, |p| match p {
            "/dev/zram0" => SwapKind::Ram,
            "/dev/dm-1" => SwapKind::Encrypted,
            _ => SwapKind::Unknown,
        });
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].kind, SwapKind::Ram);
        assert_eq!(got[1].kind, SwapKind::Encrypted);
        assert_eq!(got[2].path, "/swap file");
        assert_eq!(got[2].kind, SwapKind::Unknown);
        assert!(!got[2].kind.is_safe());
    }

    #[test]
    fn unescape_handles_truncated_and_invalid() {
        assert_eq!(unescape_octal("a\\04"), "a\\04");
        assert_eq!(unescape_octal("a\\999"), "a\\999");
        assert_eq!(unescape_octal("\\"), "\\");
        assert_eq!(unescape_octal("x\\040y"), "x y");
        assert_eq!(unescape_octal("\\+12"), "\\+12");
        assert_eq!(unescape_octal("\\400"), "\\400");
    }
}
