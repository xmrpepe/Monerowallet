//! Accounts and subaddresses.
//!
//! The scanner looks ahead the same distance as wallet2 by default (50
//! accounts × 200 addresses beyond the highest used), so funds sent to any
//! address the reference wallet would have generated are found when a wallet
//! is restored (differentially tested).

use monero_wallet::Scanner;
use monero_wallet::address::SubaddressIndex;

/// wallet2 default major lookahead.
pub const LOOKAHEAD_ACCOUNTS: u32 = 50;
/// wallet2 default minor lookahead.
pub const LOOKAHEAD_ADDRESSES: u32 = 200;
/// Hard limits, to bound scanner memory and label storage.
pub const MAX_ACCOUNTS: u32 = 1_000;
/// See [`MAX_ACCOUNTS`].
pub const MAX_ADDRESSES_PER_ACCOUNT: u32 = 100_000;
/// Maximum label length in bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// One account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// User label (sanitised, bounded).
    pub label: String,
    /// Number of addresses handed out or seen in use (index 0 always exists).
    pub addresses: u32,
}

/// All accounts of a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubaddressBook {
    accounts: Vec<Account>,
}

impl Default for SubaddressBook {
    fn default() -> Self {
        Self {
            accounts: vec![Account {
                label: "Primary account".into(),
                addresses: 1,
            }],
        }
    }
}

/// Strips control characters (terminal escape injection, T-UI-TERM) and bounds length.
#[must_use]
pub fn sanitize_label(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len().saturating_add(c.len_utf8()) > MAX_LABEL_LEN {
            break;
        }
        out.push(c);
    }
    out
}

impl SubaddressBook {
    /// Builds a book from stored accounts.
    #[must_use]
    pub fn from_accounts(accounts: Vec<Account>) -> Self {
        if accounts.is_empty() {
            Self::default()
        } else {
            Self { accounts }
        }
    }

    /// Accounts.
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Adds an account. Returns its index, or `None` at the limit.
    pub fn add_account(&mut self, label: &str) -> Option<u32> {
        let idx = u32::try_from(self.accounts.len()).ok()?;
        if idx >= MAX_ACCOUNTS {
            return None;
        }
        self.accounts.push(Account {
            label: sanitize_label(label),
            addresses: 1,
        });
        Some(idx)
    }

    /// Hands out the next unused address index of `account`.
    pub fn next_address(&mut self, account: u32) -> Option<u32> {
        let a = self.accounts.get_mut(usize::try_from(account).ok()?)?;
        if a.addresses >= MAX_ADDRESSES_PER_ACCOUNT {
            return None;
        }
        let idx = a.addresses;
        a.addresses = a.addresses.saturating_add(1);
        Some(idx)
    }

    /// Records that `(account, index)` received funds; grows the book so
    /// the lookahead window moves forward (wallet2 behaviour). Returns
    /// whether the registration window changed.
    pub fn mark_used(&mut self, account: u32, index: u32) -> bool {
        if account >= MAX_ACCOUNTS || index >= MAX_ADDRESSES_PER_ACCOUNT {
            return false;
        }
        let mut grew = false;
        while u32::try_from(self.accounts.len()).unwrap_or(u32::MAX) <= account {
            let n = self.accounts.len();
            self.accounts.push(Account {
                label: format!("Account #{n}"),
                addresses: 1,
            });
            grew = true;
        }
        if let Some(a) = usize::try_from(account)
            .ok()
            .and_then(|i| self.accounts.get_mut(i))
        {
            let needed = index.saturating_add(1);
            if a.addresses < needed {
                a.addresses = needed;
                grew = true;
            }
        }
        grew
    }

    /// Every index the scanner must watch: used ones plus the lookahead.
    #[must_use]
    pub fn watch_set(&self) -> Vec<SubaddressIndex> {
        let n_acc = u32::try_from(self.accounts.len()).unwrap_or(MAX_ACCOUNTS);
        let max_used = self.accounts.iter().map(|a| a.addresses).max().unwrap_or(1);
        let acc_end = n_acc.saturating_add(LOOKAHEAD_ACCOUNTS).min(MAX_ACCOUNTS);
        let addr_end = max_used
            .saturating_add(LOOKAHEAD_ADDRESSES)
            .min(MAX_ADDRESSES_PER_ACCOUNT);
        let mut out = Vec::new();
        for account in 0..acc_end {
            for index in 0..addr_end {
                if let Some(i) = SubaddressIndex::new(account, index) {
                    out.push(i);
                }
            }
        }
        out
    }

    /// Registers [`Self::watch_set`] with `scanner`.
    pub fn register(&self, scanner: &mut Scanner) {
        for i in self.watch_set() {
            scanner.register_subaddress(i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookahead_matches_wallet2_defaults() {
        let b = SubaddressBook::default();
        let w = b.watch_set();
        // 51 accounts × 201 addresses, minus the primary (0,0).
        assert_eq!(w.len(), 51 * 201 - 1);
    }

    #[test]
    fn mark_used_grows_window() {
        let mut b = SubaddressBook::default();
        assert!(b.mark_used(2, 10));
        assert_eq!(b.accounts().len(), 3);
        assert_eq!(b.accounts()[2].addresses, 11);
        assert!(!b.mark_used(2, 5));
        assert!(!b.mark_used(MAX_ACCOUNTS, 0));
    }

    #[test]
    fn labels_sanitised() {
        assert_eq!(sanitize_label("a\u{1b}[31mb\n"), "a[31mb");
        assert_eq!(sanitize_label(&"x".repeat(200)).len(), MAX_LABEL_LEN);
    }
}
