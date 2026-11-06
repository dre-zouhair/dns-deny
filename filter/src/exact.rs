use hickory_proto::rr::Name;
use std::collections::HashSet;

#[derive(Default, Debug)]
pub struct ExactFilter {
    pub allow: HashSet<Name>,
    pub deny: HashSet<Name>,
}

impl ExactFilter {
    pub fn new() -> Self {
        Self::default()
    }

    // Name equality and hashing include is_fqdn. Normalize inserted and queried
    // names so dot-stripped imports match absolute names received on the wire.
    pub fn insert_allow(&mut self, mut name: Name) {
        name.set_fqdn(true);
        self.allow.insert(name);
    }

    pub fn insert_deny(&mut self, mut name: Name) {
        name.set_fqdn(true);
        self.deny.insert(name);
    }

    /// Borrows wire-format FQDN names; only non-FQDN callers need a normalized clone.
    fn contains(set: &HashSet<Name>, name: &Name) -> bool {
        if set.is_empty() {
            return false;
        }
        if name.is_fqdn() {
            return set.contains(name);
        }
        let mut key = name.clone();
        key.set_fqdn(true);
        set.contains(&key)
    }

    pub fn check_allow(&self, name: &Name) -> bool {
        Self::contains(&self.allow, name)
    }

    pub fn check_deny(&self, name: &Name) -> bool {
        Self::contains(&self.deny, name)
    }

    pub fn has_allow(&self) -> bool {
        !self.allow.is_empty()
    }

    pub fn has_deny(&self) -> bool {
        !self.deny.is_empty()
    }

    pub fn check(&self, name: &Name) -> Option<bool> {
        if self.check_allow(name) {
            Some(true)
        } else if self.check_deny(name) {
            Some(false)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_non_fqdn_insert_matches_fqdn_lookup() {
        // Ingestion strips the trailing dot; wire queries retain FQDN status.
        let mut filter = ExactFilter::new();
        let pattern_name = Name::from_str("blocked.example.com").unwrap();
        assert!(!pattern_name.is_fqdn());
        filter.insert_deny(pattern_name);

        let query_name = Name::from_str("blocked.example.com.").unwrap();
        assert!(query_name.is_fqdn());
        assert_eq!(filter.check(&query_name), Some(false));
    }
}
