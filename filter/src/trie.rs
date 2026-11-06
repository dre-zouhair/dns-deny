use hickory_proto::rr::Name;
use std::collections::HashMap;

/// Longest DNS label permitted by RFC 1035.
const MAX_LABEL_LEN: usize = 63;

#[derive(Default, Debug)]
pub struct TrieNode {
    // Byte keys allow borrowed lookups from a reusable buffer without per-label allocations.
    pub children: HashMap<Vec<u8>, TrieNode>,
    pub is_terminal: bool,
}

impl TrieNode {
    pub fn insert(&mut self, labels: &[Vec<u8>]) {
        let mut current = self;
        for label in labels {
            current = current.children.entry(label.clone()).or_default();
        }
        current.is_terminal = true;
    }

    /// Walk the name from its TLD inward, using stack storage for each label.
    pub fn is_match(&self, name: &Name) -> bool {
        let mut current = self;
        let mut buf = [0u8; MAX_LABEL_LEN];

        for label in name.iter().rev() {
            if current.is_terminal {
                return true;
            }
            for (out, byte) in buf.iter_mut().zip(label) {
                *out = byte.to_ascii_lowercase();
            }
            match current.children.get(&buf[..label.len()]) {
                Some(next) => current = next,
                None => return false,
            }
        }

        current.is_terminal
    }
}

#[derive(Default, Debug)]
pub struct SubdomainTrie {
    pub allow_root: TrieNode,
    pub deny_root: TrieNode,
}

impl SubdomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert-side only. Building an owned label vector here is fine — it
    /// happens once per rule at snapshot-rebuild time, not per query.
    fn name_to_reversed_labels(name: &Name) -> Vec<Vec<u8>> {
        let mut labels: Vec<Vec<u8>> = name
            .iter()
            .map(|bytes| bytes.iter().map(u8::to_ascii_lowercase).collect())
            .collect();
        labels.reverse();
        labels
    }

    pub fn insert_allow(&mut self, name: &Name) {
        let labels = Self::name_to_reversed_labels(name);
        if !labels.is_empty() {
            self.allow_root.insert(&labels);
        }
    }

    pub fn insert_deny(&mut self, name: &Name) {
        let labels = Self::name_to_reversed_labels(name);
        if !labels.is_empty() {
            self.deny_root.insert(&labels);
        }
    }

    pub fn is_empty(&self) -> bool {
        Self::root_is_empty(&self.allow_root) && Self::root_is_empty(&self.deny_root)
    }

    fn root_is_empty(root: &TrieNode) -> bool {
        root.children.is_empty() && !root.is_terminal
    }

    pub fn has_allow(&self) -> bool {
        !Self::root_is_empty(&self.allow_root)
    }

    pub fn has_deny(&self) -> bool {
        !Self::root_is_empty(&self.deny_root)
    }

    pub fn check_allow(&self, name: &Name) -> bool {
        self.has_allow() && name.num_labels() > 0 && self.allow_root.is_match(name)
    }

    pub fn check_deny(&self, name: &Name) -> bool {
        self.has_deny() && name.num_labels() > 0 && self.deny_root.is_match(name)
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
    fn test_case_insensitive_match_without_string_labels() {
        let mut trie = SubdomainTrie::new();
        trie.insert_deny(&Name::from_str("Example.COM.").unwrap());

        assert!(trie.check_deny(&Name::from_str("example.com.").unwrap()));
        assert!(trie.check_deny(&Name::from_str("EXAMPLE.com.").unwrap()));
        assert!(trie.check_deny(&Name::from_str("sub.ExAmPlE.CoM.").unwrap()));
    }

    #[test]
    fn test_empty_roots_short_circuit() {
        let trie = SubdomainTrie::new();
        assert!(trie.is_empty());
        assert!(!trie.has_allow());
        assert!(!trie.has_deny());
        assert!(!trie.check_allow(&Name::from_str("anything.com.").unwrap()));
        assert!(!trie.check_deny(&Name::from_str("anything.com.").unwrap()));
    }

    #[test]
    fn test_sibling_label_does_not_match() {
        let mut trie = SubdomainTrie::new();
        trie.insert_deny(&Name::from_str("example.com.").unwrap());
        assert!(!trie.check_deny(&Name::from_str("notexample.com.").unwrap()));
        assert!(!trie.check_deny(&Name::from_str("example.org.").unwrap()));
    }

    #[test]
    fn test_root_name_is_not_matched_against_empty_label_set() {
        let mut trie = SubdomainTrie::new();
        trie.insert_deny(&Name::from_str("example.com.").unwrap());
        // The root name has no labels; it must not be treated as a match.
        assert!(!trie.check_deny(&Name::root()));
    }
}
