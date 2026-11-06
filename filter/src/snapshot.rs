use crate::exact::ExactFilter;
use crate::regex_set::RegexFilter;
use crate::trie::SubdomainTrie;
use hickory_proto::rr::Name;

pub struct FilterSnapshot {
    pub exact: ExactFilter,
    pub trie: SubdomainTrie,
    pub regex: RegexFilter,
}

impl FilterSnapshot {
    pub fn new(exact: ExactFilter, trie: SubdomainTrie, regex: RegexFilter) -> Self {
        Self { exact, trie, regex }
    }

    pub fn check(&self, name: &Name) -> Option<bool> {
        // Format only when a regex direction is actually reached, and reuse it.
        let regex_str = std::cell::OnceCell::new();
        let regex_name = || regex_str.get_or_init(|| RegexFilter::name_str(name));

        // Allows take precedence across all tiers, including a broad trie allow
        // paired with an exact deny from a different list.
        if self.exact.check_allow(name)
            || self.trie.check_allow(name)
            || (self.regex.has_allow() && self.regex.check_allow_str(regex_name()))
        {
            return Some(true);
        }

        if self.exact.check_deny(name)
            || self.trie.check_deny(name)
            || (self.regex.has_deny() && self.regex.check_deny_str(regex_name()))
        {
            return Some(false);
        }

        None
    }
}
