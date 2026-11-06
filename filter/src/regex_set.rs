use hickory_proto::rr::Name;
use regex::{RegexSet, RegexSetBuilder};

pub struct RegexFilter {
    allow_set: Vec<RegexSet>,
    deny_set: Vec<RegexSet>,
}

impl RegexFilter {
    /// A filter with no allow or deny patterns.
    pub fn empty() -> Self {
        Self {
            allow_set: Vec::new(),
            deny_set: Vec::new(),
        }
    }

    pub fn new(allow_patterns: &[String], deny_patterns: &[String]) -> Result<Self, regex::Error> {
        // Split oversized sets rather than disabling unrelated valid rules.
        fn compile(
            patterns: &[String],
            output: &mut Vec<RegexSet>,
            remaining: &mut usize,
        ) -> Result<(), regex::Error> {
            if patterns.is_empty() {
                return Ok(());
            }
            if *remaining == 0 {
                return Err(regex::Error::CompiledTooBig(80 * 1024 * 1024));
            }
            match RegexSetBuilder::new(patterns)
                .case_insensitive(true)
                .build()
            {
                Ok(set) => {
                    output.push(set);
                    *remaining -= 1;
                    Ok(())
                }
                Err(error) if patterns.len() == 1 => Err(error),
                Err(_) => {
                    let middle = patterns.len() / 2;
                    compile(&patterns[..middle], output, remaining)?;
                    compile(&patterns[middle..], output, remaining)
                }
            }
        }
        let mut allow_set = Vec::new();
        let mut deny_set = Vec::new();
        let mut remaining = 8;
        compile(allow_patterns, &mut allow_set, &mut remaining)?;
        compile(deny_patterns, &mut deny_set, &mut remaining)?;
        Ok(Self {
            allow_set,
            deny_set,
        })
    }

    /// Strips the FQDN trailing dot so `$`-anchored blocklist patterns match.
    /// Lowercases directly into one String without cloning the Name.
    pub fn name_str(name: &Name) -> String {
        let mut s = name.to_string();
        s.make_ascii_lowercase();
        if s.ends_with('.') {
            s.truncate(s.len() - 1);
        }
        s
    }

    pub fn has_allow(&self) -> bool {
        !self.allow_set.is_empty()
    }

    pub fn has_deny(&self) -> bool {
        !self.deny_set.is_empty()
    }

    /// True when no patterns are loaded in either direction, so callers can
    /// skip building the query string entirely.
    pub fn is_empty(&self) -> bool {
        self.allow_set.is_empty() && self.deny_set.is_empty()
    }

    /// Accepts a preformatted name so checking both directions needs only one allocation.
    pub fn check_allow_str(&self, name_str: &str) -> bool {
        self.allow_set.iter().any(|allow| allow.is_match(name_str))
    }

    pub fn check_deny_str(&self, name_str: &str) -> bool {
        self.deny_set.iter().any(|deny| deny.is_match(name_str))
    }

    pub fn check_allow(&self, name: &Name) -> bool {
        !self.allow_set.is_empty() && self.check_allow_str(&Self::name_str(name))
    }

    pub fn check_deny(&self, name: &Name) -> bool {
        !self.deny_set.is_empty() && self.check_deny_str(&Self::name_str(name))
    }

    pub fn check(&self, name: &Name) -> Option<bool> {
        if self.is_empty() {
            return None;
        }

        let name_str = Self::name_str(name);

        if self.check_allow_str(&name_str) {
            return Some(true);
        }

        if self.check_deny_str(&name_str) {
            return Some(false);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_dollar_anchored_pattern_matches_fqdn_query() {
        let filter = RegexFilter::new(&[], &[r"\.doubleclick\.net$".to_string()]).unwrap();
        let name = Name::from_str("ad.doubleclick.net.").unwrap();
        assert!(name.is_fqdn());
        assert!(filter.check_deny(&name));
    }

    #[test]
    fn test_uppercase_pattern_matches_lowercase_query() {
        let filter = RegexFilter::new(&[], &[r"^Ads\.".to_string()]).unwrap();
        let name = Name::from_str("ads.example.com.").unwrap();
        assert!(filter.check_deny(&name));
    }
}
