use hickory_proto::rr::Name;
use std::str::FromStr;

pub struct SafeSearchMapping {
    pub pattern: &'static str,
    pub target: &'static str,
}

pub static MAPPINGS: &[SafeSearchMapping] = &[
    SafeSearchMapping {
        pattern: "google.com.",
        target: "forcesafesearch.google.com.",
    },
    SafeSearchMapping {
        pattern: "www.google.com.",
        target: "forcesafesearch.google.com.",
    },
    SafeSearchMapping {
        pattern: "youtube.com.",
        target: "restrict.youtube.com.",
    },
    SafeSearchMapping {
        pattern: "www.youtube.com.",
        target: "restrict.youtube.com.",
    },
    SafeSearchMapping {
        pattern: "m.youtube.com.",
        target: "restrict.youtube.com.",
    },
    SafeSearchMapping {
        pattern: "youtube-nocookie.com.",
        target: "restrict.youtube.com.",
    },
    SafeSearchMapping {
        pattern: "www.youtube-nocookie.com.",
        target: "restrict.youtube.com.",
    },
    SafeSearchMapping {
        pattern: "bing.com.",
        target: "strict.bing.com.",
    },
    SafeSearchMapping {
        pattern: "www.bing.com.",
        target: "strict.bing.com.",
    },
];

/// Returns the target for explicitly listed Google/YouTube/Bing names,
/// including bare domains. Unrelated subdomains must not be rewritten.
pub fn get_safesearch_target(domain: &Name) -> Option<Name> {
    let query_str = domain.to_utf8().to_lowercase();

    for mapping in MAPPINGS {
        if query_str == mapping.pattern
            && let Ok(name) = Name::from_str(mapping.target)
        {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bare_domain_is_rewritten() {
        let target = get_safesearch_target(&Name::from_str("google.com.").unwrap());
        assert_eq!(
            target,
            Some(Name::from_str("forcesafesearch.google.com.").unwrap())
        );

        let target = get_safesearch_target(&Name::from_str("youtube.com.").unwrap());
        assert_eq!(
            target,
            Some(Name::from_str("restrict.youtube.com.").unwrap())
        );

        let target = get_safesearch_target(&Name::from_str("bing.com.").unwrap());
        assert_eq!(target, Some(Name::from_str("strict.bing.com.").unwrap()));
    }

    #[test]
    fn test_www_subdomain_is_rewritten() {
        let target = get_safesearch_target(&Name::from_str("www.google.com.").unwrap());
        assert_eq!(
            target,
            Some(Name::from_str("forcesafesearch.google.com.").unwrap())
        );
    }

    #[test]
    fn test_unrelated_subdomain_is_not_rewritten() {
        assert_eq!(
            get_safesearch_target(&Name::from_str("mail.google.com.").unwrap()),
            None
        );
        assert_eq!(
            get_safesearch_target(&Name::from_str("example.com.").unwrap()),
            None
        );
    }
}
