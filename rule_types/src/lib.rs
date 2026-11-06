//! Shared, dependency-light types for describing filter rules and
//! normalizing domain names.
//!
//! Kept separate from ingestion so type-only consumers avoid parser and SQLite dependencies.

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleType {
    Exact,
    Regex,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilterRule {
    pub pattern: String,
    pub action: RuleAction,
    pub rule_type: RuleType,
}

/// Normalizes a domain name: trims whitespace, strips trailing dots, lowercases,
/// and converts internationalized domain names (IDN) to punycode/ascii.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return None;
    }

    match idna::domain_to_ascii(domain) {
        Ok(ascii) => Some(ascii.to_lowercase()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain_trims_case_and_trailing_dot() {
        assert_eq!(
            normalize_domain("  Example.COM.  "),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_normalize_domain_rejects_empty() {
        assert_eq!(normalize_domain("   ."), None);
    }

    #[test]
    fn test_normalize_domain_converts_idn_to_punycode() {
        let result = normalize_domain("münchen.de").unwrap();
        assert!(
            result.starts_with("xn--"),
            "expected punycode, got {result}"
        );
    }
}
