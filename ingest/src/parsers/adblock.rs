use crate::{FilterRule, RuleAction, RuleType, normalize_domain};

pub fn parse(content: &str) -> Vec<FilterRule> {
    parse_limited(content, usize::MAX).expect("unlimited parser")
}

pub fn parse_limited(
    content: &str,
    max_rules: usize,
) -> Result<Vec<FilterRule>, crate::IngestError> {
    let mut rules = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }

        let mut is_allow = false;
        let domain_part;

        if let Some(stripped) = line.strip_prefix("@@||") {
            is_allow = true;
            domain_part = stripped;
        } else if let Some(stripped) = line.strip_prefix("||") {
            domain_part = stripped;
        } else {
            continue;
        }

        // DNS has no referring page, resource type, or party context. Never
        // broaden a contextual browser exception into a global DNS allow.
        // `important` changes priority, not scope; all other unsupported
        // modifiers (including badfilter) must leave the rule unapplied.
        if let Some((_, options)) = domain_part.split_once('$')
            && !options.split(',').all(|option| option == "important")
        {
            continue;
        }

        // Adblock rules may omit '^'; '$' still terminates the domain before options.
        let end = domain_part.find(['^', '$']).unwrap_or(domain_part.len());
        let domain = &domain_part[..end];

        // Reject path/element-selector rules — not domain-applicable.
        if domain.contains('/') || domain.contains('*') || domain.contains('#') {
            continue;
        }

        if let Some(normalized) = normalize_domain(domain) {
            if rules.len() >= max_rules {
                return Err(crate::IngestError::LimitExceeded("source rule count"));
            }
            rules.push(FilterRule {
                pattern: normalized,
                action: if is_allow {
                    RuleAction::Allow
                } else {
                    RuleAction::Deny
                },
                rule_type: RuleType::Exact,
            });
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contextual_exceptions_and_badfilter_are_never_broadened() {
        let rules = parse(
            "||tracker.example^\n@@||tracker.example^$domain=trusted.example\n@@||tracker.example^$third-party\n@@||tracker.example^$badfilter\n||unrelated.example^$script\n",
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern, "tracker.example");
        assert_eq!(rules[0].action, RuleAction::Deny);
        let rules = parse("@@||trusted.example^\n");
        assert_eq!(rules[0].action, RuleAction::Allow);
    }

    #[test]
    fn test_caret_less_rule_is_not_dropped() {
        let rules = parse("||example.com\n");
        assert_eq!(rules.len(), 1, "{rules:?}");
        assert_eq!(rules[0].pattern, "example.com");
        assert_eq!(rules[0].action, RuleAction::Deny);
    }

    #[test]
    fn test_option_separator_without_caret_is_not_dropped() {
        let rules = parse("||example.com$important\n");
        assert_eq!(rules.len(), 1, "{rules:?}");
        assert_eq!(rules[0].pattern, "example.com");
    }

    #[test]
    fn test_caret_terminated_rule_still_works() {
        let rules = parse("||example.com^\n");
        assert_eq!(rules.len(), 1, "{rules:?}");
        assert_eq!(rules[0].pattern, "example.com");
    }

    #[test]
    fn test_allowlist_prefix_still_works() {
        let rules = parse("@@||example.com\n");
        assert_eq!(rules.len(), 1, "{rules:?}");
        assert_eq!(rules[0].action, RuleAction::Allow);
    }

    #[test]
    fn test_path_and_element_rules_are_rejected() {
        let rules = parse("||example.com/path\n||example.com/*\nexample.com##.ad-banner\n");
        assert!(rules.is_empty(), "{rules:?}");
    }
}
