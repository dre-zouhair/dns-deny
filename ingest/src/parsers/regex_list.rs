use crate::{FilterRule, RuleAction, RuleType};

pub fn parse(content: &str, default_action: RuleAction) -> Vec<FilterRule> {
    parse_limited(content, default_action, usize::MAX).expect("unlimited parser")
}

pub fn parse_limited(
    content: &str,
    default_action: RuleAction,
    max_rules: usize,
) -> Result<Vec<FilterRule>, crate::IngestError> {
    let mut rules = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        if regex::Regex::new(line).is_ok() {
            if rules.len() >= max_rules {
                return Err(crate::IngestError::LimitExceeded("source rule count"));
            }
            rules.push(FilterRule {
                pattern: line.to_string(),
                action: default_action,
                rule_type: RuleType::Regex,
            });
        }
    }
    Ok(rules)
}
