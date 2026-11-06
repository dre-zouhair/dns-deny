use crate::{FilterRule, RuleAction, RuleType, normalize_domain};

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
        let mut line = line.trim();
        if let Some(pos) = line.find('#') {
            line = line[..pos].trim();
        }
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        if tokens[0].parse::<std::net::IpAddr>().is_ok()
            || tokens[0] == "127.0.0.1"
            || tokens[0] == "0.0.0.0"
        {
            for token in &tokens[1..] {
                if *token == "localhost" || *token == "localhost.localdomain" {
                    continue;
                }
                if let Some(normalized) = normalize_domain(token) {
                    if rules.len() >= max_rules {
                        return Err(crate::IngestError::LimitExceeded("source rule count"));
                    }
                    rules.push(FilterRule {
                        pattern: normalized,
                        action: default_action,
                        rule_type: RuleType::Exact,
                    });
                }
            }
        }
    }
    Ok(rules)
}
