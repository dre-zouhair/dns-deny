use crate::{FilterRule, RuleAction, RuleType, normalize_domain};
use rusqlite::Connection;
use std::path::Path;

pub fn parse<P: AsRef<Path>>(path: P) -> Result<Vec<FilterRule>, crate::IngestError> {
    parse_limited(path, crate::MAX_SOURCE_RULES)
}

pub fn parse_limited<P: AsRef<Path>>(
    path: P,
    max_rules: usize,
) -> Result<Vec<FilterRule>, crate::IngestError> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.pragma_update(None, "trusted_schema", false)?;
    let mut rules = Vec::new();

    if let Ok(mut stmt) = conn.prepare("SELECT type, domain FROM domainlist WHERE enabled = 1") {
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            // Skip malformed rows without discarding the rest of a large import.
            let rule_type_code: i32 = match row.get(0) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let domain: String = match row.get(1) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if domain.len() > crate::MAX_RULE_LINE_BYTES {
                return Err(crate::IngestError::LimitExceeded("pattern bytes"));
            }
            let (action, rule_type) = match rule_type_code {
                0 => (RuleAction::Allow, RuleType::Exact),
                1 => (RuleAction::Deny, RuleType::Exact),
                2 => (RuleAction::Allow, RuleType::Regex),
                3 => (RuleAction::Deny, RuleType::Regex),
                _ => continue,
            };

            let pattern = if rule_type == RuleType::Exact {
                if let Some(normalized) = normalize_domain(&domain) {
                    normalized
                } else {
                    continue;
                }
            } else if regex::Regex::new(&domain).is_ok() {
                // Pi-hole regexes are POSIX ERE; skip any that aren't valid
                // Rust regexes, same as the plain regex-list parser does.
                domain
            } else {
                continue;
            };

            if rules.len() >= max_rules {
                return Err(crate::IngestError::LimitExceeded("source rule count"));
            }
            rules.push(FilterRule {
                pattern,
                action,
                rule_type,
            });
        }
    }

    let table_exists: bool = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='gravity'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
        > 0;

    if table_exists && let Ok(mut stmt) = conn.prepare("SELECT domain FROM gravity") {
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let domain: String = match row.get(0) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(normalized) = normalize_domain(&domain) {
                if rules.len() >= max_rules {
                    return Err(crate::IngestError::LimitExceeded("source rule count"));
                }
                rules.push(FilterRule {
                    pattern: normalized,
                    action: RuleAction::Deny,
                    rule_type: RuleType::Exact,
                });
            }
        }
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_row_does_not_abort_entire_import() {
        let path = std::env::temp_dir().join(format!(
            "dns-deny-test-gravity-{}-{}.db",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE domainlist (type INTEGER, domain TEXT, enabled INTEGER);
                 INSERT INTO domainlist (type, domain, enabled) VALUES (1, 'good1.example.com', 1);
                 INSERT INTO domainlist (type, domain, enabled) VALUES (1, NULL, 1);
                 INSERT INTO domainlist (type, domain, enabled) VALUES (1, 'good2.example.com', 1);",
            )
            .unwrap();
        }

        let rules = parse(&path).unwrap();
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(patterns.contains(&"good1.example.com"), "{patterns:?}");
        assert!(patterns.contains(&"good2.example.com"), "{patterns:?}");
        assert_eq!(
            rules.len(),
            2,
            "the NULL row should be skipped, not abort the whole import: {patterns:?}"
        );

        let _ = std::fs::remove_file(&path);
    }
}
