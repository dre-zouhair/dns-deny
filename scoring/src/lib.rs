use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainVerdict {
    Normal,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResult {
    pub domain: String,
    pub score: f64,
    pub entropy: f64,
    pub digit_ratio: f64,
    pub hyphen_ratio: f64,
    pub subdomain_depth: usize,
    pub verdict: DomainVerdict,
}

pub struct DomainScorer {
    pub suspicious_threshold: f64,
    pub malicious_threshold: f64,
}

impl Default for DomainScorer {
    fn default() -> Self {
        Self {
            suspicious_threshold: 0.70,
            malicious_threshold: 0.85,
        }
    }
}

impl DomainScorer {
    pub fn new(suspicious_threshold: f64, malicious_threshold: f64) -> Self {
        Self {
            suspicious_threshold,
            malicious_threshold,
        }
    }

    /// Calculates Shannon entropy of a string: H(X) = - sum(P(x) * log2(P(x)))
    pub fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut frequencies = HashMap::new();
        let len = s.chars().count() as f64;

        for ch in s.chars() {
            *frequencies.entry(ch).or_insert(0f64) += 1.0;
        }

        let mut entropy = 0.0;
        for count in frequencies.values() {
            let p = count / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Ratio of numeric digits to character count, matching the entropy denominator
    /// even for multibyte input.
    pub fn calculate_digit_ratio(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let len = s.chars().count() as f64;
        let digits = s.chars().filter(|c| c.is_ascii_digit()).count();
        digits as f64 / len
    }

    /// Calculates ratio of hyphens to total character length (char count,
    /// see `calculate_digit_ratio`).
    pub fn calculate_hyphen_ratio(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let len = s.chars().count() as f64;
        let hyphens = s.chars().filter(|c| *c == '-').count();
        hyphens as f64 / len
    }

    /// Evaluates a domain name and returns a heuristic score result
    pub fn score_domain(&self, domain: &str) -> ScoreResult {
        let clean_domain = domain.trim_end_matches('.').to_lowercase();
        let labels: Vec<&str> = clean_domain.split('.').collect();
        let subdomain_depth = labels.len().saturating_sub(2);

        // Score only the second-level label: subdomains must not dilute a DGA
        // label or inflate the score of a legitimate host.
        let main_part = if labels.len() >= 2 {
            labels[labels.len() - 2].to_string()
        } else {
            clean_domain.clone()
        };

        let entropy = Self::calculate_entropy(&main_part);
        let digit_ratio = Self::calculate_digit_ratio(&main_part);
        let hyphen_ratio = Self::calculate_hyphen_ratio(&main_part);

        // Entropy above 3.0 contributes to risk score (English text is ~2.5-3.0)
        let entropy_score = if entropy > 3.0 {
            ((entropy - 3.0) / 1.5).min(1.0) * 0.50
        } else {
            0.0
        };

        let digit_score = (digit_ratio * 3.0).min(1.0) * 0.35;
        let hyphen_score = (hyphen_ratio * 4.0).min(1.0) * 0.25;

        let main_part_len = main_part.chars().count();
        let length_penalty = if main_part_len > 18 {
            ((main_part_len - 18) as f64 / 20.0).min(1.0) * 0.20
        } else {
            0.0
        };

        let combined_score = (entropy_score + digit_score + hyphen_score + length_penalty).min(1.0);

        let verdict = if combined_score >= self.malicious_threshold {
            DomainVerdict::Malicious
        } else if combined_score >= self.suspicious_threshold {
            DomainVerdict::Suspicious
        } else {
            DomainVerdict::Normal
        };

        ScoreResult {
            domain: clean_domain,
            score: (combined_score * 100.0).round() / 100.0,
            entropy: (entropy * 100.0).round() / 100.0,
            digit_ratio: (digit_ratio * 100.0).round() / 100.0,
            hyphen_ratio: (hyphen_ratio * 100.0).round() / 100.0,
            subdomain_depth,
            verdict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legitimate_domains_are_normal() {
        let scorer = DomainScorer::default();

        let google = scorer.score_domain("google.com");
        assert_eq!(google.verdict, DomainVerdict::Normal);
        assert!(google.score < 0.50);

        let github = scorer.score_domain("github.com");
        assert_eq!(github.verdict, DomainVerdict::Normal);

        let wikipedia = scorer.score_domain("wikipedia.org");
        assert_eq!(wikipedia.verdict, DomainVerdict::Normal);
    }

    #[test]
    fn test_dga_suspicious_domain() {
        let scorer = DomainScorer::default();

        let dga = scorer.score_domain("x89qzk-71a-99m-w1m8928173491-dga.biz");
        assert!(dga.score >= 0.70);
        assert!(
            dga.verdict == DomainVerdict::Suspicious || dga.verdict == DomainVerdict::Malicious
        );
    }

    #[test]
    fn test_main_part_is_only_second_level_label() {
        let scorer = DomainScorer::default();

        // Subdomains must not add a length or entropy penalty to "github".
        let legit = scorer.score_domain("cdn.assets.static.github.com");
        assert_eq!(legit.verdict, DomainVerdict::Normal);

        // Normal-looking subdomains must not dilute the DGA label.
        let bare = scorer.score_domain("x89qzk-71a-99m-w1m8928173491-dga.biz");
        let buried = scorer.score_domain("www.mail.x89qzk-71a-99m-w1m8928173491-dga.biz");
        assert_eq!(bare.score, buried.score);
        assert!(buried.score >= 0.70);
    }

    #[test]
    fn test_entropy_calculation() {
        let entropy_empty = DomainScorer::calculate_entropy("");
        assert_eq!(entropy_empty, 0.0);

        let entropy_simple = DomainScorer::calculate_entropy("aaaa");
        assert_eq!(entropy_simple, 0.0);

        let entropy_rand = DomainScorer::calculate_entropy("abcdefgh");
        assert!(entropy_rand > 2.9);
    }
}
