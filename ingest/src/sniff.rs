#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum BlocklistFormat {
    GravityDb,
    PlainList,
    HostsFile,
    AdblockSyntax,
    RegexList,
}

pub fn sniff_format(bytes: &[u8]) -> BlocklistFormat {
    if bytes.starts_with(b"SQLite format 3\0") {
        return BlocklistFormat::GravityDb;
    }

    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return BlocklistFormat::PlainList,
    };

    let non_comment_lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
        .take(50)
        .collect();

    if non_comment_lines.is_empty() {
        return BlocklistFormat::PlainList;
    }

    let mut adblock_score = 0;
    let mut hosts_score = 0;
    let mut regex_score = 0;
    let mut plain_score = 0;

    for line in &non_comment_lines {
        if line.starts_with("||") || line.contains("##") || line.contains("#@#") {
            adblock_score += 1;
        } else {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 2
                && (tokens[0] == "127.0.0.1"
                    || tokens[0] == "0.0.0.0"
                    || tokens[0].parse::<std::net::IpAddr>().is_ok())
            {
                hosts_score += 1;
            } else if line.contains('^')
                || line.contains('$')
                || line.contains('*')
                || line.contains('|')
            {
                regex_score += 1;
            } else {
                plain_score += 1;
            }
        }
    }

    // Vote across the sample so one stray format marker cannot misclassify the file.
    // Ties favor adblock, hosts, regex, then plain domains.
    let candidates = [
        (BlocklistFormat::PlainList, plain_score),
        (BlocklistFormat::RegexList, regex_score),
        (BlocklistFormat::HostsFile, hosts_score),
        (BlocklistFormat::AdblockSyntax, adblock_score),
    ];

    candidates
        .into_iter()
        .max_by_key(|(_, score)| *score)
        .map(|(fmt, _)| fmt)
        .unwrap_or(BlocklistFormat::PlainList)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_stray_adblock_like_line_does_not_flip_a_plain_list() {
        // 9 plain domains plus 1 line with an inline "##" substring that
        // isn't filtered as a comment (comment stripping only checks the
        // start of the line).
        let content = "a1.example.com\n\
                        a2.example.com\n\
                        a3.example.com\n\
                        a4.example.com\n\
                        a5.example.com\n\
                        a6.example.com\n\
                        a7.example.com\n\
                        a8.example.com\n\
                        a9.example.com\n\
                        weird##domain.example.com\n";
        assert_eq!(sniff_format(content.as_bytes()), BlocklistFormat::PlainList);
    }

    #[test]
    fn test_majority_adblock_still_detected() {
        let content =
            "||a1.example.com^\n||a2.example.com^\n||a3.example.com^\nplain.example.com\n";
        assert_eq!(
            sniff_format(content.as_bytes()),
            BlocklistFormat::AdblockSyntax
        );
    }

    #[test]
    fn test_majority_hosts_still_detected() {
        let content = "0.0.0.0 a1.example.com\n0.0.0.0 a2.example.com\n0.0.0.0 a3.example.com\nplain.example.com\n";
        assert_eq!(sniff_format(content.as_bytes()), BlocklistFormat::HostsFile);
    }
}
