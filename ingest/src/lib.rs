pub mod parsers;
pub mod sniff;

use std::io::{Read, Write};
use std::path::Path;

/// Bounds downloads, local files and cached imports equally.
pub const MAX_SOURCE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SOURCE_RULES: usize = 1_000_000;
pub const MAX_RULE_LINE_BYTES: usize = 16 * 1024;

// Preserve the ingest API while allowing type-only consumers to depend on rule_types.
pub use rule_types::{FilterRule, RuleAction, RuleType, normalize_domain};

#[derive(Debug)]
pub enum IngestError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    LimitExceeded(&'static str),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Io(e) => write!(f, "I/O error reading blocklist source: {}", e),
            IngestError::Sqlite(e) => write!(f, "SQLite error parsing gravity.db source: {}", e),
            IngestError::LimitExceeded(reason) => {
                write!(f, "blocklist import limit exceeded: {reason}")
            }
        }
    }
}

impl std::error::Error for IngestError {}

impl From<std::io::Error> for IngestError {
    fn from(e: std::io::Error) -> Self {
        IngestError::Io(e)
    }
}

impl From<rusqlite::Error> for IngestError {
    fn from(e: rusqlite::Error) -> Self {
        IngestError::Sqlite(e)
    }
}

/// Where `ingest_source` should read a blocklist source's content from.
pub enum SourceData<'a> {
    /// A real file already on disk (e.g. a locally-configured blocklist
    /// path). Required for `GravityDb`, which needs direct SQLite file
    /// access rather than an in-memory buffer -- for text formats, the file
    /// is read fresh from this path.
    Path(&'a Path),
    /// Content already fetched into memory (e.g. an HTTP response body).
    /// For `GravityDb` this is written out to a private temporary file
    /// internally, since SQLite needs a real file to open; for text
    /// formats, it's used directly with no extra I/O.
    Bytes(&'a [u8]),
}

pub fn read_source(path: &Path) -> Result<Vec<u8>, IngestError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((MAX_SOURCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(IngestError::LimitExceeded("source bytes"));
    }
    Ok(bytes)
}

/// Dispatches source parsing here so file and HTTP imports use the same format mapping.
pub fn ingest_source(
    format: sniff::BlocklistFormat,
    source: SourceData,
) -> Result<Vec<FilterRule>, IngestError> {
    let bytes = match source {
        SourceData::Path(path) => read_source(path)?,
        SourceData::Bytes(bytes) => {
            if bytes.len() > MAX_SOURCE_BYTES {
                return Err(IngestError::LimitExceeded("source bytes"));
            }
            return ingest_bytes(format, bytes);
        }
    };
    ingest_bytes(format, &bytes)
}

fn ingest_bytes(
    format: sniff::BlocklistFormat,
    bytes: &[u8],
) -> Result<Vec<FilterRule>, IngestError> {
    use sniff::BlocklistFormat;
    if format == BlocklistFormat::GravityDb {
        // Random name, exclusive creation, mode 0600 and RAII cleanup prevent
        // symlink following and leave no files behind on parser errors.
        let mut temporary = tempfile::NamedTempFile::new()?;
        temporary.write_all(bytes)?;
        temporary.flush()?;
        return parsers::gravity_db::parse_limited(temporary.path(), MAX_SOURCE_RULES);
    }
    let contents = String::from_utf8_lossy(bytes);
    if contents
        .lines()
        .any(|line| line.len() > MAX_RULE_LINE_BYTES)
    {
        return Err(IngestError::LimitExceeded("line bytes"));
    }
    match format {
        BlocklistFormat::PlainList => {
            parsers::plain::parse_limited(&contents, RuleAction::Deny, MAX_SOURCE_RULES)
        }
        BlocklistFormat::HostsFile => {
            parsers::hosts::parse_limited(&contents, RuleAction::Deny, MAX_SOURCE_RULES)
        }
        BlocklistFormat::AdblockSyntax => {
            parsers::adblock::parse_limited(&contents, MAX_SOURCE_RULES)
        }
        BlocklistFormat::RegexList => {
            parsers::regex_list::parse_limited(&contents, RuleAction::Deny, MAX_SOURCE_RULES)
        }
        BlocklistFormat::GravityDb => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sniff::BlocklistFormat;

    #[test]
    fn test_ingest_source_bytes_plain_list() {
        let rules = ingest_source(
            BlocklistFormat::PlainList,
            SourceData::Bytes(b"a.example.com\nb.example.com\n"),
        )
        .unwrap();
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(patterns.contains(&"a.example.com"));
        assert!(patterns.contains(&"b.example.com"));
    }

    #[test]
    fn test_ingest_source_path_reads_file() {
        let path = std::env::temp_dir().join(format!(
            "dns-deny-test-ingest-source-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, "c.example.com\n").unwrap();

        let rules = ingest_source(BlocklistFormat::PlainList, SourceData::Path(&path)).unwrap();
        let _ = std::fs::remove_file(&path);

        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(patterns.contains(&"c.example.com"), "{patterns:?}");
    }

    fn seed_gravity_db(path: &Path) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE domainlist (type INTEGER, domain TEXT, enabled INTEGER);
             INSERT INTO domainlist (type, domain, enabled) VALUES (1, 'gravity.example.com', 1);",
        )
        .unwrap();
    }

    #[test]
    fn test_ingest_source_gravity_db_via_path() {
        let path = std::env::temp_dir().join(format!(
            "dns-deny-test-ingest-gravity-path-{}-{}.db",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);
        seed_gravity_db(&path);

        let rules = ingest_source(BlocklistFormat::GravityDb, SourceData::Path(&path)).unwrap();
        let _ = std::fs::remove_file(&path);

        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(patterns.contains(&"gravity.example.com"), "{patterns:?}");
    }

    #[test]
    fn test_ingest_source_gravity_db_via_bytes_uses_temp_file_and_cleans_up() {
        let source_path = std::env::temp_dir().join(format!(
            "dns-deny-test-ingest-gravity-src-{}-{}.db",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&source_path);
        seed_gravity_db(&source_path);
        let bytes = std::fs::read(&source_path).unwrap();
        let _ = std::fs::remove_file(&source_path);

        let rules = ingest_source(BlocklistFormat::GravityDb, SourceData::Bytes(&bytes)).unwrap();
        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        assert!(patterns.contains(&"gravity.example.com"), "{patterns:?}");

        let leftover = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_type().is_ok_and(|kind| kind.is_file())
                    && e.file_name()
                        .to_string_lossy()
                        .starts_with(&format!("dns-deny-gravity-{}-", std::process::id()))
            });
        assert!(
            !leftover,
            "temp gravity db file should be cleaned up after parsing"
        );
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn gravity_import_does_not_follow_legacy_predictable_symlinks() {
        let mut victim = tempfile::NamedTempFile::new().unwrap();
        victim.write_all(b"original data").unwrap();
        let bait =
            std::env::temp_dir().join(format!("dns-deny-gravity-{}-0.db", std::process::id()));
        std::os::unix::fs::symlink(victim.path(), &bait).unwrap();
        let _ = ingest_source(
            sniff::BlocklistFormat::GravityDb,
            SourceData::Bytes(b"attacker bytes"),
        );
        let contents = std::fs::read(victim.path()).unwrap();
        let untouched_link = bait.is_symlink();
        let _ = std::fs::remove_file(bait);
        assert_eq!(contents, b"original data");
        assert!(untouched_link);
    }

    #[test]
    fn oversized_sources_and_lines_are_rejected() {
        let bytes = vec![b'x'; MAX_SOURCE_BYTES + 1];
        assert!(matches!(
            ingest_source(sniff::BlocklistFormat::PlainList, SourceData::Bytes(&bytes)),
            Err(IngestError::LimitExceeded("source bytes"))
        ));
        let bytes = vec![b'x'; MAX_RULE_LINE_BYTES + 1];
        assert!(matches!(
            ingest_source(sniff::BlocklistFormat::RegexList, SourceData::Bytes(&bytes)),
            Err(IngestError::LimitExceeded("line bytes"))
        ));
    }

    #[test]
    fn text_rule_limits_abort_before_collecting_the_remaining_input() {
        assert!(matches!(
            parsers::plain::parse_limited("one.example\ntwo.example\n", RuleAction::Deny, 1),
            Err(IngestError::LimitExceeded("source rule count"))
        ));
        assert!(matches!(
            parsers::hosts::parse_limited("0.0.0.0 one.example two.example\n", RuleAction::Deny, 1),
            Err(IngestError::LimitExceeded("source rule count"))
        ));
        assert!(matches!(
            parsers::adblock::parse_limited("||one.example^\n||two.example^\n", 1),
            Err(IngestError::LimitExceeded("source rule count"))
        ));
        assert!(matches!(
            parsers::regex_list::parse_limited("^one\n^two\n", RuleAction::Deny, 1),
            Err(IngestError::LimitExceeded("source rule count"))
        ));
    }

    #[test]
    fn gravity_rule_limit_aborts_the_import() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let db = rusqlite::Connection::open(file.path()).unwrap();
        db.execute_batch("CREATE TABLE gravity(domain TEXT); INSERT INTO gravity VALUES ('one.example'), ('two.example');").unwrap();
        drop(db);
        assert!(matches!(
            parsers::gravity_db::parse_limited(file.path(), 1),
            Err(IngestError::LimitExceeded("source rule count"))
        ));
    }
}
