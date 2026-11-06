use filter::FilterVerdict;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use logger::{QueryLogger, run_retention_sweep};
use std::net::IpAddr;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_unbounded_to_bounded_drop_policy() {
    let db_path = tempfile::NamedTempFile::new().unwrap().into_temp_path();
    let logger = QueryLogger::new(&db_path, 5, 90);

    for i in 0..10 {
        logger.log(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            format!("test{}.com", i),
            RecordType::A,
            ResponseCode::NoError,
            1000,
            FilterVerdict::Pass,
            "Cache".into(),
        );
    }

    let dropped = logger.dropped_count();
    assert!(
        dropped > 0,
        "Expected some logs to be dropped, got {}",
        dropped
    );
}

#[tokio::test]
async fn test_retention_sweep() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("test_retention.db");

    let conn = rusqlite::Connection::open(&db_path).unwrap();

    conn.execute_batch(
        "CREATE TABLE logs_2025_01_01 (
            timestamp INTEGER, client_ip TEXT, name TEXT, qtype TEXT, response_code TEXT, duration_ns INTEGER, verdict TEXT
         );
         CREATE TABLE logs_2026_07_20 (
            timestamp INTEGER, client_ip TEXT, name TEXT, qtype TEXT, response_code TEXT, duration_ns INTEGER, verdict TEXT
         );"
    ).unwrap();

    // Release the statement borrow before closing the connection.
    {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(names.contains(&"logs_2025_01_01".to_string()));
        assert!(names.contains(&"logs_2026_07_20".to_string()));
    }
    drop(conn);

    run_retention_sweep(&db_path, 90).await.unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert!(
            !names.contains(&"logs_2025_01_01".to_string()),
            "logs_2025_01_01 should be dropped"
        );
    }
}

#[tokio::test]
async fn test_retention_sweep_does_not_delete_partition_exactly_at_boundary() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("test_boundary.db");

    let retention_days: i64 = 90;
    let today = chrono::Utc::now().date_naive();
    let boundary_date = today - chrono::Duration::days(retention_days);
    let boundary_table = format!("logs_{}", boundary_date.format("%Y_%m_%d"));
    let expired_date = boundary_date - chrono::Duration::days(1);
    let expired_table = format!("logs_{}", expired_date.format("%Y_%m_%d"));

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(&format!(
        "CREATE TABLE {} (timestamp INTEGER, client_ip TEXT, name TEXT, qtype TEXT, response_code TEXT, duration_ns INTEGER, verdict TEXT);
         CREATE TABLE {} (timestamp INTEGER, client_ip TEXT, name TEXT, qtype TEXT, response_code TEXT, duration_ns INTEGER, verdict TEXT);",
        boundary_table, expired_table
    )).unwrap();
    drop(conn);

    run_retention_sweep(&db_path, retention_days).await.unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert!(
        names.contains(&boundary_table),
        "partition exactly at the retention boundary must not be deleted early: {:?}",
        names
    );
    assert!(
        !names.contains(&expired_table),
        "partition strictly older than the retention window should be dropped: {:?}",
        names
    );
}

#[tokio::test]
async fn test_retention_sweep_ignores_malformed_table_names() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("test_malformed.db");

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    // Retention must ignore malformed partition names, including valid date
    // prefixes with the wrong length.
    conn.execute_batch(
        "CREATE TABLE logs_not_a_date (timestamp INTEGER);
         CREATE TABLE logs_2020 (timestamp INTEGER);",
    )
    .unwrap();
    drop(conn);

    run_retention_sweep(&db_path, 90).await.unwrap();

    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")
        .unwrap();
    let names: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert!(names.contains(&"logs_not_a_date".to_string()));
    assert!(names.contains(&"logs_2020".to_string()));
}

#[tokio::test]
async fn test_end_to_end_logged_entries_are_persisted_to_sqlite() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("e2e.db");

    let logger = QueryLogger::new(&db_path, 100, 90);
    logger.log(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        "end-to-end-test.example".to_string(),
        RecordType::A,
        ResponseCode::NoError,
        1234,
        FilterVerdict::Pass,
        "Cache".into(),
    );

    // Exercise the real worker and its 200ms flush timer; poll rather than
    // assuming when a background task will run.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(conn) = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            let table: Option<String> = conn.query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%' LIMIT 1",
                [],
                |row| row.get(0),
            ).ok();

            if let Some(table) = table {
                let found: i64 = conn
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {} WHERE name = ?1", table),
                        ["end-to-end-test.example"],
                        |row| row.get(0),
                    )
                    .unwrap_or(0);
                if found > 0 {
                    return;
                }
            }
        }

        if std::time::Instant::now() > deadline {
            panic!("logged entry was never persisted to sqlite within the timeout");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn test_concurrent_read_while_writing_succeeds_under_wal() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("concurrent.db");

    let logger = QueryLogger::new(&db_path, 1000, 90);
    for i in 0..50 {
        logger.log(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            format!("concurrent{}.com", i),
            RecordType::A,
            ResponseCode::NoError,
            100,
            FilterVerdict::Pass,
            "Cache".into(),
        );
    }

    // WAL readers must remain usable during writes; any lock error fails the test.
    for _ in 0..20 {
        let conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("a reader must be able to open the db concurrently with the writer under WAL");
        let result: Result<i64, _> = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
            [],
            |row| row.get(0),
        );
        assert!(
            result.is_ok(),
            "concurrent read failed while writer was active: {:?}",
            result.err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

use logger::LogEntry;
use logger::stats::{self, Window};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn entry_at(ms: i64, name: &str, client: [u8; 4], verdict: FilterVerdict) -> LogEntry {
    LogEntry {
        timestamp: UNIX_EPOCH + Duration::from_millis(ms as u64),
        client_ip: IpAddr::V4(Ipv4Addr::from(client)),
        name: name.to_string(),
        qtype: RecordType::A,
        response_code: ResponseCode::NoError,
        duration_ns: 1000,
        verdict,
        resolver: "Standard Upstreams".into(),
    }
}

fn open(db_path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(db_path).unwrap()
}

#[test]
fn test_rollups_match_raw_rows_across_batches_hours_and_days() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("rollups.db");
    let now = now_ms();
    // Anchor to bucket starts so the test can't straddle an hour or UTC-day
    // boundary depending on when it runs.
    let two_days_ago = now - now.rem_euclid(stats::DAY_MS) - 2 * stats::DAY_MS + stats::HOUR_MS;
    let this_hour = now - now.rem_euclid(stats::HOUR_MS);

    // Two separate flushes (batches) must accumulate, not overwrite.
    let mut first = Vec::new();
    for _ in 0..3 {
        first.push(entry_at(
            two_days_ago,
            "a.com",
            [10, 0, 0, 1],
            FilterVerdict::Block,
        ));
    }
    first.push(entry_at(
        two_days_ago,
        "b.com",
        [10, 0, 0, 2],
        FilterVerdict::Pass,
    ));
    logger::persist_entries_blocking(&db_path, &first).unwrap();
    let second = vec![
        entry_at(
            two_days_ago + stats::HOUR_MS,
            "b.com",
            [10, 0, 0, 2],
            FilterVerdict::Allow,
        ),
        entry_at(this_hour, "b.com", [10, 0, 0, 3], FilterVerdict::Pass),
    ];
    logger::persist_entries_blocking(&db_path, &second).unwrap();

    let conn = open(&db_path);
    let all = stats::totals(&conn, Window::All, now).unwrap();
    assert_eq!((all.total, all.blocked), (6, 3));
    assert_eq!(stats::totals(&conn, Window::Last7d, now).unwrap().total, 6);
    let day = stats::totals(&conn, Window::Last24h, now).unwrap();
    assert_eq!((day.total, day.blocked), (1, 0));

    assert_eq!(
        stats::top(&conn, Window::All, stats::DIM_BLOCKED_DOMAIN, 10, now).unwrap(),
        vec![("a.com".to_string(), 3)]
    );
    assert_eq!(
        stats::top(&conn, Window::All, stats::DIM_ALLOWED_DOMAIN, 10, now).unwrap(),
        vec![("b.com".to_string(), 3)]
    );
    assert_eq!(
        stats::top(&conn, Window::All, stats::DIM_CLIENT, 2, now).unwrap(),
        vec![("10.0.0.1".to_string(), 3), ("10.0.0.2".to_string(), 2)]
    );
    assert_eq!(
        stats::top(&conn, Window::Last24h, stats::DIM_CLIENT, 10, now).unwrap(),
        vec![("10.0.0.3".to_string(), 1)]
    );
    assert_eq!(
        stats::top(&conn, Window::All, stats::DIM_QTYPE, 10, now).unwrap(),
        vec![("A".to_string(), 6)]
    );

    let daily = stats::buckets(&conn, Window::All, now).unwrap();
    assert_eq!(daily.len(), 3, "{daily:?}");
    assert_eq!((daily[0].total, daily[0].blocked), (5, 3));
    assert_eq!(daily[2].total, 1);

    let hourly = stats::buckets(&conn, Window::Last24h, now).unwrap();
    assert_eq!(hourly.len(), 24);
    assert_eq!(hourly.iter().map(|b| b.total).sum::<u64>(), 1);
    assert_eq!(hourly.last().unwrap().total, 1);
}

#[test]
fn test_backfill_counts_old_rows_once_and_skips_live_ones() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("backfill.db");
    let start = now_ms();
    let table = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(start)
        .unwrap()
        .format("logs_%Y_%m_%d")
        .to_string();

    // A partition written by a build without rollups.
    let conn = open(&db_path);
    conn.execute_batch(&format!(
        "CREATE TABLE {table} (
            timestamp INTEGER NOT NULL, client_ip TEXT NOT NULL, name TEXT NOT NULL,
            qtype TEXT NOT NULL, response_code TEXT NOT NULL, duration_ns INTEGER NOT NULL,
            verdict TEXT NOT NULL, resolver TEXT NOT NULL DEFAULT 'Unknown'
        );"
    ))
    .unwrap();
    for (offset, name, verdict) in [
        (-2 * stats::HOUR_MS, "old-blocked.com", "Block"),
        (-stats::HOUR_MS, "old-allowed.com", "Pass"),
        // At/after rollup_start: the live writer counts these, not backfill.
        (60_000, "live.com", "Pass"),
    ] {
        conn.execute(
            &format!(
                "INSERT INTO {table} VALUES (?1, '10.0.0.9', ?2, 'A', 'No Error', 1, ?3, 'Standard Upstreams')"
            ),
            rusqlite::params![start + offset, name, verdict],
        )
        .unwrap();
    }
    drop(conn);

    assert_eq!(stats::backfill(&db_path, start).unwrap(), 1);
    // Idempotent: a second run (e.g. next restart) changes nothing.
    assert_eq!(stats::backfill(&db_path, start + 1_000).unwrap(), 0);

    let conn = open(&db_path);
    let now = start + 120_000;
    let all = stats::totals(&conn, Window::All, now).unwrap();
    assert_eq!((all.total, all.blocked), (2, 1));
    assert_eq!(
        stats::top(&conn, Window::Last24h, stats::DIM_BLOCKED_DOMAIN, 10, now).unwrap(),
        vec![("old-blocked.com".to_string(), 1)]
    );
}

#[tokio::test]
async fn test_retention_sweep_expires_rollups() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("retention-rollups.db");
    let now = now_ms();
    logger::persist_entries_blocking(
        &db_path,
        &[
            entry_at(
                now - 200 * stats::DAY_MS,
                "ancient.com",
                [10, 0, 0, 1],
                FilterVerdict::Block,
            ),
            entry_at(
                now - 60_000,
                "recent.com",
                [10, 0, 0, 1],
                FilterVerdict::Pass,
            ),
        ],
    )
    .unwrap();

    run_retention_sweep(&db_path, 90).await.unwrap();

    let conn = open(&db_path);
    let all = stats::totals(&conn, Window::All, now).unwrap();
    assert_eq!((all.total, all.blocked), (1, 0));
    assert!(
        stats::top(&conn, Window::All, stats::DIM_BLOCKED_DOMAIN, 10, now)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_steady_trickle_of_queries_is_flushed_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("trickle.db");
    let logger = QueryLogger::new(&db_path, 1000, 90);

    let persisted = || -> i64 {
        let Ok(conn) = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) else {
            return 0;
        };
        conn.query_row(
            "SELECT COALESCE(SUM(total), 0) FROM stats_daily_totals",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    };

    // One query every 50ms never leaves a 200ms idle gap. The old flush only
    // fired after such a gap (or 500 entries), so nothing would be persisted
    // while the trickle continues.
    for i in 0..30 {
        logger.log(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            format!("trickle{i}.com"),
            RecordType::A,
            ResponseCode::NoError,
            1000,
            FilterVerdict::Pass,
            "Cache".into(),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 30 entries over ~1.5s; with a 200ms flush interval all but the last
    // few must already be on disk.
    let count = persisted();
    assert!(
        count >= 20,
        "only {count} of 30 entries persisted mid-trickle"
    );
}
