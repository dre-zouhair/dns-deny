//! Pre-aggregated query statistics.
//!
//! The writer updates rollups in the same transaction as raw log rows.
//! Dashboard reads use these tables to avoid scanning retained partitions:
//!
//! - `stats_hourly_totals` / `stats_daily_totals`: query and block counts per
//!   UTC hour / UTC day, kept for the whole retention period.
//! - `stats_daily_dim`: per-day counts per dimension value (domain, client,
//!   query type, resolver), kept for the whole retention period.
//! - `stats_hourly_dim`: the same per hour, only for the last
//!   [`HOURLY_DIM_RETENTION_MS`] -- it exists solely for the 24h top lists.
//!
//! Partitions that predate the rollups are folded in once by [`backfill`].

use crate::LogEntry;
use filter::FilterVerdict;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::HashMap;
use std::path::Path;

pub const HOUR_MS: i64 = 3_600_000;
pub const DAY_MS: i64 = 86_400_000;

/// How long per-hour dimension rows are kept. A little over 24h so the oldest
/// bucket of a rolling 24h window is never pruned while still in view.
pub const HOURLY_DIM_RETENTION_MS: i64 = 26 * HOUR_MS;

pub const DIM_BLOCKED_DOMAIN: &str = "blocked_domain";
pub const DIM_ALLOWED_DOMAIN: &str = "allowed_domain";
pub const DIM_CLIENT: &str = "client";
pub const DIM_QTYPE: &str = "qtype";
pub const DIM_RESOLVER: &str = "resolver";

const SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS stats_hourly_totals (
        hour_ms INTEGER PRIMARY KEY,
        total INTEGER NOT NULL DEFAULT 0,
        blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS stats_daily_totals (
        day INTEGER PRIMARY KEY,
        total INTEGER NOT NULL DEFAULT 0,
        blocked INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS stats_hourly_dim (
        dim TEXT NOT NULL,
        hour_ms INTEGER NOT NULL,
        key TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (dim, hour_ms, key)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS stats_daily_dim (
        dim TEXT NOT NULL,
        day INTEGER NOT NULL,
        key TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (dim, day, key)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS stats_meta (
        key TEXT PRIMARY KEY,
        value INTEGER NOT NULL
    );";

/// The time span a dashboard statistic covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Window {
    /// The current UTC hour and the 23 before it.
    Last24h,
    /// Today (UTC) and the 6 days before it.
    Last7d,
    /// Everything still within the log retention period.
    All,
}

impl Window {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "24h" => Some(Self::Last24h),
            "7d" => Some(Self::Last7d),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub total: u64,
    pub blocked: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bucket {
    pub start_ms: i64,
    pub total: u64,
    pub blocked: u64,
}

pub fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA_SQL)
}

fn hour_start(ms: i64) -> i64 {
    ms - ms.rem_euclid(HOUR_MS)
}

fn day_index(ms: i64) -> i64 {
    ms.div_euclid(DAY_MS)
}

pub(crate) fn entry_ms(entry: &LogEntry) -> i64 {
    entry
        .timestamp
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Folds a batch into the rollup tables. Aggregates in memory first so each
/// distinct (bucket, dimension, value) costs one upsert per batch, not one
/// per entry.
pub(crate) fn record_batch(tx: &Transaction, entries: &[LogEntry]) -> rusqlite::Result<()> {
    let mut hourly_totals: HashMap<i64, (i64, i64)> = HashMap::new();
    let mut daily_totals: HashMap<i64, (i64, i64)> = HashMap::new();
    let mut hourly_dim: HashMap<(&'static str, i64, String), i64> = HashMap::new();
    let mut daily_dim: HashMap<(&'static str, i64, String), i64> = HashMap::new();

    for entry in entries {
        let ms = entry_ms(entry);
        let hour = hour_start(ms);
        let day = day_index(ms);
        let blocked = entry.verdict == FilterVerdict::Block;

        for (bucket, map) in [(hour, &mut hourly_totals), (day, &mut daily_totals)] {
            let counts = map.entry(bucket).or_default();
            counts.0 += 1;
            counts.1 += i64::from(blocked);
        }

        let domain_dim = if blocked {
            DIM_BLOCKED_DOMAIN
        } else {
            DIM_ALLOWED_DOMAIN
        };
        let dims = [
            (domain_dim, entry.name.clone()),
            (DIM_CLIENT, entry.client_ip.to_string()),
            (DIM_QTYPE, entry.qtype.to_string()),
            (DIM_RESOLVER, entry.resolver.to_string()),
        ];
        for (dim, key) in dims {
            *hourly_dim.entry((dim, hour, key.clone())).or_default() += 1;
            *daily_dim.entry((dim, day, key)).or_default() += 1;
        }
    }

    let mut stmt = tx.prepare_cached(
        "INSERT INTO stats_hourly_totals (hour_ms, total, blocked) VALUES (?1, ?2, ?3)
         ON CONFLICT(hour_ms) DO UPDATE SET
             total = total + excluded.total, blocked = blocked + excluded.blocked",
    )?;
    for (hour, (total, blocked)) in hourly_totals {
        stmt.execute(params![hour, total, blocked])?;
    }
    let mut stmt = tx.prepare_cached(
        "INSERT INTO stats_daily_totals (day, total, blocked) VALUES (?1, ?2, ?3)
         ON CONFLICT(day) DO UPDATE SET
             total = total + excluded.total, blocked = blocked + excluded.blocked",
    )?;
    for (day, (total, blocked)) in daily_totals {
        stmt.execute(params![day, total, blocked])?;
    }
    let mut stmt = tx.prepare_cached(
        "INSERT INTO stats_hourly_dim (dim, hour_ms, key, count) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(dim, hour_ms, key) DO UPDATE SET count = count + excluded.count",
    )?;
    for ((dim, hour, key), count) in hourly_dim {
        stmt.execute(params![dim, hour, key, count])?;
    }
    let mut stmt = tx.prepare_cached(
        "INSERT INTO stats_daily_dim (dim, day, key, count) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(dim, day, key) DO UPDATE SET count = count + excluded.count",
    )?;
    for ((dim, day, key), count) in daily_dim {
        stmt.execute(params![dim, day, key, count])?;
    }
    Ok(())
}

/// Drops per-hour dimension rows that have aged out of every 24h window.
pub(crate) fn prune_hourly_dim(conn: &Connection, now_ms: i64) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM stats_hourly_dim WHERE hour_ms < ?1",
        [now_ms - HOURLY_DIM_RETENTION_MS],
    )
}

/// Deletes rollup rows for days before `threshold_day` (days since the Unix
/// epoch, UTC), mirroring the retention sweep's partition drops.
pub(crate) fn delete_before(conn: &Connection, threshold_day: i64) -> rusqlite::Result<()> {
    let threshold_ms = threshold_day.saturating_mul(DAY_MS);
    conn.execute(
        "DELETE FROM stats_daily_totals WHERE day < ?1",
        [threshold_day],
    )?;
    conn.execute(
        "DELETE FROM stats_daily_dim WHERE day < ?1",
        [threshold_day],
    )?;
    conn.execute(
        "DELETE FROM stats_hourly_totals WHERE hour_ms < ?1",
        [threshold_ms],
    )?;
    conn.execute(
        "DELETE FROM stats_hourly_dim WHERE hour_ms < ?1",
        [threshold_ms],
    )?;
    Ok(())
}

// ── Reads ─────────────────────────────────────────────────────────────────

/// True once the rollup schema exists. A log database written by an older
/// build (or none at all) simply has no statistics yet.
fn has_rollups(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'stats_daily_totals'",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
}

/// First hour/day included in `window` at `now_ms`.
fn window_start_hour(now_ms: i64) -> i64 {
    hour_start(now_ms) - 23 * HOUR_MS
}

fn window_start_day(now_ms: i64) -> i64 {
    day_index(now_ms) - 6
}

pub fn totals(conn: &Connection, window: Window, now_ms: i64) -> rusqlite::Result<Totals> {
    if !has_rollups(conn)? {
        return Ok(Totals::default());
    }
    let (sql, from) = match window {
        Window::Last24h => (
            "SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0)
             FROM stats_hourly_totals WHERE hour_ms >= ?1",
            window_start_hour(now_ms),
        ),
        Window::Last7d => (
            "SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0)
             FROM stats_daily_totals WHERE day >= ?1",
            window_start_day(now_ms),
        ),
        Window::All => (
            "SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0)
             FROM stats_daily_totals WHERE day >= ?1",
            i64::MIN,
        ),
    };
    conn.query_row(sql, [from], |row| {
        Ok(Totals {
            total: row.get::<_, i64>(0)? as u64,
            blocked: row.get::<_, i64>(1)? as u64,
        })
    })
}

/// Ranks dimension values across the whole window before applying `limit`,
/// with ties broken by value for stable results.
pub fn top(
    conn: &Connection,
    window: Window,
    dim: &str,
    limit: usize,
    now_ms: i64,
) -> rusqlite::Result<Vec<(String, u64)>> {
    if !has_rollups(conn)? {
        return Ok(Vec::new());
    }
    let (sql, from) = match window {
        Window::Last24h => (
            "SELECT key, SUM(count) AS c FROM stats_hourly_dim
             WHERE dim = ?1 AND hour_ms >= ?2
             GROUP BY key ORDER BY c DESC, key ASC LIMIT ?3",
            window_start_hour(now_ms),
        ),
        Window::Last7d => (
            "SELECT key, SUM(count) AS c FROM stats_daily_dim
             WHERE dim = ?1 AND day >= ?2
             GROUP BY key ORDER BY c DESC, key ASC LIMIT ?3",
            window_start_day(now_ms),
        ),
        Window::All => (
            "SELECT key, SUM(count) AS c FROM stats_daily_dim
             WHERE dim = ?1 AND day >= ?2
             GROUP BY key ORDER BY c DESC, key ASC LIMIT ?3",
            i64::MIN,
        ),
    };
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut stmt = conn.prepare_cached(sql)?;
    let rows = stmt.query_map(params![dim, from, limit], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;
    rows.collect()
}

/// Chart buckets for `window`, oldest first, with empty buckets filled in:
/// 24 hourly buckets for `Last24h`, 168 hourly buckets for `Last7d`, and one
/// daily bucket per day from the oldest retained day through today for `All`.
pub fn buckets(conn: &Connection, window: Window, now_ms: i64) -> rusqlite::Result<Vec<Bucket>> {
    let rollups = has_rollups(conn)?;
    let (step, first, last, sql) = match window {
        Window::Last24h | Window::Last7d => {
            let hours = if window == Window::Last24h { 24 } else { 168 };
            let last = hour_start(now_ms);
            (
                HOUR_MS,
                last - (hours - 1) * HOUR_MS,
                last,
                "SELECT hour_ms, total, blocked FROM stats_hourly_totals WHERE hour_ms >= ?1",
            )
        }
        Window::All => {
            let today = day_index(now_ms);
            let oldest = if rollups {
                conn.query_row("SELECT MIN(day) FROM stats_daily_totals", [], |row| {
                    row.get::<_, Option<i64>>(0)
                })?
                .unwrap_or(today)
                .min(today)
            } else {
                today
            };
            (
                DAY_MS,
                oldest * DAY_MS,
                today * DAY_MS,
                "SELECT day * 86400000, total, blocked FROM stats_daily_totals WHERE day * 86400000 >= ?1",
            )
        }
    };

    let mut counts: HashMap<i64, (u64, u64)> = HashMap::new();
    if rollups {
        let mut stmt = conn.prepare_cached(sql)?;
        let rows = stmt.query_map([first], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
            ))
        })?;
        for row in rows {
            let (start, total, blocked) = row?;
            counts.insert(start, (total, blocked));
        }
    }

    let mut out = Vec::new();
    let mut start = first;
    while start <= last {
        let (total, blocked) = counts.get(&start).copied().unwrap_or((0, 0));
        out.push(Bucket {
            start_ms: start,
            total,
            blocked,
        });
        start += step;
    }
    Ok(out)
}

// ── One-time backfill ─────────────────────────────────────────────────────

/// True for a `logs_YYYY_MM_DD` partition name. Table names are interpolated
/// into SQL below, so only names of exactly this shape are ever used.
pub fn is_partition_name(name: &str) -> bool {
    name.strip_prefix("logs_").is_some_and(|date| {
        date.len() == 10
            && date.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 4 | 7) {
                    byte == b'_'
                } else {
                    byte.is_ascii_digit()
                }
            })
            && chrono::NaiveDate::parse_from_str(date, "%Y_%m_%d").is_ok()
    })
}

/// Folds partitions written before the rollups existed into them, so the
/// dashboard shows existing history immediately after an upgrade.
///
/// `rollup_start_ms` is recorded the first time this runs (the first startup
/// of a build with rollups); every row from then on is counted by the live
/// writer, so only rows older than it are backfilled. Each partition is
/// processed in its own transaction that also records a marker, so the
/// backfill is idempotent and survives being interrupted. Returns the number
/// of partitions processed by this call.
pub fn backfill(db_path: &Path, now_ms: i64) -> rusqlite::Result<usize> {
    let mut conn = Connection::open(db_path)?;
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    create_schema(&conn)?;
    conn.execute(
        "INSERT OR IGNORE INTO stats_meta (key, value) VALUES ('rollup_start_ms', ?1)",
        [now_ms],
    )?;
    let rollup_start: i64 = conn.query_row(
        "SELECT value FROM stats_meta WHERE key = 'rollup_start_ms'",
        [],
        |row| row.get(0),
    )?;

    let partitions: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'logs_%'",
        )?;
        let names = stmt.query_map([], |row| row.get::<_, String>(0))?;
        names
            .filter_map(Result::ok)
            .filter(|name| is_partition_name(name))
            .collect()
    };

    let mut processed = 0;
    for table in partitions {
        let marker = format!("backfilled:{table}");
        let done: Option<i64> = conn
            .query_row(
                "SELECT value FROM stats_meta WHERE key = ?1",
                [&marker],
                |row| row.get(0),
            )
            .optional()?;
        if done.is_some() {
            continue;
        }

        let tx = conn.transaction()?;
        backfill_partition(&tx, &table, rollup_start, now_ms)?;
        tx.execute(
            "INSERT INTO stats_meta (key, value) VALUES (?1, 1)",
            [&marker],
        )?;
        tx.commit()?;
        processed += 1;
    }
    Ok(processed)
}

fn backfill_partition(
    tx: &Transaction,
    table: &str,
    rollup_start: i64,
    now_ms: i64,
) -> rusqlite::Result<()> {
    tx.execute(
        &format!(
            "INSERT INTO stats_hourly_totals (hour_ms, total, blocked)
             SELECT (timestamp / {HOUR_MS}) * {HOUR_MS} AS h, COUNT(*), SUM(verdict = 'Block')
             FROM {table} WHERE timestamp < ?1 GROUP BY h
             ON CONFLICT(hour_ms) DO UPDATE SET
                 total = total + excluded.total, blocked = blocked + excluded.blocked"
        ),
        [rollup_start],
    )?;
    tx.execute(
        &format!(
            "INSERT INTO stats_daily_totals (day, total, blocked)
             SELECT timestamp / {DAY_MS} AS d, COUNT(*), SUM(verdict = 'Block')
             FROM {table} WHERE timestamp < ?1 GROUP BY d
             ON CONFLICT(day) DO UPDATE SET
                 total = total + excluded.total, blocked = blocked + excluded.blocked"
        ),
        [rollup_start],
    )?;

    let dims = [
        (DIM_BLOCKED_DOMAIN, "name", "verdict = 'Block'"),
        (DIM_ALLOWED_DOMAIN, "name", "verdict != 'Block'"),
        (DIM_CLIENT, "client_ip", "1"),
        (DIM_QTYPE, "qtype", "1"),
        (DIM_RESOLVER, "resolver", "1"),
    ];
    let hourly_from = now_ms - HOURLY_DIM_RETENTION_MS;
    for (dim, column, filter) in dims {
        tx.execute(
            &format!(
                "INSERT INTO stats_daily_dim (dim, day, key, count)
                 SELECT ?1, timestamp / {DAY_MS} AS d, {column}, COUNT(*)
                 FROM {table} WHERE timestamp < ?2 AND {filter} GROUP BY d, {column}
                 ON CONFLICT(dim, day, key) DO UPDATE SET count = count + excluded.count"
            ),
            params![dim, rollup_start],
        )?;
        tx.execute(
            &format!(
                "INSERT INTO stats_hourly_dim (dim, hour_ms, key, count)
                 SELECT ?1, (timestamp / {HOUR_MS}) * {HOUR_MS} AS h, {column}, COUNT(*)
                 FROM {table} WHERE timestamp < ?2 AND timestamp >= ?3 AND {filter}
                 GROUP BY h, {column}
                 ON CONFLICT(dim, hour_ms, key) DO UPDATE SET count = count + excluded.count"
            ),
            params![dim, rollup_start, hourly_from],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_parse() {
        assert_eq!(Window::parse("24h"), Some(Window::Last24h));
        assert_eq!(Window::parse("7d"), Some(Window::Last7d));
        assert_eq!(Window::parse("all"), Some(Window::All));
        assert_eq!(Window::parse("1y"), None);
    }

    #[test]
    fn test_partition_name_validation() {
        assert!(is_partition_name("logs_2024_01_31"));
        assert!(!is_partition_name("logs_2024_1_31"));
        assert!(!is_partition_name("logs_2024_01_31; DROP TABLE x"));
        assert!(!is_partition_name("stats_daily_totals"));
    }

    #[test]
    fn test_reads_on_database_without_rollups_are_empty() {
        let conn = Connection::open_in_memory().unwrap();
        let now = 1_700_000_000_000;
        assert_eq!(totals(&conn, Window::All, now).unwrap(), Totals::default());
        assert!(
            top(&conn, Window::Last24h, DIM_CLIENT, 10, now)
                .unwrap()
                .is_empty()
        );
        let b = buckets(&conn, Window::Last24h, now).unwrap();
        assert_eq!(b.len(), 24);
        assert!(b.iter().all(|b| b.total == 0));
        assert_eq!(buckets(&conn, Window::Last7d, now).unwrap().len(), 168);
        assert_eq!(buckets(&conn, Window::All, now).unwrap().len(), 1);
    }
}
