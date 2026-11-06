use filter::FilterVerdict;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use rusqlite::Connection;
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, warn};

pub mod stats;

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub client_ip: IpAddr,
    pub name: String,
    pub qtype: RecordType,
    pub response_code: ResponseCode,
    pub duration_ns: u64,
    pub verdict: FilterVerdict,
    /// Borrows fixed resolver labels to avoid a heap allocation per logged query.
    pub resolver: Cow<'static, str>,
}

pub struct QueryLogger {
    tx: Sender<LogEntry>,
    broadcast_tx: tokio::sync::broadcast::Sender<LogEntry>,
    dropped_count: Arc<AtomicU64>,
}

impl QueryLogger {
    pub fn new<P: AsRef<Path>>(db_path: P, capacity: usize, retention_days: i64) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        let rx = Arc::new(Mutex::new(rx));
        let db_path = db_path.as_ref().to_path_buf();
        let dropped_count = Arc::new(AtomicU64::new(0));
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(1000);

        // Establish durable WAL mode before worker and retention connections can
        // race to open the file. Other pragmas must still be set per connection.
        if let Err(e) = initialize_database(&db_path) {
            error!(
                "Failed to initialize query log database at {:?}: {:?}",
                db_path, e
            );
        }

        spawn_logger_supervisor(db_path.clone(), rx);

        spawn_stats_backfill(db_path.clone());

        spawn_retention_scheduler(db_path, retention_days);

        Self {
            tx,
            broadcast_tx,
            dropped_count,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn log(
        &self,
        client_ip: IpAddr,
        name: String,
        qtype: RecordType,
        response_code: ResponseCode,
        duration_ns: u64,
        verdict: FilterVerdict,
        resolver: Cow<'static, str>,
    ) {
        let entry = LogEntry {
            timestamp: SystemTime::now(),
            client_ip,
            name,
            qtype,
            response_code,
            duration_ns,
            verdict,
            resolver,
        };

        // Clone for live tail only when subscribed; otherwise every query would
        // allocate strings for a broadcast with no receivers.
        if self.broadcast_tx.receiver_count() > 0 {
            let _ = self.broadcast_tx.send(entry.clone());
        }

        if let Err(e) = self.tx.try_send(entry) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    let prev = self.dropped_count.fetch_add(1, Ordering::Relaxed);
                    if prev.is_multiple_of(1000) {
                        warn!("Query log buffer full. Dropped {} logs so far", prev + 1);
                    }
                }
                mpsc::error::TrySendError::Closed(_) => {
                    error!("Query logger channel closed. Dropping log entry");
                }
            }
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<LogEntry> {
        self.broadcast_tx.subscribe()
    }
}

/// Caps retries for persistent database failures to avoid flooding the error log.
const MAX_RESTART_BACKOFF: Duration = Duration::from_secs(60);

/// A long healthy run resets backoff so an isolated error restarts promptly.
const HEALTHY_RUNTIME_RESETS_BACKOFF: Duration = Duration::from_secs(30);

/// 1s, 2s, 4s, ... capped at `MAX_RESTART_BACKOFF`, for the `n`th
/// consecutive failure (0-indexed).
fn restart_backoff(consecutive_failures: u32) -> Duration {
    Duration::from_secs(1u64 << consecutive_failures.min(6)).min(MAX_RESTART_BACKOFF)
}

fn spawn_logger_supervisor(db_path: PathBuf, rx: Arc<Mutex<Receiver<LogEntry>>>) {
    tokio::spawn(async move {
        // Keep pending entries across worker errors or panics. Only a successful
        // SQLite commit removes them; the supervisor owns the batch across retries.
        let batch: Arc<Mutex<Vec<LogEntry>>> = Arc::new(Mutex::new(Vec::new()));
        let mut consecutive_failures: u32 = 0;

        loop {
            let db_path_clone = db_path.clone();
            let rx_clone = rx.clone();
            let batch_clone = batch.clone();
            let attempt_start = Instant::now();

            let handle =
                tokio::spawn(async move { run_worker(db_path_clone, rx_clone, batch_clone).await });

            match handle.await {
                Ok(Ok(())) => {
                    info!("Logger worker exited normally");
                    break;
                }
                Ok(Err(e)) => {
                    error!("Logger worker exited with error: {:?}", e);
                }
                Err(join_err) => {
                    error!("Logger worker panicked: {:?}", join_err);
                }
            }

            if attempt_start.elapsed() >= HEALTHY_RUNTIME_RESETS_BACKOFF {
                consecutive_failures = 0;
            }
            let backoff = restart_backoff(consecutive_failures);
            consecutive_failures = consecutive_failures.saturating_add(1);
            warn!(
                "Restarting logger worker in {:?} (attempt {}, pending batch preserved)...",
                backoff, consecutive_failures
            );
            tokio::time::sleep(backoff).await;
        }
    });
}

/// Opens a connection and reapplies per-connection pragmas. WAL mode is
/// established separately during initialization because it persists in the file.
fn apply_pragmas(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -10000;
         PRAGMA busy_timeout = 5000;",
    )?;

    // WAL requests can silently retain the previous journal mode. Inspect the
    // returned mode before other connections rely on WAL semantics.
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        warn!(
            "Query log database did not enter WAL mode (got '{}' instead); concurrent readers/writers may see more lock contention than expected",
            mode
        );
    }

    Ok(())
}

/// Only the historical log listing needs a per-partition timestamp index.
/// Statistics use rollups; extra indexes would add work to every insert.
fn partition_indexes_sql(table: &str) -> String {
    format!("CREATE INDEX IF NOT EXISTS idx_{table}_timestamp ON {table}(timestamp);")
}

/// Indexes older builds created that nothing reads any more.
fn obsolete_partition_indexes_sql(table: &str) -> String {
    format!(
        "DROP INDEX IF EXISTS idx_{table}_name;
         DROP INDEX IF EXISTS idx_{table}_verdict_name;"
    )
}

/// Brings indexes on already-existing partition tables in line with
/// `partition_indexes_sql`: creates any missing one and drops the obsolete
/// ones. Runs once at startup alongside the `resolver` column migration.
fn migrate_partition_indexes(conn: &Connection) -> Result<(), rusqlite::Error> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")?;
    let table_names: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(Result::ok)
        .collect();
    drop(stmt);

    for table in table_names {
        if !stats::is_partition_name(&table) {
            continue;
        }
        conn.execute_batch(&partition_indexes_sql(&table))?;
        conn.execute_batch(&obsolete_partition_indexes_sql(&table))?;
    }

    Ok(())
}

/// Migrates partitions that predate the resolver column once at startup,
/// keeping schema writes off the log-reading and batch-writing paths.
fn migrate_legacy_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")?;
    let table_names: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(Result::ok)
        .collect();

    for table in table_names {
        if !stats::is_partition_name(&table) {
            continue;
        }
        let mut info_stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
        let has_resolver = info_stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|col| col == "resolver");

        if !has_resolver {
            info!(
                "Migrating legacy log partition table {} to add resolver column",
                table
            );
            conn.execute(
                &format!(
                    "ALTER TABLE {} ADD COLUMN resolver TEXT NOT NULL DEFAULT 'Unknown'",
                    table
                ),
                [],
            )?;
        }
    }

    Ok(())
}

fn initialize_database(db_path: &Path) -> Result<(), rusqlite::Error> {
    let conn = Connection::open(db_path)?;
    apply_pragmas(&conn)?;
    stats::create_schema(&conn)?;
    migrate_legacy_tables(&conn)?;
    migrate_partition_indexes(&conn)
}

/// Most entries a batch holds before it is flushed early.
const MAX_BATCH_ENTRIES: usize = 500;

/// Maximum wait before flushing, even under continuous low-volume traffic.
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

async fn run_worker(
    db_path: PathBuf,
    rx: Arc<Mutex<Receiver<LogEntry>>>,
    batch: Arc<Mutex<Vec<LogEntry>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = Some(
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Connection> {
            let conn = Connection::open(&db_path)?;
            apply_pragmas(&conn)?;
            Ok(conn)
        })
        .await??,
    );

    // This worker is the receiver's only consumer for its whole lifetime.
    let mut rx = rx.lock().await;
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_pruned_hour = None;

    loop {
        tokio::select! {
            item = rx.recv() => match item {
                Some(entry) => {
                    let full = {
                        let mut batch_lock = batch.lock().await;
                        batch_lock.push(entry);
                        batch_lock.len() >= MAX_BATCH_ENTRIES
                    };
                    if full {
                        flush(&mut conn, &batch).await?;
                    }
                }
                None => break,
            },
            _ = ticker.tick() => {
                if !batch.lock().await.is_empty() {
                    flush(&mut conn, &batch).await?;
                }
                let now_ms = now_epoch_ms();
                let hour = now_ms / stats::HOUR_MS;
                if last_pruned_hour != Some(hour) {
                    with_conn(&mut conn, move |c| stats::prune_hourly_dim(c, now_ms)).await?;
                    last_pruned_hour = Some(hour);
                }
            }
        }
    }

    flush(&mut conn, &batch).await
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Runs blocking SQLite work on the blocking pool rather than on a runtime
/// worker that also serves DNS. The connection is moved in and handed back;
/// if the closure panics it is lost, the worker errors out, and the
/// supervisor restarts it with a fresh connection.
async fn with_conn<T, F>(
    conn: &mut Option<Connection>,
    f: F,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
where
    T: Send + 'static,
    F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
{
    let mut owned = conn.take().ok_or("logger database connection was lost")?;
    let (owned, result) = tokio::task::spawn_blocking(move || {
        let result = f(&mut owned);
        (owned, result)
    })
    .await?;
    *conn = Some(owned);
    Ok(result?)
}

/// Flushes the pending batch. On failure the entries stay in `batch` (see
/// `flush_batch`), so the supervisor's restart retries them.
async fn flush(
    conn: &mut Option<Connection>,
    batch: &Arc<Mutex<Vec<LogEntry>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let batch = batch.clone();
    with_conn(conn, move |c| {
        let mut batch_lock = batch.blocking_lock();
        flush_batch(&mut batch_lock, c)
    })
    .await
}

/// Writes `entries` (raw rows plus rollups) synchronously, creating the
/// database if needed. For tests and tooling that need log data with chosen
/// timestamps; the server itself always logs through [`QueryLogger`].
pub fn persist_entries_blocking(db_path: &Path, entries: &[LogEntry]) -> rusqlite::Result<()> {
    initialize_database(db_path)?;
    let mut conn = Connection::open(db_path)?;
    let mut batch = entries.to_vec();
    flush_batch(&mut batch, &mut conn)
}

fn flush_batch(batch: &mut Vec<LogEntry>, conn: &mut Connection) -> Result<(), rusqlite::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    // Group by UTC day without draining the batch: a failed transaction must
    // leave every entry available for retry.
    let mut groups: HashMap<String, Vec<&LogEntry>> = HashMap::new();
    for entry in batch.iter() {
        let datetime: chrono::DateTime<chrono::Utc> = entry.timestamp.into();
        let partition = datetime.format("%Y_%m_%d").to_string();
        groups.entry(partition).or_default().push(entry);
    }

    let tx = conn.transaction()?;
    for (partition, entries) in groups {
        let table_name = format!("logs_{}", partition);

        tx.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {table_name} (
                timestamp INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                name TEXT NOT NULL,
                qtype TEXT NOT NULL,
                response_code TEXT NOT NULL,
                duration_ns INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                resolver TEXT NOT NULL DEFAULT 'Unknown'
            );
            {}",
            partition_indexes_sql(&table_name)
        ))?;

        let mut stmt = tx.prepare_cached(&format!(
            "INSERT INTO {} (timestamp, client_ip, name, qtype, response_code, duration_ns, verdict, resolver)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            table_name
        ))?;

        for entry in entries {
            let timestamp_ms = entry
                .timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let ip_str = entry.client_ip.to_string();
            let qtype_str = entry.qtype.to_string();
            let rcode_str = entry.response_code.to_string();
            let verdict_str = format!("{:?}", entry.verdict);

            stmt.execute((
                timestamp_ms,
                ip_str,
                entry.name.as_str(),
                qtype_str,
                rcode_str,
                entry.duration_ns as i64,
                verdict_str,
                entry.resolver.as_ref(),
            ))?;
        }
    }
    stats::create_schema(&tx)?;
    stats::record_batch(&tx, batch)?;
    tx.commit()?;
    batch.clear();

    Ok(())
}

/// Folds log partitions that predate the stats rollups into them, once, on a
/// blocking thread so startup isn't held up. See [`stats::backfill`].
fn spawn_stats_backfill(db_path: PathBuf) {
    if db_path.as_os_str() == ":memory:" {
        return;
    }
    tokio::task::spawn_blocking(move || match stats::backfill(&db_path, now_epoch_ms()) {
        Ok(0) => {}
        Ok(n) => info!(
            "Backfilled dashboard statistics from {} log partition(s)",
            n
        ),
        Err(e) => error!("Dashboard statistics backfill failed: {:?}", e),
    });
}

fn spawn_retention_scheduler(db_path: PathBuf, retention_days: i64) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_retention_sweep(&db_path, retention_days).await {
                error!("Retention sweep failed: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
        }
    });
}

pub async fn run_retention_sweep(
    db_path: &Path,
    retention_days: i64,
) -> Result<(), rusqlite::Error> {
    let db_path = db_path.to_path_buf();
    tokio::task::spawn_blocking(move || retention_sweep_blocking(&db_path, retention_days))
        .await
        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?
}

fn retention_sweep_blocking(db_path: &Path, retention_days: i64) -> rusqlite::Result<()> {
    let conn = Connection::open(db_path)?;
    // Wait for a concurrent log flush instead of failing retention with SQLITE_BUSY.
    conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
    let mut stmt =
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'")?;
    let mut rows = stmt.query([])?;

    // Drop only fully expired UTC days. Comparing midnight against an instant
    // would discard the boundary partition before all of its entries expire.
    let threshold_date = (chrono::Utc::now() - chrono::Duration::days(retention_days)).date_naive();
    let mut tables_to_drop = Vec::new();

    while let Some(row) = rows.next()? {
        let table_name: String = row.get(0)?;
        if stats::is_partition_name(&table_name) {
            let date_str = &table_name[5..]; // YYYY_MM_DD
            if let Ok(date) = chrono::NaiveDate::parse_from_str(date_str, "%Y_%m_%d")
                && date < threshold_date
            {
                tables_to_drop.push(table_name);
            }
        }
    }

    for table in tables_to_drop {
        info!("Dropping expired log partition table: {}", table);
        conn.execute(&format!("DROP TABLE IF EXISTS {}", table), [])?;
    }

    stats::create_schema(&conn)?;
    let threshold_day = threshold_date
        .signed_duration_since(chrono::DateTime::UNIX_EPOCH.date_naive())
        .num_days();
    stats::delete_before(&conn, threshold_day)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn retention_lock_wait_does_not_block_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("retention.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE logs_2000_01_01 (timestamp INTEGER); BEGIN IMMEDIATE;")
            .unwrap();
        let sweep = tokio::spawn(async move { super::run_retention_sweep(&path, 7).await });
        let started = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let elapsed = started.elapsed();
        conn.execute_batch("COMMIT;").unwrap();
        sweep.await.unwrap().unwrap();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "runtime stalled for {elapsed:?}"
        );
    }

    #[test]
    fn migrations_ignore_untrusted_partition_identifiers() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE logs_2024_01_01(timestamp INTEGER);
            CREATE TABLE audit_canary(value INTEGER);
            INSERT INTO audit_canary VALUES (1);
            CREATE TABLE \"logs_bad; DROP TABLE audit_canary;--\"(unrelated INTEGER);
            CREATE TABLE logs_9999_99_99(unrelated INTEGER);",
        )
        .unwrap();
        super::migrate_legacy_tables(&conn).unwrap();
        super::migrate_partition_indexes(&conn).unwrap();
        assert_eq!(
            conn.query_row("SELECT value FROM audit_canary", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('logs_2024_01_01') WHERE name='resolver'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(columns, 1);
        let columns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('logs_9999_99_99') WHERE name='resolver'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(columns, 0);
    }
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_restart_backoff_grows_then_caps() {
        assert_eq!(restart_backoff(0), Duration::from_secs(1));
        assert_eq!(restart_backoff(1), Duration::from_secs(2));
        assert_eq!(restart_backoff(2), Duration::from_secs(4));
        assert_eq!(restart_backoff(3), Duration::from_secs(8));
        assert_eq!(
            restart_backoff(6),
            Duration::from_secs(60),
            "2^6=64s should already be clamped to the 60s cap"
        );
        assert_eq!(
            restart_backoff(100),
            MAX_RESTART_BACKOFF,
            "must never exceed the cap regardless of how many failures"
        );
    }

    fn sample_entry(name: &str) -> LogEntry {
        LogEntry {
            timestamp: SystemTime::now(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            name: name.to_string(),
            qtype: RecordType::A,
            response_code: ResponseCode::NoError,
            duration_ns: 100,
            verdict: FilterVerdict::Pass,
            resolver: Cow::Borrowed("Test"),
        }
    }

    #[test]
    fn test_flush_batch_preserves_entries_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let mut conn = Connection::open(&db_path).unwrap();
        let mut seed_batch = vec![sample_entry("seed.com")];
        flush_batch(&mut seed_batch, &mut conn).unwrap();
        assert!(
            seed_batch.is_empty(),
            "a successful flush must clear the batch"
        );
        drop(conn);

        // Re-open read-only: the transaction inside flush_batch will fail
        // as soon as it tries to write, simulating a mid-flush failure.
        let mut ro_conn =
            Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();

        let mut batch = vec![sample_entry("a.com"), sample_entry("b.com")];
        let result = flush_batch(&mut batch, &mut ro_conn);

        assert!(result.is_err(), "expected the read-only flush to fail");
        assert_eq!(
            batch.len(),
            2,
            "entries must survive a failed flush instead of being dropped by an early drain"
        );
    }

    #[test]
    fn test_initialize_database_enables_wal_mode() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("wal_test.db");

        initialize_database(&db_path).unwrap();

        // New connections must observe the durable WAL mode established at startup.
        let conn = Connection::open(&db_path).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn test_flush_creates_only_the_timestamp_index() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("idx.db");
        let mut conn = Connection::open(&db_path).unwrap();

        let mut batch = vec![sample_entry("indexed.com")];
        flush_batch(&mut batch, &mut conn).unwrap();

        let table: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'logs_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();

        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name = ?1")
            .unwrap();
        let indexes: Vec<String> = stmt
            .query_map([&table], |r| r.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();

        assert!(
            indexes.iter().any(|i| i.ends_with("_timestamp")),
            "ORDER BY timestamp DESC needs an index, got {:?}",
            indexes
        );
        assert_eq!(
            indexes.len(),
            1,
            "stats come from rollups; partitions only need the timestamp index, got {:?}",
            indexes
        );
    }

    #[test]
    fn test_startup_migration_fixes_indexes_on_preexisting_partitions() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("backfill.db");

        // A partition created by an older build: correct columns, but only
        // the original (now obsolete) name index.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE logs_2021_02_03 (
                timestamp INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                name TEXT NOT NULL,
                qtype TEXT NOT NULL,
                response_code TEXT NOT NULL,
                duration_ns INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                resolver TEXT NOT NULL DEFAULT 'Unknown'
            );
            CREATE INDEX idx_logs_2021_02_03_name ON logs_2021_02_03(name);",
        )
        .unwrap();
        drop(conn);

        initialize_database(&db_path).unwrap();

        let conn = Connection::open(&db_path).unwrap();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name = 'logs_2021_02_03'")
            .unwrap();
        let indexes: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect();

        assert!(
            indexes.iter().any(|i| i.ends_with("_timestamp")),
            "got {:?}",
            indexes
        );
        assert!(
            !indexes.iter().any(|i| i.ends_with("_name")),
            "obsolete name indexes must be dropped, got {:?}",
            indexes
        );
    }

    #[test]
    fn test_migrate_legacy_tables_adds_missing_resolver_column() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("legacy.db");

        // Simulate a partition table created before the `resolver` column
        // existed.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE logs_2020_01_01 (
                timestamp INTEGER NOT NULL,
                client_ip TEXT NOT NULL,
                name TEXT NOT NULL,
                qtype TEXT NOT NULL,
                response_code TEXT NOT NULL,
                duration_ns INTEGER NOT NULL,
                verdict TEXT NOT NULL
            );",
        )
        .unwrap();

        migrate_legacy_tables(&conn).unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(logs_2020_01_01)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get(1))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            columns.contains(&"resolver".to_string()),
            "expected resolver column to be added, got {:?}",
            columns
        );

        // Migration must be idempotent for tables that already have the column.
        migrate_legacy_tables(&conn).unwrap();
    }
}
