use std::path::{Path, PathBuf};
use tracing::debug;

use crate::config::Config;

#[derive(Debug)]
pub enum ConfigStoreError {
    Sqlite { path: PathBuf, message: String },
    Serialize(String),
    Deserialize { path: PathBuf, message: String },
    Validation(String),
    UnsupportedSchema { path: PathBuf, version: i64 },
    RevisionConflict { path: PathBuf, expected: i64 },
    SeedConflict { path: PathBuf },
    TaskJoin(String),
    Io { path: PathBuf, message: String },
}

impl std::fmt::Display for ConfigStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite { path, message } => {
                write!(f, "database error for '{}': {}", path.display(), message)
            }
            Self::Serialize(msg) => write!(f, "failed to serialize configuration: {}", msg),
            Self::Deserialize { path, message } => {
                write!(
                    f,
                    "failed to deserialize configuration from '{}': {}",
                    path.display(),
                    message
                )
            }
            Self::Validation(msg) => write!(f, "configuration validation failed: {}", msg),
            Self::UnsupportedSchema { path, version } => {
                write!(
                    f,
                    "unsupported schema version {} for state database '{}'; delete development database to reset",
                    version,
                    path.display()
                )
            }
            Self::RevisionConflict { path, expected } => {
                write!(
                    f,
                    "revision conflict for '{}': expected revision {}",
                    path.display(),
                    expected
                )
            }
            Self::SeedConflict { path } => {
                write!(
                    f,
                    "initialization conflict for '{}': configuration row already exists",
                    path.display()
                )
            }
            Self::TaskJoin(msg) => write!(f, "blocking task join failed: {}", msg),
            Self::Io { path, message } => {
                write!(f, "I/O error for '{}': {}", path.display(), message)
            }
        }
    }
}

impl std::error::Error for ConfigStoreError {}

fn ensure_file_permissions(path: &Path) -> Result<(), ConfigStoreError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| ConfigStoreError::Io {
            path: parent.to_path_buf(),
            message: e.to_string(),
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|e| ConfigStoreError::Io {
                    path: path.to_path_buf(),
                    message: e.to_string(),
                })?;
        } else {
            let metadata = std::fs::metadata(path).map_err(|e| ConfigStoreError::Io {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|e| ConfigStoreError::Io {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        }
    }

    Ok(())
}

fn open_connection(path: &Path) -> Result<rusqlite::Connection, ConfigStoreError> {
    ensure_file_permissions(path)?;

    let conn = rusqlite::Connection::open(path).map_err(|e| ConfigStoreError::Sqlite {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    conn.execute_batch(
        "PRAGMA busy_timeout = 5000;
         PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;",
    )
    .map_err(|e| ConfigStoreError::Sqlite {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let version: i64 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

    match version {
        0 => {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS config_state (
                    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
                    revision        INTEGER NOT NULL CHECK (revision >= 1),
                    config_toml     TEXT NOT NULL,
                    updated_at_unix INTEGER NOT NULL
                );
                PRAGMA user_version = 1;",
            )
            .map_err(|e| ConfigStoreError::Sqlite {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        }
        1 => {}
        v => {
            return Err(ConfigStoreError::UnsupportedSchema {
                path: path.to_path_buf(),
                version: v,
            });
        }
    }

    Ok(conn)
}

fn load_current_sync(path: &Path) -> Result<Option<(Config, i64)>, ConfigStoreError> {
    let conn = open_connection(path)?;

    let mut stmt = conn
        .prepare("SELECT revision, config_toml FROM config_state WHERE singleton = 1;")
        .map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

    let mut rows = stmt.query([]).map_err(|e| ConfigStoreError::Sqlite {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    if let Some(row) = rows.next().map_err(|e| ConfigStoreError::Sqlite {
        path: path.to_path_buf(),
        message: e.to_string(),
    })? {
        let revision: i64 = row.get(0).map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let config_toml: String = row.get(1).map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        let config: Config =
            toml::from_str(&config_toml).map_err(|e| ConfigStoreError::Deserialize {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;

        config.validate().map_err(ConfigStoreError::Validation)?;

        Ok(Some((config, revision)))
    } else {
        Ok(None)
    }
}

fn insert_seed_sync(path: &Path, config: &Config) -> Result<i64, ConfigStoreError> {
    config.validate().map_err(ConfigStoreError::Validation)?;

    let toml_str =
        toml::to_string_pretty(config).map_err(|e| ConfigStoreError::Serialize(e.to_string()))?;

    let conn = open_connection(path)?;
    let now = crate::config::now_epoch();

    let res = conn.execute(
        "INSERT INTO config_state (singleton, revision, config_toml, updated_at_unix)
         VALUES (1, 1, ?1, ?2);",
        rusqlite::params![toml_str, now],
    );

    match res {
        Ok(_) => Ok(1),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(ConfigStoreError::SeedConflict {
                path: path.to_path_buf(),
            })
        }
        Err(e) => Err(ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        }),
    }
}

fn update_config_sync(
    path: &Path,
    config: &Config,
    expected_revision: i64,
    reason: &'static str,
) -> Result<i64, ConfigStoreError> {
    config.validate().map_err(ConfigStoreError::Validation)?;

    let toml_str =
        toml::to_string_pretty(config).map_err(|e| ConfigStoreError::Serialize(e.to_string()))?;

    debug!(
        reason = reason,
        expected_revision = expected_revision,
        path = %path.display(),
        "Persisting configuration update"
    );

    let conn = open_connection(path)?;
    let now = crate::config::now_epoch();

    let mut stmt = conn
        .prepare(
            "UPDATE config_state
             SET revision = revision + 1,
                 config_toml = ?1,
                 updated_at_unix = ?2
             WHERE singleton = 1 AND revision = ?3
             RETURNING revision;",
        )
        .map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

    let mut rows = stmt
        .query(rusqlite::params![toml_str, now, expected_revision])
        .map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

    if let Some(row) = rows.next().map_err(|e| ConfigStoreError::Sqlite {
        path: path.to_path_buf(),
        message: e.to_string(),
    })? {
        let new_revision: i64 = row.get(0).map_err(|e| ConfigStoreError::Sqlite {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        Ok(new_revision)
    } else {
        Err(ConfigStoreError::RevisionConflict {
            path: path.to_path_buf(),
            expected: expected_revision,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ConfigStoreError> {
        let path = path.as_ref().to_path_buf();
        open_connection(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_current(&self) -> Result<Option<(Config, i64)>, ConfigStoreError> {
        load_current_sync(&self.path)
    }

    pub async fn load_current_async(&self) -> Result<Option<(Config, i64)>, ConfigStoreError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || load_current_sync(&path))
            .await
            .map_err(|e| ConfigStoreError::TaskJoin(e.to_string()))?
    }

    pub fn insert_seed(&self, config: &Config) -> Result<i64, ConfigStoreError> {
        insert_seed_sync(&self.path, config)
    }

    pub async fn insert_seed_async(&self, config: &Config) -> Result<i64, ConfigStoreError> {
        let path = self.path.clone();
        let config = config.clone();
        tokio::task::spawn_blocking(move || insert_seed_sync(&path, &config))
            .await
            .map_err(|e| ConfigStoreError::TaskJoin(e.to_string()))?
    }

    pub fn update_config(
        &self,
        config: &Config,
        expected_revision: i64,
        reason: &'static str,
    ) -> Result<i64, ConfigStoreError> {
        update_config_sync(&self.path, config, expected_revision, reason)
    }

    pub async fn update_config_async(
        &self,
        config: &Config,
        expected_revision: i64,
        reason: &'static str,
    ) -> Result<i64, ConfigStoreError> {
        let path = self.path.clone();
        let config = config.clone();
        tokio::task::spawn_blocking(move || {
            update_config_sync(&path, &config, expected_revision, reason)
        })
        .await
        .map_err(|e| ConfigStoreError::TaskJoin(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::base_config;

    #[test]
    fn test_fresh_database_starts_empty_then_inserts_seed() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();
        assert!(store.load_current().unwrap().is_none());

        let config = base_config();
        let rev = store.insert_seed(&config).unwrap();
        assert_eq!(rev, 1);

        let (loaded, rev2) = store.load_current().unwrap().expect("should have row");
        assert_eq!(rev2, 1);
        assert_eq!(loaded, config);
    }

    #[test]
    fn test_reopening_loads_same_config_and_revision() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let config = base_config();
        {
            let store = ConfigStore::open(&db_path).unwrap();
            store.insert_seed(&config).unwrap();
        }
        let store2 = ConfigStore::open(&db_path).unwrap();
        let (loaded, rev) = store2.load_current().unwrap().unwrap();
        assert_eq!(rev, 1);
        assert_eq!(loaded, config);
    }

    #[test]
    fn test_changing_seed_after_insertion_has_no_effect() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let config1 = base_config();
        let store = ConfigStore::open(&db_path).unwrap();
        store.insert_seed(&config1).unwrap();

        let mut config2 = config1.clone();
        config2.enforce_safesearch = !config2.enforce_safesearch;
        let res = store.insert_seed(&config2);
        assert!(matches!(res, Err(ConfigStoreError::SeedConflict { .. })));

        let (loaded, rev) = store.load_current().unwrap().unwrap();
        assert_eq!(rev, 1);
        assert_eq!(loaded.enforce_safesearch, config1.enforce_safesearch);
    }

    #[test]
    fn test_conditional_update_changes_config_and_returns_revision_2() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let config = base_config();
        let store = ConfigStore::open(&db_path).unwrap();
        store.insert_seed(&config).unwrap();

        let mut updated = config.clone();
        updated.enforce_safesearch = !updated.enforce_safesearch;
        let rev = store.update_config(&updated, 1, "test:update").unwrap();
        assert_eq!(rev, 2);

        let (loaded, loaded_rev) = store.load_current().unwrap().unwrap();
        assert_eq!(loaded_rev, 2);
        assert_eq!(loaded.enforce_safesearch, updated.enforce_safesearch);
    }

    #[test]
    fn test_stale_expected_revision_returns_conflict_and_preserves_config() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let config = base_config();
        let store = ConfigStore::open(&db_path).unwrap();
        store.insert_seed(&config).unwrap();

        let mut updated = config.clone();
        updated.enforce_safesearch = !updated.enforce_safesearch;
        let err = store.update_config(&updated, 99, "test:stale").unwrap_err();
        assert!(matches!(
            err,
            ConfigStoreError::RevisionConflict { expected: 99, .. }
        ));

        let (loaded, rev) = store.load_current().unwrap().unwrap();
        assert_eq!(rev, 1);
        assert_eq!(loaded, config);
    }

    #[test]
    fn test_invalid_stored_toml_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO config_state (singleton, revision, config_toml, updated_at_unix)
             VALUES (1, 1, 'invalid [ toml {', 100);",
            [],
        )
        .unwrap();

        let err = store.load_current().unwrap_err();
        assert!(matches!(err, ConfigStoreError::Deserialize { .. }));
    }

    #[test]
    fn test_stored_toml_failing_validate_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let store = ConfigStore::open(&db_path).unwrap();

        let mut config = base_config();
        config.upstreams.clear();
        let toml_str = toml::to_string_pretty(&config).unwrap();

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO config_state (singleton, revision, config_toml, updated_at_unix)
             VALUES (1, 1, ?1, 100);",
            rusqlite::params![toml_str],
        )
        .unwrap();

        let err = store.load_current().unwrap_err();
        assert!(matches!(err, ConfigStoreError::Validation(_)));
    }

    #[test]
    fn test_unsupported_user_version_fails_without_modification() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("PRAGMA user_version = 2;", []).unwrap();
        }

        let err = ConfigStore::open(&db_path).unwrap_err();
        match err {
            ConfigStoreError::UnsupportedSchema { version, .. } => assert_eq!(version, 2),
            other => panic!("Expected UnsupportedSchema, got {:?}", other),
        }

        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }

    #[cfg(unix)]
    #[test]
    fn test_database_mode_is_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.db");
        let _store = ConfigStore::open(&db_path).unwrap();

        let meta = std::fs::metadata(&db_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
