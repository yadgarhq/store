//! Migrations: this crate runs them, modules own them.
//!
//! D7 keeps `store` free of entity schemas, so it cannot hold anyone's
//! migrations. It can only take what a module hands it and guarantee three
//! things: applied in version order, applied exactly once, and never applied to
//! a database that has already moved past them.
//!
//! Everything here is the ordering and safety logic, deliberately separate from
//! executing SQL, because that half is testable without a database and is where
//! the mistakes that corrupt data actually live.

/// One migration. `sql` is opaque — this crate never parses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    /// Strictly increasing, starting at 1. Zero is reserved (see
    /// [`MigrationError::ZeroVersion`]).
    pub version: u64,
    /// For error messages and the applied-migrations table. Not an identifier.
    pub name: String,
    pub sql: String,
}

/// A module's migrations, validated on construction.
///
/// Validating here rather than at apply time is deliberate: a duplicate version
/// is a mistake in the source tree, and finding it on the deployment that
/// happens to run second is finding it in the worst place.
#[derive(Debug, Clone)]
pub struct MigrationSet(Vec<Migration>);

impl MigrationSet {
    pub fn new(mut migrations: Vec<Migration>) -> Result<Self, MigrationError> {
        // Sorted here rather than trusting the caller. A module builds this list
        // by reading a directory, and directory order is not sorted order on
        // every filesystem — the difference between a deterministic schema and
        // one that depends on which machine ran it.
        migrations.sort_by_key(|m| m.version);

        if let Some(m) = migrations.iter().find(|m| m.version == 0) {
            return Err(MigrationError::ZeroVersion {
                name: m.name.clone(),
            });
        }

        for pair in migrations.windows(2) {
            if pair[0].version == pair[1].version {
                return Err(MigrationError::DuplicateVersion {
                    version: pair[0].version,
                    first: pair[0].name.clone(),
                    second: pair[1].name.clone(),
                });
            }
        }

        Ok(Self(migrations))
    }

    pub fn versions(&self) -> Vec<u64> {
        self.0.iter().map(|m| m.version).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Everything above `applied`, in order.
    pub fn pending_after(&self, applied: u64) -> impl Iterator<Item = &Migration> {
        self.0.iter().filter(move |m| m.version > applied)
    }

    /// Refuse to run against a database that is ahead of this binary.
    ///
    /// The deployment this exists for is a rollback: the database sits at
    /// version 5 while the older binary knows only 4. Treating that as "nothing
    /// pending" runs old code against a newer schema **silently**, which is how
    /// data is corrupted rather than how an outage happens. Failing at boot is
    /// the whole point — the same reasoning as D7's capability probe.
    pub fn check_not_ahead(&self, applied: u64) -> Result<(), MigrationError> {
        let known = self.0.last().map(|m| m.version).unwrap_or(0);
        if applied > known {
            return Err(MigrationError::DatabaseAhead { applied, known });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error(
        "migrations {first} and {second} both claim version {version}; \
         one of them would silently never apply"
    )]
    DuplicateVersion {
        version: u64,
        first: String,
        second: String,
    },

    #[error(
        "migration {name} uses version 0, which is reserved: 0 is the marker \
         for a database with nothing applied"
    )]
    ZeroVersion { name: String },

    #[error(
        "database is at migration {applied} but this binary knows only up to \
         {known} — it is running against a schema from a newer version. \
         Refusing to start rather than operating on it blind."
    )]
    DatabaseAhead { applied: u64, known: u64 },

    #[error("migration {version} ({name}) failed: {source}")]
    Failed {
        version: u64,
        name: String,
        #[source]
        source: sqlx::Error,
    },

    #[error("the engine rejected a migration-ledger operation: {0}")]
    Engine(#[source] sqlx::Error),

    #[error(
        "could not take the migration lock within {seconds}s. Another replica is \
         migrating and has not finished, or one died holding a connection. \
         Refusing to migrate concurrently — that is what corrupts a schema."
    )]
    LockUnavailable { seconds: i32 },
}

impl MigrationError {
    fn engine(e: sqlx::Error) -> Self {
        Self::Engine(e)
    }
}

// ---------------------------------------------------------------------------
// Execution. Everything above is testable without a database and is where the
// mistakes that corrupt data live; this half is where they take effect.
// ---------------------------------------------------------------------------

use sqlx::{AssertSqlSafe, MySqlPool};

/// Where the applied version is recorded. One row per applied migration, never
/// updated — so the history is readable, not just the high-water mark.
const LEDGER: &str = "yadgar_schema_migrations";

/// A cluster-wide lock name, so concurrent replicas serialise on migration.
///
/// MariaDB's GET_LOCK is held by a CONNECTION and released when it drops, which
/// is the property that matters here: a replica killed mid-migration cannot
/// leave the lock held forever.
const LOCK: &str = "yadgar_migrate";

/// How long a replica waits for another one's migration before giving up.
///
/// Long enough for a real migration on a real table, short enough that a
/// deadlock surfaces as a boot failure rather than a pod hanging in Running.
const LOCK_TIMEOUT_SECS: i32 = 60;

/// Apply everything pending, in order, and return the version now applied.
///
/// **One migration, one transaction.** Not one transaction for the whole set:
/// MariaDB commits implicitly on DDL, so a multi-statement "transaction" around
/// `ALTER TABLE` is a transaction in name only, and believing otherwise means
/// believing a half-applied set will roll back when it will not. Per-migration
/// is the honest unit — a failure leaves earlier migrations applied and recorded,
/// which is recoverable because the ledger says exactly where it stopped.
pub async fn apply(pool: &MySqlPool, set: &MigrationSet) -> Result<u64, MigrationError> {
    // SERIALISE ACROSS REPLICAS, and this is not belt-and-braces.
    //
    // D55 requires at least two replicas and both start at once. Without this
    // lock both read `applied = 0`, both run migration 1, one wins and the other
    // dies on "Table 'x' already exists" — then crash-loops, because a failed
    // migration is a failed boot. Observed on the first real two-replica deploy
    // of task-db, and reproduced in tests/engine.rs. A single process cannot
    // exhibit it, which is the entire argument for D55.
    //
    // A transaction would not have helped: MariaDB commits implicitly on DDL, so
    // the racing CREATE TABLE is visible the moment it runs.
    //
    // The lock is held by a CONNECTION and released when that connection drops,
    // so a replica killed mid-migration cannot strand it.
    let mut lock_conn = pool.acquire().await.map_err(MigrationError::engine)?;
    let acquired: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, ?)")
        .bind(LOCK)
        .bind(LOCK_TIMEOUT_SECS)
        .fetch_one(&mut *lock_conn)
        .await
        .map_err(MigrationError::engine)?;

    if acquired != Some(1) {
        return Err(MigrationError::LockUnavailable {
            seconds: LOCK_TIMEOUT_SECS,
        });
    }

    let outcome = apply_locked(pool, set).await;

    // Released explicitly rather than left to the connection dropping, so the
    // next replica proceeds immediately instead of waiting on pool recycling.
    let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
        .bind(LOCK)
        .execute(&mut *lock_conn)
        .await;

    outcome
}

async fn apply_locked(pool: &MySqlPool, set: &MigrationSet) -> Result<u64, MigrationError> {
    // AUDIT (sqlx 0.9 requires one): the only interpolation is LEDGER, a private
    // const in this file. No caller input reaches it.
    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE TABLE IF NOT EXISTS {LEDGER} (
             version BIGINT UNSIGNED NOT NULL PRIMARY KEY,
             name    VARCHAR(255)    NOT NULL,
             applied_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
         )"
    )))
    .execute(pool)
    .await
    .map_err(MigrationError::engine)?;

    // AUDIT: LEDGER const only.
    let applied: u64 = sqlx::query_scalar(AssertSqlSafe(format!(
        // CAST is load-bearing, not decoration: MariaDB types
        // COALESCE(MAX(unsigned), 0) as DECIMAL, and decoding that into u64
        // fails at runtime with a type mismatch. Found by running against a
        // real engine; no amount of logic testing would have surfaced it.
        "SELECT CAST(COALESCE(MAX(version), 0) AS UNSIGNED) FROM {LEDGER}"
    )))
    .fetch_one(pool)
    .await
    .map_err(MigrationError::engine)?;

    // Before applying anything: refuse a database this binary is older than.
    set.check_not_ahead(applied)?;

    let mut current = applied;
    for m in set.pending_after(applied) {
        // AUDIT: this IS the module's migration, and D7 makes `sql` opaque —
        // this crate never parses it and cannot hold anyone's schema. The
        // trust boundary is the module's own source tree, which is the same
        // boundary as the code calling this function. There is no untrusted
        // input here to escape; a hostile migration file is a compromised
        // repository, not an injection.
        sqlx::raw_sql(AssertSqlSafe(m.sql.clone()))
            .execute(pool)
            .await
            .map_err(|e| MigrationError::Failed {
                version: m.version,
                name: m.name.clone(),
                source: e,
            })?;

        // AUDIT: LEDGER const; version and name are bound parameters.
        sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO {LEDGER} (version, name) VALUES (?, ?)"
        )))
        .bind(m.version)
        .bind(&m.name)
        .execute(pool)
        .await
        .map_err(MigrationError::engine)?;

        current = m.version;
    }

    Ok(current)
}
