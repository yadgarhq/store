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
        "could not take the migration lock {name} within {seconds}s. Another \
         process on this database server holds it: a replica of this module \
         that is still migrating, another install migrating the same database, \
         or one that died holding a connection. Refusing to migrate concurrently — that is what \
         corrupts a schema. The wait is the chart key \
         database.migrationLockTimeoutSeconds."
    )]
    LockUnavailable { name: String, seconds: i32 },

    #[error(
        "the migration pool has no default database (SELECT DATABASE() is \
         NULL), so there is nothing to migrate and no name for the \
         per-database migration lock. Set the chart key database.name."
    )]
    NoDatabase,

    #[error(
        "the migration lock wait must be at least 1 second, and {seconds} was \
         configured. A negative wait never takes the lock and zero never waits \
         for the other replica, so either fails the boot for the wrong reason."
    )]
    LockTimeoutInvalid { seconds: i32 },
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

/// The PREFIX of the per-database lock name ([`LockOptions::per_database_name`]),
/// so concurrent replicas of one database serialise on migration.
///
/// MariaDB's GET_LOCK is held by a SESSION and released when the session ends,
/// which is the property that matters here: a replica killed mid-migration
/// cannot leave the lock held forever. A session ends when its connection
/// CLOSES, not when a pooled handle to it drops: a dropped handle returns the
/// session to the pool with its locks still held, which is why `apply` marks
/// its lock connection `close_on_drop`.
///
/// **THIS IS AN ADDRESS, NOT A KNOB**, in the sense `yadgar-lifecycle`'s
/// `CONFIG_DIR` is one. ADR-0569 governs the VALUE of a setting. A lock name is
/// an identifier every replica of a module must agree on, or they do not
/// serialise against each other; letting an installation vary it would buy
/// nothing and could only break that. `tests/migrate.rs` pins the spelling.
///
/// **ITS SCOPE WAS THE DEFECT (yaadgaar #368, ADR-1006).** `GET_LOCK` names are
/// server-wide, so every module whose database shares one server serialised its
/// migrations on this one name. The fix is a per-database name
/// ([`LockOptions::per_database_name`]), rolled out in two releases because a
/// rollout runs old and new pods at once:
///
/// - **Release A (v0.5.x)** took this name alone, server-wide (the legacy
///   lock), FIRST and then the per-database name, on the same connection.
///   Pods older than A take only the legacy name, so they serialised against
///   A pods.
/// - **Release B (this one)** takes only the per-database name. Release A pods
///   hold that name too, so A and B still serialise. B must not reach a module
///   until every pod of it runs A: a pod older than A and a B pod share no
///   name, which reopens D55's double-CREATE race for the rollout. For the
///   same reason a module running B rolls back only to A, never to v0.4.x.
const LOCK: &str = "yadgar_migrate";

/// MySQL's `GET_LOCK` name limit, in characters. MariaDB 11.8.9 measured 192;
/// the lower one is the bound that holds on every engine D80 admits.
const LOCK_NAME_MAX_CHARS: usize = 64; // ADR-0569-EXCEPTION(CC): an engine limit, not a tunable.

/// Hex digits of SHA-256 kept when a per-database name would pass the limit.
const LOCK_NAME_HASH_HEX: usize = 16; // ADR-0569-EXCEPTION(CC): part of the lock address every replica must agree on.

/// Which lock to take, and how long to wait for it.
///
/// **THE WAIT HAS NO DEFAULT HERE (ADR-0569).** Up to v0.2.13 this struct
/// implemented `Default` with a compiled-in 60 seconds, and `apply` used it, so
/// every `-db` twin ran a 60-second wait that no configuration file stated and
/// no operator could change. How long a migration takes is a property of the
/// installation — its table sizes, its engine, a managed service's IOPS — so the
/// wait is a knob, and a knob is read from the owning service's configuration
/// and handed in. The caller is the one that knows which knob and which file to
/// name when it is absent; this crate refuses only a value that cannot mean
/// "wait for the other replica", via [`LockOptions::new`].
///
/// The fields are private so that refusal cannot be stepped around with a
/// struct literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockOptions {
    /// Server-wide `GET_LOCK` name. [`LOCK`] outside tests.
    name: String,
    /// Seconds to wait before giving up and failing the boot. Always >= 1.
    timeout_secs: i32,
}

impl LockOptions {
    /// The migration lock, waiting `timeout_secs` for another replica's
    /// migration before failing the boot.
    ///
    /// # Errors
    ///
    /// [`MigrationError::LockTimeoutInvalid`] for anything below one second.
    /// Both refusals are MEASURED on MariaDB 11.8.9 rather than reasoned:
    ///
    /// - a NEGATIVE wait makes `GET_LOCK` return NULL at once with warning 1411
    ///   "Incorrect timeout value", even when nobody holds the lock. Passed
    ///   through, the migration never runs and the boot fails as
    ///   [`MigrationError::LockUnavailable`], telling the operator another
    ///   replica is migrating when none is;
    /// - ZERO makes `GET_LOCK` try once and not wait. D55 starts two replicas at
    ///   once, so the second fails its boot on every rollout that carries a
    ///   migration.
    pub fn new(timeout_secs: i32) -> Result<Self, MigrationError> {
        if timeout_secs < 1 {
            return Err(MigrationError::LockTimeoutInvalid {
                seconds: timeout_secs,
            });
        }
        Ok(Self {
            name: LOCK.to_string(),
            timeout_secs,
        })
    }

    /// The same lock under another name — FOR TESTS ONLY, behind the
    /// `test-support` feature so no service can reach it.
    ///
    /// `GET_LOCK` is server-wide rather than per-database, so a suite that
    /// holds the lock on purpose to reach `LockUnavailable` must not collide
    /// with every other test taking [`LOCK`]. A service has no use for this:
    /// replicas that took different names would not serialise at all.
    #[cfg(feature = "test-support")]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// The prefix of the per-database `GET_LOCK` name. Release B no longer
    /// takes this name by itself.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The per-database `GET_LOCK` name for `database`: the prefix, a colon,
    /// and the database name. When that would pass 64 characters it is the
    /// prefix, a colon, and the first 16 hex digits of SHA-256 of the
    /// database name instead. A database name may itself be 64 characters.
    ///
    /// Under `with_name` the override replaces the prefix too, so a test that
    /// holds a lock on purpose collides with no other test on either name.
    pub fn per_database_name(&self, database: &str) -> String {
        let literal = format!("{}:{database}", self.name);
        if literal.chars().count() <= LOCK_NAME_MAX_CHARS {
            return literal;
        }
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(database.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}:{}", self.name, &hex[..LOCK_NAME_HASH_HEX])
    }

    /// Seconds a replica waits for another one's migration.
    pub fn timeout_secs(&self) -> i32 {
        self.timeout_secs
    }
}

/// Apply everything pending, in order, and return the version now applied.
///
/// **One migration, one transaction.** Not one transaction for the whole set:
/// MariaDB commits implicitly on DDL, so a multi-statement "transaction" around
/// `ALTER TABLE` is a transaction in name only, and believing otherwise means
/// believing a half-applied set will roll back when it will not. Per-migration
/// is the honest unit — a failure leaves earlier migrations applied and recorded,
/// which is recoverable because the ledger says exactly where it stopped.
///
/// `lock` carries the wait the caller read from its own configuration; there is
/// no form of this function that supplies one for it (ADR-0569).
pub async fn apply(
    pool: &MySqlPool,
    set: &MigrationSet,
    lock: &LockOptions,
) -> Result<u64, MigrationError> {
    // SERIALISE ACROSS REPLICAS, and this is not belt-and-braces.
    //
    // D55 requires at least two replicas and both start at once. Without this
    // lock both read `applied = 0`, both run migration 1, one wins and the other
    // dies on "Table 'x' already exists" — then crash-loops, because a failed
    // migration is a failed boot. Observed on the first real two-replica deploy
    // of task-db, and reproduced in tests/engine_migrate.rs. A single process cannot
    // exhibit it, which is the entire argument for D55.
    //
    // A transaction would not have helped: MariaDB commits implicitly on DDL, so
    // the racing CREATE TABLE is visible the moment it runs.
    //
    // The lock is held by a SESSION. A killed process ends its sessions, so a
    // replica killed mid-migration cannot strand it. An in-process CANCELLATION
    // is different: dropping this future (a caller's timeout, a shutdown
    // `select!`) drops the pooled handle, and by default that RETURNS the
    // session to the pool still holding every lock it took — and still
    // waiting server-side on one it asked for (measured on MariaDB 11.8.9:
    // both names held 7 s later; review S1/S3 on store#37). `close_on_drop`
    // ends the session instead, and the server releases its locks.
    let mut lock_conn = pool.acquire().await.map_err(MigrationError::engine)?;
    lock_conn.close_on_drop();

    // The database the migrations will run in names the per-database lock.
    // Asked of the engine, not of the configuration: it is the session's own
    // answer, the one the migrations will actually see.
    let database: Option<String> = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&mut *lock_conn)
        .await
        .map_err(MigrationError::engine)?;
    let per_database = lock.per_database_name(&database.ok_or(MigrationError::NoDatabase)?);

    // RELEASE B: the per-database name only (see `LOCK`).
    take_lock(
        &mut lock_conn,
        &per_database,
        lock.timeout_secs,
        lock.timeout_secs,
    )
    .await?;

    let outcome = apply_locked(pool, set).await;

    // Released explicitly rather than left to the close on drop, so the next
    // replica proceeds immediately.
    release_lock(&mut lock_conn, &per_database).await;

    outcome
}

/// Take `name`, waiting up to `wait_secs`. A refusal reports `budget_secs`,
/// the whole wait the operator configured, which is the number they can act on.
/// A `wait_secs` of 0 tries once; that is the end of a spent budget, not the
/// zero wait `LockOptions::new` refuses.
async fn take_lock(
    conn: &mut sqlx::MySqlConnection,
    name: &str,
    wait_secs: i32,
    budget_secs: i32,
) -> Result<(), MigrationError> {
    let acquired: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, ?)")
        .bind(name)
        .bind(wait_secs)
        .fetch_one(&mut *conn)
        .await
        .map_err(MigrationError::engine)?;
    if acquired != Some(1) {
        return Err(MigrationError::LockUnavailable {
            name: name.to_string(),
            seconds: budget_secs,
        });
    }
    Ok(())
}

async fn release_lock(conn: &mut sqlx::MySqlConnection, name: &str) {
    let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
        .bind(name)
        .execute(&mut *conn)
        .await;
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
