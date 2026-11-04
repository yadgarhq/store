//! Every refusal `migrate` can return.

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

    #[error(
        "migration {version} ({name}) was edited after it was applied: the \
         ledger records SQL with sha256 {recorded}, this binary carries \
         {embedded}. The database never ran the new SQL, so it does not have \
         the schema this binary expects. Refusing to start. Restore the \
         migration as it shipped and put the change in a new migration."
    )]
    ChecksumMismatch {
        version: u64,
        name: String,
        recorded: String,
        embedded: String,
    },

    #[error(
        "migration {version} is recorded in the ledger as {recorded}, with no \
         checksum, but this binary's migration {version} is {embedded}. The \
         ledger predates checksums, so its name is the only evidence of what \
         ran, and it is not this migration. Refusing to start rather than \
         recording this binary's checksum for SQL that never ran."
    )]
    LedgerNameMismatch {
        version: u64,
        recorded: String,
        embedded: String,
    },

    #[error(
        "migration {version} ({name}) has no row in the ledger, but migration \
         {applied} has already run: it was added below a migration that \
         shipped before it. Applying it now would run it out of order, and \
         skipping it would leave it unapplied on every boot. Refusing to \
         start. Renumber it above {applied}."
    )]
    NotApplied {
        version: u64,
        name: String,
        applied: u64,
    },

    #[error(
        "the ledger records migration {version}, which this binary does not \
         carry: the database ran SQL this binary knows nothing about. Refusing \
         to start rather than migrating on top of it. Restore the migration as \
         it shipped."
    )]
    LedgerUnknown { version: u64 },

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
        "could not take the per-database migration lock {name} within \
         {seconds}s: another process on this database server holds it. It may \
         be a pod of this module that is still migrating, another install \
         migrating the same database, or a process that died holding its \
         connection. Refusing to migrate concurrently — that is what corrupts \
         a schema. The wait is the chart key \
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
    pub(super) fn engine(e: sqlx::Error) -> Self {
        Self::Engine(e)
    }
}
