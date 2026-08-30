//! The backup and restore-verify harness (D6).
//!
//! D6 makes this contract-enforced so no module can ship without one, and the
//! reason is an incident rather than a principle: on 2026-06-16 a faulty
//! restore-verification check destroyed 3,622 memories. The check passed; the
//! rows were gone.
//!
//! **A backup nobody has restored is a hypothesis.** So the contract is backup
//! *and* verified restore, and the verification is the part with tests.
//!
//! D6 also accepts what this cannot give: with one database per module (D58)
//! there is no global point-in-time snapshot, so these are per-module guarantees
//! and nothing here claims consistency across modules.

/// What a restore produced, as counted against what the backup recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub rows_backed_up: u64,
    pub rows_restored: u64,
    pub tables: u64,
}

/// Deliberately three outcomes rather than a `Result`. An empty database
/// verifies, but "verified" and "verified, and there was nothing in it" must not
/// look alike to a caller — a new module legitimately has no rows, and so does
/// one whose backup silently captured nothing.
#[derive(Debug)]
pub enum VerifyOutcome {
    Verified,
    VerifiedEmpty,
    Failed(BackupError),
}

impl RestoreReport {
    pub fn verify(&self) -> VerifyOutcome {
        if self.tables == 0 && (self.rows_backed_up > 0 || self.rows_restored > 0) {
            return VerifyOutcome::Failed(BackupError::Incoherent {
                detail: format!(
                    "{} rows reported across 0 tables — the count and the schema disagree",
                    self.rows_backed_up.max(self.rows_restored)
                ),
            });
        }

        if self.rows_backed_up != self.rows_restored {
            // Not only the under-count. Restoring MORE rows than were backed up
            // means the restore landed on a database that was not empty, so the
            // result is a mix of two states and nobody can say which rows came
            // from where.
            return VerifyOutcome::Failed(BackupError::RowCountMismatch {
                expected: self.rows_backed_up,
                found: self.rows_restored,
            });
        }

        if self.rows_backed_up == 0 {
            VerifyOutcome::VerifiedEmpty
        } else {
            VerifyOutcome::Verified
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error(
        "restore verification failed: backed up {expected} rows, restored {found}. \
         The backup is not proven and must not be relied on."
    )]
    RowCountMismatch { expected: u64, found: u64 },

    #[error("restore verification could not be trusted: {detail}")]
    Incoherent { detail: String },
}

// ---------------------------------------------------------------------------
// The counting half. `RestoreReport` is arithmetic over numbers; this is where
// the numbers come from, and a report built from anything else is the 2026-06-16
// failure waiting to happen — a check that passes because it was handed the
// counts it wanted.
// ---------------------------------------------------------------------------

use sqlx::{AssertSqlSafe, MySqlPool, Row};

/// What one schema actually contains, right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Census {
    pub tables: u64,
    pub rows: u64,
}

/// Count tables and rows in `schema` by reading every table.
///
/// **Not `information_schema.TABLES.TABLE_ROWS`**, which is an InnoDB *estimate*
/// derived from sampled index statistics and can be off by a wide margin — one
/// query, and it would make verification cheap and wrong. Verification is the
/// thing that failed on 2026-06-16, so it counts for real.
pub async fn census(pool: &MySqlPool, schema: &str) -> Result<Census, sqlx::Error> {
    let names: Vec<String> = sqlx::query(
        "SELECT TABLE_NAME FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'",
    )
    .bind(schema)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| r.try_get::<String, _>(0))
    .collect::<Result<_, _>>()?;

    let mut rows = 0u64;
    for name in &names {
        // The name came from information_schema for this schema, not from a
        // caller, and it is backquoted — an identifier cannot be bound as a
        // parameter, so this is the seam that has to be argued rather than
        // assumed.
        // AUDIT: an identifier cannot be a bound parameter, so this is the one
        // place here that interpolates. `name` came from information_schema for
        // this schema rather than from a caller, and both identifiers are
        // backquoted with embedded backquotes doubled — the MariaDB escape.
        // `schema` is caller-supplied, so it gets the same treatment rather than
        // being trusted for being "just a schema name".
        let n: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM `{}`.`{}`",
            schema.replace('`', "``"),
            name.replace('`', "``")
        )))
        .fetch_one(pool)
        .await?;
        rows += n as u64;
    }

    Ok(Census {
        tables: names.len() as u64,
        rows,
    })
}
