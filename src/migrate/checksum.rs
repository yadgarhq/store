//! Checksums of applied migrations (yaadgaar #249).
//!
//! The ledger used to record a version and a name only, so a migration edited
//! after it shipped was invisible: a store that applied the old SQL records the
//! version, never runs the new SQL, and drifts from what a fresh install builds
//! — how project-db v0.7.0 shipped broken. Each row now carries the SHA-256 of
//! the SQL that ran ([`Migration::checksum`]), and every boot compares.

use sqlx::{AssertSqlSafe, MySqlPool};

use super::{Migration, MigrationError, MigrationSet, LEDGER};

impl Migration {
    /// SHA-256 of `sql`'s exact bytes, lowercase hex: what the ledger records
    /// for this migration once it is applied, and what every later boot
    /// compares against. Exact bytes, never normalised SQL — whitespace inside a
    /// string literal is data, and this crate never parses `sql` (D7).
    pub fn checksum(&self) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.sql.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Add the `checksum` column to a ledger created before it existed (#249).
///
/// Probed in `information_schema` rather than `ADD COLUMN IF NOT EXISTS`, which
/// is MariaDB-only. Runs under the migration lock, so two replicas cannot both
/// see it absent and both add it.
pub(super) async fn add_checksum_column(pool: &MySqlPool) -> Result<(), MigrationError> {
    let present: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.COLUMNS \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = 'checksum'",
    )
    .bind(LEDGER)
    .fetch_one(pool)
    .await
    .map_err(MigrationError::engine)?;
    if present == 0 {
        // AUDIT: LEDGER const only.
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER TABLE {LEDGER} ADD COLUMN checksum CHAR(64) NULL"
        )))
        .execute(pool)
        .await
        .map_err(MigrationError::engine)?;
    }
    Ok(())
}

/// Compare every applied migration's recorded checksum to this binary's.
///
/// - **Recorded and equal**: fine.
/// - **Recorded and different**: [`MigrationError::ChecksumMismatch`]. The
///   migration was edited after it shipped, so this database never ran the SQL
///   this binary carries — the split between fresh and upgraded installs that
///   project-db v0.7.0 shipped.
/// - **Not recorded** (a row written before checksums existed): TRUST ON FIRST
///   USE. The SQL that actually ran is gone, so it cannot be verified; the
///   row's NAME is the only evidence, and it must equal the embedded
///   migration's name ([`MigrationError::LedgerNameMismatch`] otherwise). Then
///   this binary's checksum is recorded, and every later boot verifies against
///   it. An edit made before the first checksum-aware boot is NOT caught.
///
/// Every row is checked before any backfill is written, so a refusal writes no
/// checksum. The `checksum` column itself may already exist by then:
/// [`add_checksum_column`] runs first and its `ALTER` is DDL, which commits at
/// once. A recorded version this binary does not carry is not
/// checked here; one above the newest is refused by `check_not_ahead`.
pub(super) async fn verify_checksums(
    pool: &MySqlPool,
    set: &MigrationSet,
) -> Result<(), MigrationError> {
    // AUDIT: LEDGER const only.
    let rows: Vec<(u64, String, Option<String>)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT version, name, checksum FROM {LEDGER} ORDER BY version"
    )))
    .fetch_all(pool)
    .await
    .map_err(MigrationError::engine)?;

    let mut backfill = Vec::new();
    for (version, name, recorded) in rows {
        let Some(m) = set.pending_after(0).find(|m| m.version == version) else {
            continue;
        };
        let embedded = m.checksum();
        match recorded {
            Some(recorded) if recorded == embedded => {}
            Some(recorded) => {
                return Err(MigrationError::ChecksumMismatch {
                    version,
                    name: m.name.clone(),
                    recorded,
                    embedded,
                })
            }
            None if name == m.name => backfill.push((version, name, embedded)),
            None => {
                return Err(MigrationError::LedgerNameMismatch {
                    version,
                    recorded: name,
                    embedded: m.name.clone(),
                })
            }
        }
    }

    for (version, name, checksum) in backfill {
        // AUDIT: LEDGER const; checksum and version are bound parameters. The
        // `IS NULL` keeps a backfill from overwriting a recorded checksum.
        sqlx::query(AssertSqlSafe(format!(
            "UPDATE {LEDGER} SET checksum = ? WHERE version = ? AND checksum IS NULL"
        )))
        .bind(&checksum)
        .bind(version)
        .execute(pool)
        .await
        .map_err(MigrationError::engine)?;
        tracing::warn!(version, %name, %checksum, "backfilled the checksum of a migration applied before checksums were recorded (trust on first use)");
    }
    Ok(())
}
