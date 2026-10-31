//! Checksums of applied migrations against a real engine (yaadgaar #249).
//!
//! The ledger used to record a version and a name, so a migration edited after
//! it shipped was invisible: a store that had applied the old SQL records the
//! version, never runs the new SQL, and drifts from what a fresh install builds.
//! project-db v0.7.0 shipped broken exactly that way (its `tests/upgrade.rs`).
//! Now every applied row carries the SHA-256 of the SQL that ran, and a boot
//! whose embedded SQL differs refuses, naming the migration.
//!
//! No engine, no run. See `tests/common/mod.rs`.

mod common;

use common::{lock, migration, migrations, scratch_pool};
use yadgar_store::migrate::{self, MigrationError, MigrationSet};

/// `(version, name, checksum)` per ledger row, in version order.
async fn ledger(pool: &sqlx::MySqlPool) -> Vec<(u64, String, Option<String>)> {
    sqlx::query_as("SELECT version, name, checksum FROM yadgar_schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("ledger")
}

async fn exec(pool: &sqlx::MySqlPool, sql: &'static str) {
    sqlx::query(sql).execute(pool).await.expect(sql);
}

async fn table_exists(pool: &sqlx::MySqlPool, table: &str) -> bool {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT TABLE_NAME FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
    )
    .bind(table)
    .fetch_optional(pool)
    .await
    .expect("information_schema");
    found.is_some()
}

/// The set from `common::migrations` with migration 1's SQL edited in place,
/// plus a new migration 3 that must never run behind the refusal.
fn edited_set() -> MigrationSet {
    MigrationSet::new(vec![
        migration(
            1,
            "create_thing",
            "CREATE TABLE thing (id INT PRIMARY KEY, extra INT)",
        ),
        migration(2, "add_label", "ALTER TABLE thing ADD COLUMN label TEXT"),
        migration(3, "create_other", "CREATE TABLE other (id INT PRIMARY KEY)"),
    ])
    .expect("valid set")
}

fn embedded(set: &MigrationSet) -> Vec<(u64, String, Option<String>)> {
    set.pending_after(0)
        .map(|m| (m.version, m.name.clone(), Some(m.checksum())))
        .collect()
}

#[tokio::test]
async fn every_applied_migration_records_the_checksum_of_its_sql() {
    let pool = scratch_pool("ys_sum_fresh").await;
    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");
    assert_eq!(ledger(&pool).await, embedded(&migrations()));
}

/// THE CLAIM: an applied migration whose SQL changed refuses the boot, names
/// the migration, and refuses BEFORE anything pending runs.
#[tokio::test]
async fn an_applied_migration_edited_in_place_refuses_the_boot_naming_it() {
    let pool = scratch_pool("ys_sum_edited").await;
    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");

    let err = migrate::apply(&pool, &edited_set(), &lock())
        .await
        .expect_err("an edited applied migration must refuse the boot");
    assert!(
        matches!(err, MigrationError::ChecksumMismatch { version: 1, .. }),
        "the variant must name version 1: {err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains("migration 1 (create_thing)"),
        "names it: {text}"
    );
    assert!(
        text.contains(&migrations().pending_after(0).next().unwrap().checksum()),
        "carries the recorded digest: {text}"
    );
    assert!(
        !table_exists(&pool, "other").await,
        "migration 3 must not run behind the refusal"
    );
}

/// A ledger written before checksums existed, with the column itself absent:
/// the store every deployed module has today. It boots, and the column is
/// added and filled with this binary's digests (trust on first use).
#[tokio::test]
async fn a_ledger_from_before_checksums_gains_the_column_and_is_backfilled() {
    let pool = scratch_pool("ys_sum_legacy").await;
    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");
    exec(
        &pool,
        "ALTER TABLE yadgar_schema_migrations DROP COLUMN checksum",
    )
    .await;

    let applied = migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("a pre-checksum ledger must boot");
    assert_eq!(applied, 2);
    assert_eq!(ledger(&pool).await, embedded(&migrations()));
}

/// The backfill is stored, so the NEXT boot verifies against it: an edit made
/// after the backfill is caught.
#[tokio::test]
async fn a_backfilled_checksum_catches_a_later_edit() {
    let pool = scratch_pool("ys_sum_backfill").await;
    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");
    exec(&pool, "UPDATE yadgar_schema_migrations SET checksum = NULL").await;

    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("a NULL checksum is backfilled, not refused");
    assert_eq!(ledger(&pool).await, embedded(&migrations()));

    let err = migrate::apply(&pool, &edited_set(), &lock())
        .await
        .expect_err("the backfilled digest must be checked");
    assert!(matches!(
        err,
        MigrationError::ChecksumMismatch { version: 1, .. }
    ));
}

/// The one thing a pre-checksum row CAN be checked against is its name. A row
/// whose name differs from the embedded migration of that version is not the
/// migration this binary carries, so it is refused rather than backfilled.
#[tokio::test]
async fn a_row_without_a_checksum_under_another_name_is_refused_not_backfilled() {
    let pool = scratch_pool("ys_sum_renamed").await;
    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");
    exec(
        &pool,
        "UPDATE yadgar_schema_migrations SET checksum = NULL, name = 'something_else' \
         WHERE version = 2",
    )
    .await;

    let err = migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect_err("an unverifiable row under another name must refuse");
    assert!(
        matches!(err, MigrationError::LedgerNameMismatch { version: 2, .. }),
        "{err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains("something_else") && text.contains("add_label"),
        "names both: {text}"
    );
    let rows = ledger(&pool).await;
    assert_eq!(
        rows[1].2, None,
        "nothing was backfilled for the refused row"
    );
}
