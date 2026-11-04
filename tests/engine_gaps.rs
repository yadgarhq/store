//! Gaps below the ledger's newest row, against a real engine (yaadgaar #487).
//!
//! `apply` read only the ledger's MAXIMUM. A migration numbered below it with no
//! row was never applied, and a row below it that the binary does not carry was
//! never checked. Both now refuse the boot before any SQL runs or any row is
//! written.
//!
//! No engine, no run. See `tests/common/mod.rs`.

mod common;

use common::{lock, migration, scratch_pool};
use yadgar_store::migrate::{self, MigrationError, MigrationSet};

fn set(versions: &[u64]) -> MigrationSet {
    MigrationSet::new(
        versions
            .iter()
            .map(|&v| {
                migration(
                    v,
                    &format!("create_t{v}"),
                    &format!("CREATE TABLE t{v} (id INT)"),
                )
            })
            .collect(),
    )
    .expect("valid set")
}

async fn ledger(pool: &sqlx::MySqlPool) -> Vec<u64> {
    sqlx::query_scalar("SELECT version FROM yadgar_schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("ledger")
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

/// Direction (a): migration 2 was added after migration 3 shipped. Before the
/// fix `apply` returned 3 and migration 2 never ran, on this boot or any other.
#[tokio::test]
async fn a_migration_added_below_the_applied_maximum_refuses_the_boot() {
    let pool = scratch_pool("ys_gap_below").await;
    migrate::apply(&pool, &set(&[1, 3]), &lock())
        .await
        .expect("history");

    let err = migrate::apply(&pool, &set(&[1, 2, 3, 4]), &lock())
        .await
        .expect_err("a hole below the maximum must refuse the boot");
    assert!(
        matches!(
            err,
            MigrationError::NotApplied {
                version: 2,
                applied: 3,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(ledger(&pool).await, vec![1, 3], "nothing recorded");
    assert!(!table_exists(&pool, "t2").await, "the hole did not run");
    assert!(!table_exists(&pool, "t4").await, "pending work did not run");
}

/// Direction (b): the ledger records migration 2 and this binary does not carry
/// it. Before the fix the row was skipped and migration 4 ran on top of a schema
/// this binary knows nothing about.
#[tokio::test]
async fn a_ledger_row_the_binary_does_not_carry_refuses_the_boot() {
    let pool = scratch_pool("ys_gap_unknown").await;
    migrate::apply(&pool, &set(&[1, 2, 3]), &lock())
        .await
        .expect("history");

    let err = migrate::apply(&pool, &set(&[1, 3, 4]), &lock())
        .await
        .expect_err("an unknown ledger row must refuse the boot");
    assert!(
        matches!(err, MigrationError::LedgerUnknown { version: 2 }),
        "{err:?}"
    );
    assert_eq!(ledger(&pool).await, vec![1, 2, 3], "nothing recorded");
    assert!(!table_exists(&pool, "t4").await, "pending work did not run");
}

/// A pre-checksum row in a refused ledger keeps its NULL: the refusal comes
/// before the trust-on-first-use backfill, so a refused boot writes nothing.
#[tokio::test]
async fn a_refused_gap_writes_no_checksum_backfill() {
    let pool = scratch_pool("ys_gap_no_backfill").await;
    migrate::apply(&pool, &set(&[1, 3]), &lock())
        .await
        .expect("history");
    sqlx::query("UPDATE yadgar_schema_migrations SET checksum = NULL")
        .execute(&pool)
        .await
        .expect("model a pre-checksum ledger");

    migrate::apply(&pool, &set(&[1, 2, 3]), &lock())
        .await
        .expect_err("the hole refuses");
    let nulls: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM yadgar_schema_migrations WHERE checksum IS NULL")
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(nulls, 2, "no row was backfilled");
}
