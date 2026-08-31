//! The backup census against a real engine (D6).
//!
//! `RestoreReport` is arithmetic over numbers; this is where the numbers come
//! from. A report built from anything else is the 2026-06-16 failure waiting to
//! happen — a check that passes because it was handed the counts it wanted.
//!
//! No engine, no run. See `tests/common/mod.rs`.

mod common;

use common::{migrations, root, scratch_pool};
use yadgar_store::{backup, migrate};

/// D6: a backup nobody has restored is a hypothesis. The counting half is what
/// turns `RestoreReport` from a struct into a measurement.
#[tokio::test]
async fn row_counts_come_from_the_engine_and_verify() {
    let pool = scratch_pool("ys_backup").await;
    migrate::apply(&pool, &migrations()).await.expect("apply");

    sqlx::raw_sql("INSERT INTO thing (id) VALUES (1), (2), (3)")
        .execute(&pool)
        .await
        .expect("seed");

    let census = backup::census(&pool, "ys_backup").await.expect("census");
    // 3 seeded rows + 2 rows in the migration ledger. The ledger IS counted,
    // deliberately: it is part of the database, and a restore that dropped it
    // would leave the schema unversioned while looking healthy. Excluding
    // "our own" tables from a verification is how a verification stops
    // verifying.
    assert_eq!(
        census.rows, 5,
        "three seeded rows plus the migration ledger"
    );
    assert_eq!(census.tables, 2, "thing and the migration ledger");

    let report = backup::RestoreReport {
        rows_backed_up: census.rows,
        rows_restored: census.rows,
        tables: census.tables,
    };
    assert!(
        matches!(report.verify(), backup::VerifyOutcome::Verified),
        "equal counts over real tables must verify"
    );
}

/// The 2026-06-16 shape: the check passed and the rows were gone. Counts taken
/// from a real engine must catch it.
#[tokio::test]
async fn a_restore_that_lost_rows_fails_verification() {
    let pool = scratch_pool("ys_lost").await;
    migrate::apply(&pool, &migrations()).await.expect("apply");
    sqlx::raw_sql("INSERT INTO thing (id) VALUES (1), (2), (3)")
        .execute(&pool)
        .await
        .expect("seed");

    let before = backup::census(&pool, "ys_lost").await.expect("census");
    sqlx::raw_sql("DELETE FROM thing WHERE id > 1")
        .execute(&pool)
        .await
        .expect("simulate a lossy restore");
    let after = backup::census(&pool, "ys_lost").await.expect("census");

    let report = backup::RestoreReport {
        rows_backed_up: before.rows,
        rows_restored: after.rows,
        tables: after.tables,
    };
    assert!(
        matches!(report.verify(), backup::VerifyOutcome::Failed(_)),
        "3 backed up, 1 restored: this is the incident, and it must fail"
    );
}

/// CENSUS MUST COUNT THE SCHEMA IT WAS ASKED ABOUT, NOT THE POOL'S OWN.
///
/// The actual use case is restore-into-staging-then-compare: restore the backup
/// into a second schema on the same engine and census both. Every other test
/// here censuses the pool's default database, so dropping the `` `{schema}`. ``
/// qualifier from the `COUNT(*)` would be invisible — the unqualified name would
/// resolve to the same table and the numbers would agree by accident.
///
/// The two schemas here hold a table of the SAME NAME with DIFFERENT counts, on
/// purpose. A table present in one and not the other would make an unqualified
/// query error out rather than miscount, and the test would then pass for the
/// wrong reason.
#[tokio::test]
async fn census_counts_a_different_schema_than_the_pool_is_connected_to() {
    let pool = scratch_pool("ys_census_here").await;
    migrate::apply(&pool, &migrations()).await.expect("apply");
    sqlx::raw_sql("INSERT INTO thing (id) VALUES (1), (2), (3)")
        .execute(&pool)
        .await
        .expect("seed the pool's own schema");

    // The staging schema: same table name, seven rows instead of three, and no
    // migration ledger.
    let mut other = root().await;
    for stmt in [
        "DROP DATABASE IF EXISTS ys_census_there",
        "CREATE DATABASE ys_census_there",
        "CREATE TABLE ys_census_there.thing (id INT PRIMARY KEY)",
        "INSERT INTO ys_census_there.thing (id) VALUES (1),(2),(3),(4),(5),(6),(7)",
    ] {
        sqlx::raw_sql(stmt)
            .execute(&mut other)
            .await
            .expect("staging fixture");
    }

    let there = backup::census(&pool, "ys_census_there")
        .await
        .expect("census of the staging schema");

    assert_eq!(
        there.tables, 1,
        "the staging schema holds one table; the pool's own holds two"
    );
    assert_eq!(
        there.rows, 7,
        "seven rows in ys_census_there. Counting the pool's own `thing` instead \
         gives 3, which is what an unqualified COUNT(*) would return — and a \
         restore verification comparing the wrong schema is the 2026-06-16 \
         failure with extra steps"
    );

    // And the pool's own schema is unchanged by having been asked about another.
    let here = backup::census(&pool, "ys_census_here")
        .await
        .expect("census");
    assert_eq!(here.rows, 5, "three seeded rows plus the migration ledger");
    assert_eq!(here.tables, 2);
}

/// CENSUS MUST NOT REGRESS TO `information_schema.TABLE_ROWS`.
///
/// One query instead of N would make verification cheap, and wrong: `TABLE_ROWS`
/// is an InnoDB estimate from sampled index statistics. Both other backup tests
/// would still pass, because at 3 rows the estimate is exact — the table fits in
/// so few pages that sampling reads all of them.
///
/// So the fixture is shaped to make the estimate WRONG, and the test asserts
/// both halves: that the estimate diverges (or the test proves nothing) and that
/// `census` matches an independent `COUNT(*)`.
///
/// MEASURED on MariaDB 11.8.8, `STATS_AUTO_RECALC=0` so the estimate cannot
/// silently recompute mid-test. A ladder, because the smallest diverging shape
/// was worth knowing: at 2,000/2,500/3,000/3,500/4,000 rows the estimate is
/// EXACT and this test would prove nothing — the table fits in few enough pages
/// that sampling reads all of them. Divergence starts at 4,500 (4,030 against a
/// real 4,050).
///
/// The fixture nonetheless uses the audit's own shape, 50,000 rows with 2%
/// deleted, because the whole thing builds in ~113ms and there is no CI budget
/// to save. Sitting one step above the cliff would make the divergence depend on
/// rows-per-page and `innodb_stats_persistent_sample_pages`, neither of which is
/// fixed across builds; ten times above it does not.
#[tokio::test]
async fn census_counts_rows_rather_than_trusting_the_engines_estimate() {
    const SCHEMA: &str = "ys_census_estimate";
    const INSERTED: i64 = 50_000;
    const DELETED: i64 = 1_000;

    let pool = scratch_pool(SCHEMA).await;

    let mut fixture = root().await;
    for stmt in [
        // The recursive CTE below needs more than the default 1,000 iterations.
        "SET SESSION max_recursive_iterations = 1000000".to_string(),
        format!("USE {SCHEMA}"),
        // STATS_PERSISTENT with auto-recalc OFF: the estimate is taken once, by
        // the ANALYZE below, and cannot drift while the test runs. Without that
        // InnoDB may recompute on its own and the divergence becomes a race.
        "CREATE TABLE big (id INT PRIMARY KEY, pad VARCHAR(64)) ENGINE=InnoDB \
         STATS_PERSISTENT=1, STATS_AUTO_RECALC=0"
            .to_string(),
        format!(
            "INSERT INTO big (id, pad) WITH RECURSIVE seq AS \
             (SELECT 1 AS n UNION ALL SELECT n + 1 FROM seq WHERE n < {INSERTED}) \
             SELECT n, REPEAT('x', 40) FROM seq"
        ),
        // Fix the estimate at the full table...
        "ANALYZE TABLE big".to_string(),
        // ...then delete under it, which is what a partial restore looks like.
        format!("DELETE FROM big WHERE id <= {DELETED}"),
    ] {
        // AUDIT: every statement is a literal or a const of this file.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut fixture)
            .await
            .expect("fixture");
    }

    let real: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM big")
        .fetch_one(&mut fixture)
        .await
        .expect("independent count");
    assert_eq!(real, INSERTED - DELETED);

    let estimate: Option<u64> = sqlx::query_scalar(
        "SELECT TABLE_ROWS FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'big'",
    )
    .bind(SCHEMA)
    .fetch_one(&mut fixture)
    .await
    .expect("the estimate");

    // Fixture sanity FIRST. If the estimate happened to be right, an
    // implementation reading TABLE_ROWS would pass the assertion below and this
    // test would be the thing it exists to prevent.
    assert_ne!(
        estimate,
        Some(real as u64),
        "the fixture must make the estimate wrong, or this test proves nothing"
    );

    let census = backup::census(&pool, SCHEMA).await.expect("census");
    assert_eq!(
        census.rows, real as u64,
        "census must count rows. The estimate here is {estimate:?} against a \
         real {real}, and a restore verified against an estimate is not verified"
    );
    assert_eq!(census.tables, 1);
}
