//! Migrations against a real engine: ordering, the replica race, and the two
//! things that go wrong once more than one replica exists — the lock, and a set
//! that fails halfway.
//!
//! No engine, no run. See `tests/common/mod.rs`.

mod common;

use common::{lock, migration, migrations, root, scratch_pool};
use yadgar_store::migrate::{self, LockOptions, MigrationError, MigrationSet};

#[tokio::test]
async fn migrations_apply_in_order_and_exactly_once() {
    let pool = scratch_pool("ys_migrate").await;

    let applied = migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");
    assert_eq!(applied, 2, "both migrations should apply");

    // Column from migration 2 exists, so ordering held.
    sqlx::query("SELECT id, label FROM thing")
        .fetch_optional(&pool)
        .await
        .expect("migration 2 must have run after migration 1");

    let again = migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("re-apply");
    assert_eq!(again, 2, "a second run applies nothing new");
}

/// The rollback case: the database is ahead of this binary. Silently treating
/// that as "nothing pending" runs old code on a newer schema.
#[tokio::test]
async fn a_database_ahead_of_the_binary_refuses_to_boot() {
    let pool = scratch_pool("ys_ahead").await;
    migrate::apply(&pool, &migrations(), &lock())
        .await
        .expect("apply");

    let older = MigrationSet::new(vec![migration(
        1,
        "create_thing",
        "CREATE TABLE thing (id INT PRIMARY KEY)",
    )])
    .expect("valid");

    let err = migrate::apply(&pool, &older, &lock())
        .await
        .expect_err("an older binary must refuse a newer schema");
    assert!(
        err.to_string().contains("newer version"),
        "the error must say what is wrong: {err}"
    );
}

/// THE REPLICA RACE, reproduced.
///
/// Two replicas boot at once against one database, both read `applied = 0`, and
/// both try migration 1. Before the migration lock, one won and the other died
/// on "Table 'task' already exists" — then crash-looped, because a failed
/// migration is a failed boot. Observed on the first real two-replica deploy.
///
/// A single process cannot exhibit this, which is the whole argument for D55.
#[tokio::test]
async fn concurrent_replicas_do_not_race_on_migrations() {
    let cfg = common::scratch("ys_race").await;
    let (_, secret) = common::config_and_secret("ys_race");

    // Two pools, as two replicas would have.
    let a = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool a");
    let b = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool b");

    let (ma, mb) = (migrations(), migrations());
    let (la, lb) = (lock(), lock());
    let (ra, rb) = tokio::join!(migrate::apply(&a, &ma, &la), migrate::apply(&b, &mb, &lb));

    // BOTH must succeed. One migrates, the other waits and finds the ledger
    // already current — neither may fail, because a failing replica crash-loops.
    let va = ra.expect("replica a must not fail");
    let vb = rb.expect("replica b must not fail");
    assert_eq!(va, 2);
    assert_eq!(vb, 2);

    // And the work happened exactly once: two rows, not four.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM yadgar_schema_migrations")
        .fetch_one(&a)
        .await
        .expect("count");
    assert_eq!(rows, 2, "each migration must be recorded exactly once");
}

/// A set that fails in the middle, so migration 1 is applied and 2 is not.
fn broken_set() -> MigrationSet {
    MigrationSet::new(vec![
        migration(1, "create_thing", "CREATE TABLE thing (id INT PRIMARY KEY)"),
        // Rejected by the parser, so it fails without leaving a half-table.
        migration(
            2,
            "add_label_broken",
            "ALTER TABLE thing ADD COLUMN label NOSUCHTYPE",
        ),
        migration(3, "create_other", "CREATE TABLE other (id INT PRIMARY KEY)"),
    ])
    .expect("valid set")
}

fn fixed_set() -> MigrationSet {
    MigrationSet::new(vec![
        migration(1, "create_thing", "CREATE TABLE thing (id INT PRIMARY KEY)"),
        migration(2, "add_label", "ALTER TABLE thing ADD COLUMN label TEXT"),
        migration(3, "create_other", "CREATE TABLE other (id INT PRIMARY KEY)"),
    ])
    .expect("valid set")
}

async fn ledger_high_water(pool: &sqlx::MySqlPool) -> u64 {
    sqlx::query_scalar(
        "SELECT CAST(COALESCE(MAX(version), 0) AS UNSIGNED) FROM yadgar_schema_migrations",
    )
    .fetch_one(pool)
    .await
    .expect("ledger")
}

/// THE CLAIM THIS PINS: "a failure leaves earlier migrations applied and
/// recorded, which is recoverable because the ledger says exactly where it
/// stopped."
///
/// That is the argument for one-transaction-per-migration rather than one for
/// the set — MariaDB commits implicitly on DDL, so the set-wide transaction is a
/// transaction in name only. The claim was untested, which means the recovery
/// story was untested: nothing established that the ledger stops at 1 rather
/// than at 0 or 2, and both alternatives break the operator's next step.
#[tokio::test]
async fn a_failed_migration_leaves_the_ledger_exactly_where_it_stopped() {
    let pool = scratch_pool("ys_partial").await;

    let err = migrate::apply(&pool, &broken_set(), &lock())
        .await
        .expect_err("migration 2 is not valid SQL");
    assert!(
        matches!(err, MigrationError::Failed { version: 2, .. }),
        "the error must name the migration that failed: {err:?}"
    );

    assert_eq!(
        ledger_high_water(&pool).await,
        1,
        "migration 1 succeeded, so the ledger says 1 — not 0, which would rerun \
         it, and not 2, which would skip a migration that never ran"
    );
    sqlx::query("SELECT id FROM other")
        .fetch_optional(&pool)
        .await
        .expect_err("migration 3 must not have run after 2 failed");

    // The recovery: fix migration 2 and boot again. 1 is not reapplied, 2 and 3
    // are, and the run reports 3.
    let applied = migrate::apply(&pool, &fixed_set(), &lock())
        .await
        .expect("the fixed set must apply from where the broken one stopped");
    assert_eq!(applied, 3);

    sqlx::query("SELECT id, label FROM thing")
        .fetch_optional(&pool)
        .await
        .expect("migration 2 ran on the retry");
    sqlx::query("SELECT id FROM other")
        .fetch_optional(&pool)
        .await
        .expect("migration 3 ran on the retry");

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM yadgar_schema_migrations")
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 3, "migration 1 must not be recorded twice");
}

/// `LockUnavailable` had zero callers in any test, which is how the branch
/// standing between two replicas and a corrupted schema went unexercised.
///
/// Unreachable by accident, too: it needs another connection to already hold the
/// lock, and the timeout was a private const of 60 seconds. Injecting both is
/// what makes it testable — a one-second wait, on a lock name no other test in
/// the suite touches, since `GET_LOCK` is server-wide rather than per-database.
#[tokio::test]
async fn a_lock_another_replica_holds_is_a_boot_failure_naming_the_wait() {
    let pool = scratch_pool("ys_lock_busy").await;
    let lock = LockOptions::new(1)
        .expect("one second")
        .with_name("yadgar_migrate_test_busy");

    // A stand-in for the replica that is already migrating.
    let mut holder = root().await;
    let held: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, ?)")
        .bind(lock.per_database_name("ys_lock_busy"))
        .bind(0)
        .fetch_one(&mut holder)
        .await
        .expect("take the lock");
    assert_eq!(held, Some(1), "the test must actually hold the lock");

    let err = migrate::apply(&pool, &migrations(), &lock)
        .await
        .expect_err("migrating while another replica holds the lock must fail");

    assert!(
        matches!(err, MigrationError::LockUnavailable { seconds: 1, .. }),
        "the wait it gave up after is part of the message: {err:?}"
    );
    assert!(
        err.to_string().contains("concurrently"),
        "the operator needs to be told this is a refusal, not a crash: {err}"
    );
    // AND THE WAIT MUST REACH THE MESSAGE, not only the variant. `seconds: 1`
    // above proves the value is plumbed from the caller's `LockOptions`; it says
    // nothing about the rendered text, so deleting `{seconds}s` from the
    // `#[error]` template leaves this test green and the operator reading a
    // refusal that does not say how long it waited.
    assert!(
        err.to_string().contains("1s"),
        "the message must name the wait it gave up after: {err}"
    );

    // Nothing was applied while the other replica held the lock.
    let ledger_exists: Option<String> = sqlx::query_scalar(
        "SELECT TABLE_NAME FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = 'ys_lock_busy' AND TABLE_NAME = 'thing'",
    )
    .fetch_optional(&pool)
    .await
    .expect("information_schema");
    assert!(
        ledger_exists.is_none(),
        "refusing the lock must refuse the migration too"
    );
}

/// THE LOCK MUST BE RELEASED ON THE FAILURE PATH, not only the happy one.
///
/// A failed migration is a failed boot, and the replica crash-loops. If the lock
/// leaked on that path the second replica would wait the full timeout and fail
/// too — one bad migration taking down every replica instead of one, with an
/// error naming the lock rather than the migration.
#[tokio::test]
async fn the_lock_is_released_after_a_migration_fails() {
    let pool = scratch_pool("ys_lock_release").await;
    let lock = LockOptions::new(1)
        .expect("one second")
        .with_name("yadgar_migrate_test_release");

    migrate::apply(&pool, &broken_set(), &lock)
        .await
        .expect_err("migration 2 is not valid SQL");

    // Asked from a DIFFERENT connection: IS_FREE_LOCK answers about the server,
    // and asking on the connection that held it would prove nothing.
    let mut observer = root().await;
    let free: Option<i64> = sqlx::query_scalar("SELECT IS_FREE_LOCK(?)")
        .bind(lock.per_database_name("ys_lock_release"))
        .fetch_one(&mut observer)
        .await
        .expect("is_free_lock");
    assert_eq!(
        free,
        Some(1),
        "the migration lock is still held after a failed migration; the next \
         replica would wait the whole timeout and blame the lock"
    );

    // And the proof that it is really free: another apply can take it.
    migrate::apply(&pool, &fixed_set(), &lock)
        .await
        .expect("a retry must be able to take the lock again");
}

/// Whether `name` is free, asked from a connection that never held it.
async fn assert_free(observer: &mut sqlx::MySqlConnection, name: &str) {
    let free: Option<i64> = sqlx::query_scalar("SELECT IS_FREE_LOCK(?)")
        .bind(name)
        .fetch_one(observer)
        .await
        .expect("is_free_lock");
    assert_eq!(free, Some(1), "lock {name} is still held");
}

/// Hold `name` on a fresh root connection, returned so the hold lasts.
async fn hold(name: &str) -> sqlx::MySqlConnection {
    let mut holder = root().await;
    let held: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 0)")
        .bind(name)
        .fetch_one(&mut holder)
        .await
        .expect("take the lock");
    assert_eq!(held, Some(1), "the test must actually hold {name}");
    holder
}

/// RELEASE B (yaadgaar #368): the legacy server-wide name is no longer
/// taken, so a holder of it no longer blocks this module's migration. This
/// is what lets modules sharing one server migrate at once. Safe only after
/// every pod runs release A: those pods hold the per-database name too.
#[tokio::test]
async fn a_holder_of_the_legacy_lock_no_longer_blocks_apply() {
    let pool = scratch_pool("ys_lock_legacy").await;
    let lock = LockOptions::new(1)
        .expect("one second")
        .with_name("yadgar_migrate_test_legacy");

    let _other_module = hold(lock.name()).await;

    let applied = migrate::apply(&pool, &migrations(), &lock)
        .await
        .expect("a holder of the legacy name must not block release B");
    assert_eq!(applied, 2);
}

/// The per-database name is what release A and release B pods share, so a
/// holder of it must block apply.
#[tokio::test]
async fn the_per_database_lock_blocks_apply() {
    let pool = scratch_pool("ys_lock_perdb").await;
    let lock = LockOptions::new(1)
        .expect("one second")
        .with_name("yadgar_migrate_test_perdb");
    let per_db = lock.per_database_name("ys_lock_perdb");

    let _new_pod = hold(&per_db).await;

    let err = migrate::apply(&pool, &migrations(), &lock)
        .await
        .expect_err("a holder of the per-database lock must block apply");
    assert!(
        matches!(&err, MigrationError::LockUnavailable { name, seconds: 1 } if *name == per_db),
        "the refusal must name the per-database lock: {err:?}"
    );
}

/// The happy path releases the lock, so the next replica takes them at
/// once instead of waiting on pool recycling.
#[tokio::test]
async fn a_successful_apply_frees_the_lock() {
    let pool = scratch_pool("ys_lock_both").await;
    let lock = LockOptions::new(5)
        .expect("five seconds")
        .with_name("yadgar_migrate_test_both");

    migrate::apply(&pool, &migrations(), &lock)
        .await
        .expect("apply");

    let mut observer = root().await;
    assert_free(&mut observer, &lock.per_database_name("ys_lock_both")).await;
}

/// A pool with no default database has nothing to name a per-database lock
/// after, and no migration could run on it either. Refused by name.
#[tokio::test]
async fn a_pool_without_a_database_is_refused_before_any_lock() {
    let url = common::dsn();
    let server = url
        .rsplit_once('/')
        .map(|(head, _)| head)
        .expect("dsn has a path");
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(2)
        .connect(server)
        .await
        .expect("pool without a database");
    let lock = LockOptions::new(1)
        .expect("one second")
        .with_name("yadgar_migrate_test_nodb");

    let err = migrate::apply(&pool, &migrations(), &lock)
        .await
        .expect_err("no database, no migration");
    assert!(
        matches!(err, MigrationError::NoDatabase),
        "the refusal must say there is no database: {err:?}"
    );
}

/// Whether `name` is free, polled for up to `within` from a fresh connection.
/// A closed session's locks are released by the server shortly after the
/// close, not at the instant the client drops it.
async fn freed_within(name: &str, within: std::time::Duration) -> bool {
    let mut observer = root().await;
    let deadline = std::time::Instant::now() + within;
    loop {
        let free: Option<i64> = sqlx::query_scalar("SELECT IS_FREE_LOCK(?)")
            .bind(name)
            .fetch_one(&mut observer)
            .await
            .expect("is_free_lock");
        if free == Some(1) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// A CANCELLED apply must not hand its lock connection back to the pool
/// holding a migration lock (review S1/S3 on store#37).
///
/// `GET_LOCK` is held by a SESSION. Dropping the `apply` future (a caller's
/// `timeout`, a shutdown `select!`) used to return that session to the pool
/// still holding the legacy name, and still waiting server-side on the
/// per-database one: measured on MariaDB 11.8.9, both were held 7 s later.
/// The lock connection is now closed on drop, so the server ends the session
/// and releases both names.
#[tokio::test]
async fn a_cancelled_apply_leaves_no_session_holding_the_lock() {
    let pool = scratch_pool("ys_lock_cancel").await;
    let lock = LockOptions::new(2)
        .expect("two seconds")
        .with_name("yadgar_migrate_test_cancel");
    let per_db = lock.per_database_name("ys_lock_cancel");

    // apply waits on the per-database name.
    let holder = hold(&per_db).await;

    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        migrate::apply(&pool, &migrations(), &lock),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "apply must still be waiting when cancelled"
    );

    // Released at once: a session left in the pool would still be waiting
    // server-side, take the name now, and keep it.
    drop(holder);
    assert!(
        freed_within(&per_db, std::time::Duration::from_secs(5)).await,
        "the per-database name is still held after cancellation"
    );
    // And the pool kept serving.
    drop(pool);
}
