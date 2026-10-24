//! The pool, against a real engine.
//!
//! Same rule as `probe.rs`: no engine, no run — these panic rather than skip,
//! because the logic around a gap passing while the gap itself is untested is
//! the exact state this crate was in before (D69, D55). Migrations and the
//! backup census have their own files; the shared setup is in
//! `tests/common/mod.rs`.

mod common;

use common::{config_and_secret, scratch, scratch_pool};
use yadgar_store::credentials::Secret;

#[tokio::test]
async fn the_pool_connects_with_a_resolved_credential() {
    let pool = scratch_pool("ys_pool").await;
    let one: i64 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("query");
    assert_eq!(one, 1);
}

/// **`connect` BUILDS ITS POOL FROM `pool_options`, not from a second, drifting
/// copy of it.** `tests/pool.rs` asserts what `pool_options` returns; this
/// asserts that the pool `connect` hands back carries the same values, read
/// from the live pool. None of the three is sqlx's own default (30s, 600s,
/// 1800s), so a `connect` that bypassed `pool_options` fails here.
#[tokio::test]
async fn connect_builds_the_pool_from_the_configured_options() {
    let mut cfg = scratch("ys_pool_options").await;
    let (_, secret) = config_and_secret("ys_pool_options");
    cfg.acquire_timeout = std::time::Duration::from_secs(11);
    cfg.idle_timeout = std::time::Duration::from_secs(123);
    cfg.max_lifetime = std::time::Duration::from_secs(456);

    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool");
    let options = pool.options();

    assert_eq!(
        options.get_acquire_timeout(),
        std::time::Duration::from_secs(11)
    );
    assert_eq!(
        options.get_idle_timeout(),
        Some(std::time::Duration::from_secs(123))
    );
    assert_eq!(
        options.get_max_lifetime(),
        Some(std::time::Duration::from_secs(456))
    );
}

/// The headroom check is a boot refusal, so it must run inside `connect` rather
/// than being something a caller is trusted to remember (D4).
#[tokio::test]
async fn connect_refuses_a_config_that_would_exhaust_the_engine() {
    let mut cfg = scratch("ys_headroom").await;
    let (_, secret) = config_and_secret("ys_headroom");
    cfg.max_connections = 100;
    cfg.replicas = 10;
    yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect_err("1000 connections against 151 must be refused before connecting");
}

/// THE 30-SECOND BOOT FAILURE, refused up front.
///
/// `migrate::apply` holds the migration lock on one connection while the
/// migrations run on a second, so a pool of one waits for a connection it is
/// itself holding. Before the floor in `check_engine_headroom`, only 0 was
/// rejected: `max_connections = 1` connected happily, then boot hung for 30.0s
/// and failed with "pool timed out while waiting for an open connection", which
/// names the pool and not the cause.
///
/// The timing assertion is the point. Refusing eventually is what it already
/// did; refusing IMMEDIATELY, with the reason, is the fix.
#[tokio::test]
async fn a_single_connection_pool_is_refused_at_once_not_thirty_seconds_later() {
    let mut cfg = scratch("ys_one_conn").await;
    let (_, secret) = config_and_secret("ys_one_conn");
    cfg.max_connections = 1;

    let started = std::time::Instant::now();
    let err = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect_err("one connection cannot migrate: the lock would hold the pool");
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the refusal must be immediate; took {elapsed:?}, which is the pool \
         acquire timeout rather than a check"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("migration lock"),
        "the boot error must name the cause: {msg}"
    );
}

/// THE ASSERTION THAT CAN ACTUALLY FAIL.
///
/// `tests/pool.rs` used to search the DSN for the literal word "password" —
/// while `PoolConfig` has no password field, so no value could ever have
/// appeared and no change to `dsn()` could ever have failed it. A test that
/// cannot fail is worse than none: it reads as coverage.
///
/// The seam that CAN leak is the connect path, the only place the secret and
/// the DSN are both in scope. So: a real engine, a deliberately wrong password,
/// and a search of the error for the sentinel VALUE — Display and Debug both,
/// since a `#[source]` chain reaches logs through either. The same shape as the
/// credentials suite, which searches for "hunter2" rather than for the word
/// "secret".
#[tokio::test]
async fn a_failed_connection_never_carries_the_credential_into_its_error() {
    const SENTINEL: &str = "hunter2-do-not-leak";

    let cfg = scratch("ys_leak").await;
    let err = yadgar_store::pool::connect(&cfg, &Secret::new(SENTINEL.into()))
        .await
        .expect_err("a wrong password must be refused by the engine");

    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        !display.contains(SENTINEL),
        "credential leaked into the error message: {display}"
    );
    assert!(
        !debug.contains(SENTINEL),
        "credential leaked into Debug: {debug}"
    );
}

/// A throwaway account capped at `cap`, granted on `db`, and a config that
/// connects as it. Accounts are server-wide, so each test names its own.
async fn capped_user(db: &str, user: &str, cap: u32) -> (yadgar_store::pool::PoolConfig, Secret) {
    let mut cfg = scratch(db).await;
    let mut root = common::root().await;
    for stmt in [
        format!("DROP USER IF EXISTS '{user}'@'%'"),
        format!("CREATE USER '{user}'@'%' IDENTIFIED BY 'capped' WITH MAX_USER_CONNECTIONS {cap}"),
        format!("GRANT ALL ON {db}.* TO '{user}'@'%'"),
    ] {
        // AUDIT: `db`, `user` and `cap` are literals in the calling test.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut root)
            .await
            .expect("account ddl");
    }
    cfg.username = user.to_string();
    (cfg, Secret::new("capped".into()))
}

/// THE LIVE DEFECT, against a real engine (yaadgaar #200): the operator writes
/// `MAX_USER_CONNECTIONS 20` and the chart shipped 8 per replica at a KEDA
/// ceiling of 6. The engine check passes (48 < 151 - 5); the account check
/// must refuse inside `connect`, reading the cap from the engine itself.
#[tokio::test]
async fn connect_refuses_a_pool_the_users_connection_cap_cannot_hold() {
    let (mut cfg, secret) = capped_user("ys_user_cap", "ys_cap_refused", 20).await;
    cfg.max_connections = 8;
    cfg.replicas = 6;

    let err = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect_err("48 connections cannot fit an account capped at 20");
    assert!(
        matches!(
            err,
            yadgar_store::pool::PoolError::WouldExceedUserCap {
                requested: 48,
                cap: 20,
                ..
            }
        ),
        "the refusal must carry the cap read from the engine: {err:?}"
    );

    // AND THE REFUSED POOL HOLDS NOTHING OPEN against that same cap: `connect`
    // closes it, awaiting every connection, before returning the refusal. A
    // pool merely dropped closes its connections later, in the background.
    assert_eq!(
        sessions_of("ys_cap_refused").await,
        0,
        "a refused boot left sessions open against the account's cap"
    );
}

/// Sessions the account holds right now, asked as root.
async fn sessions_of(user: &str) -> i64 {
    let mut root = common::root().await;
    sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER = ?")
        .bind(user)
        .fetch_one(&mut root)
        .await
        .expect("processlist")
}

/// And the shape ADR-1006 ships, 3 x 6 = 18, connects under the same cap.
#[tokio::test]
async fn connect_accepts_a_pool_within_the_users_connection_cap() {
    let (mut cfg, secret) = capped_user("ys_user_cap_ok", "ys_cap_ok", 20).await;
    cfg.max_connections = 3;
    cfg.replicas = 6;

    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("18 connections fit an account capped at 20");
    let one: i64 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .expect("query");
    assert_eq!(one, 1);
}
