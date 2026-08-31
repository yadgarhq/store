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
