//! The half of `yadgar-store` that talks to an engine.
//!
//! Same rule as `probe.rs`: no engine, no run — these panic rather than skip,
//! because the logic around a gap passing while the gap itself is untested is
//! the exact state this crate was in before (D69, D55).

use yadgar_store::credentials::Secret;
use yadgar_store::migrate::{Migration, MigrationSet};
use yadgar_store::pool::PoolConfig;
use yadgar_store::{backup, migrate};

fn dsn() -> String {
    std::env::var("YADGAR_TEST_DSN").unwrap_or_else(|_| {
        panic!(
            "YADGAR_TEST_DSN is unset. These tests assert what a real MariaDB \
             does; running them without one reports success while proving \
             nothing. See tests/probe.rs for the podman one-liner."
        )
    })
}

/// Parse the test DSN into a config plus its secret, so the pool constructor is
/// exercised through the same path a service uses.
fn config_and_secret(db: &str) -> (PoolConfig, Secret) {
    let url = dsn();
    let rest = url.trim_start_matches("mysql://");
    let (creds, hostpart) = rest.split_once('@').expect("dsn needs user:pass@host");
    let (user, pass) = creds.split_once(':').expect("dsn needs a password");
    let hostport = hostpart.split('/').next().unwrap();
    let (host, port) = hostport.split_once(':').expect("dsn needs a port");

    (
        PoolConfig {
            host: host.to_string(),
            port: port.parse().expect("port"),
            database: db.to_string(),
            username: user.to_string(),
            max_connections: 4,
            replicas: 2,
            engine_max_connections: 151,
            // The CI service container speaks plaintext on loopback; D58's TLS
            // requirement is asserted by pool.rs's own unit tests, which check
            // the DSN says so. Turning it on here would test the container's
            // certificate setup, not this crate.
            require_tls: false,
        },
        Secret::new(pass.to_string()),
    )
}

async fn scratch(name: &str) -> PoolConfig {
    use sqlx::Connection;
    let mut root = sqlx::MySqlConnection::connect(&dsn())
        .await
        .expect("connect");
    for stmt in [
        format!("DROP DATABASE IF EXISTS {name}"),
        format!("CREATE DATABASE {name}"),
    ] {
        // AUDIT: `name` is a literal in this file, not input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut root)
            .await
            .expect("ddl");
    }
    config_and_secret(name).0
}

fn migrations() -> MigrationSet {
    MigrationSet::new(vec![
        Migration {
            version: 1,
            name: "create_thing".into(),
            sql: "CREATE TABLE thing (id INT PRIMARY KEY)".into(),
        },
        Migration {
            version: 2,
            name: "add_label".into(),
            sql: "ALTER TABLE thing ADD COLUMN label TEXT".into(),
        },
    ])
    .expect("valid set")
}

#[tokio::test]
async fn the_pool_connects_with_a_resolved_credential() {
    let cfg = scratch("ys_pool").await;
    let (_, secret) = config_and_secret("ys_pool");
    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool should connect");
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

#[tokio::test]
async fn migrations_apply_in_order_and_exactly_once() {
    let cfg = scratch("ys_migrate").await;
    let (_, secret) = config_and_secret("ys_migrate");
    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool");

    let applied = migrate::apply(&pool, &migrations()).await.expect("apply");
    assert_eq!(applied, 2, "both migrations should apply");

    // Column from migration 2 exists, so ordering held.
    sqlx::query("SELECT id, label FROM thing")
        .fetch_optional(&pool)
        .await
        .expect("migration 2 must have run after migration 1");

    let again = migrate::apply(&pool, &migrations())
        .await
        .expect("re-apply");
    assert_eq!(again, 2, "a second run applies nothing new");
}

/// The rollback case: the database is ahead of this binary. Silently treating
/// that as "nothing pending" runs old code on a newer schema.
#[tokio::test]
async fn a_database_ahead_of_the_binary_refuses_to_boot() {
    let cfg = scratch("ys_ahead").await;
    let (_, secret) = config_and_secret("ys_ahead");
    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool");

    migrate::apply(&pool, &migrations()).await.expect("apply");

    let older = MigrationSet::new(vec![Migration {
        version: 1,
        name: "create_thing".into(),
        sql: "CREATE TABLE thing (id INT PRIMARY KEY)".into(),
    }])
    .expect("valid");

    let err = migrate::apply(&pool, &older)
        .await
        .expect_err("an older binary must refuse a newer schema");
    assert!(
        err.to_string().contains("newer version"),
        "the error must say what is wrong: {err}"
    );
}

/// D6: a backup nobody has restored is a hypothesis. The counting half is what
/// turns `RestoreReport` from a struct into a measurement.
#[tokio::test]
async fn row_counts_come_from_the_engine_and_verify() {
    let cfg = scratch("ys_backup").await;
    let (_, secret) = config_and_secret("ys_backup");
    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool");
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
    let cfg = scratch("ys_lost").await;
    let (_, secret) = config_and_secret("ys_lost");
    let pool = yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool");
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
