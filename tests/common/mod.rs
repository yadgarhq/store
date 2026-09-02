//! Shared setup for the engine-backed suites.
//!
//! Same rule everywhere below: **no engine, no run**. These panic rather than
//! skip, because a suite that quietly passes with nothing to talk to is the
//! failure D69 exists to stop one level up.
//!
//! This lives in `tests/common/` rather than in one big `engine.rs` because the
//! engine-backed tests exceed a single file's complexity ceiling once the lock,
//! partial-failure and cross-schema cases are covered. Each `engine_*.rs`
//! includes this module; `#![allow(dead_code)]` because no single suite uses all
//! of it and an unused helper is not a defect.

#![allow(dead_code)]

use sqlx::{Connection, MySqlConnection, MySqlPool};
use yadgar_store::credentials::Secret;
use yadgar_store::migrate::{Migration, MigrationSet};
use yadgar_store::pool::{MySqlSslMode, PoolConfig};

pub fn dsn() -> String {
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
pub fn config_and_secret(db: &str) -> (PoolConfig, Secret) {
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
            // requirement is asserted by tests/pool.rs, which checks the default
            // mode and the options the connection is actually built with.
            // Turning it on here would test the container's certificate setup,
            // not this crate.
            ssl_mode: MySqlSslMode::Disabled,
        },
        Secret::new(pass.to_string()),
    )
}

pub async fn root() -> MySqlConnection {
    MySqlConnection::connect(&dsn()).await.expect("connect")
}

/// An empty database named `name`, dropped first so a rerun starts clean.
pub async fn scratch(name: &str) -> PoolConfig {
    let mut root = root().await;
    for stmt in [
        format!("DROP DATABASE IF EXISTS {name}"),
        format!("CREATE DATABASE {name}"),
    ] {
        // AUDIT: `name` is a literal in the calling test, not input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
            .execute(&mut root)
            .await
            .expect("ddl");
    }
    config_and_secret(name).0
}

/// [`scratch`] plus a pool onto it, which is how every engine test starts.
pub async fn scratch_pool(name: &str) -> MySqlPool {
    let cfg = scratch(name).await;
    let (_, secret) = config_and_secret(name);
    yadgar_store::pool::connect(&cfg, &secret)
        .await
        .expect("pool")
}

pub fn migration(version: u64, name: &str, sql: &str) -> Migration {
    Migration {
        version,
        name: name.into(),
        sql: sql.into(),
    }
}

pub fn migrations() -> MigrationSet {
    MigrationSet::new(vec![
        migration(1, "create_thing", "CREATE TABLE thing (id INT PRIMARY KEY)"),
        migration(2, "add_label", "ALTER TABLE thing ADD COLUMN label TEXT"),
    ])
    .expect("valid set")
}
