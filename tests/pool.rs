//! The pool, and D4's actual reason for existing.
//!
//! The `-db` twin is not only a boundary — it is the CONNECTION CONCENTRATOR.
//! N replicas of a logic service with embedded pools multiply connections
//! against an engine with hard limits; one `-db` in front of the engine bounds
//! them. So the pool's ceiling is a correctness property of the topology, not a
//! tuning knob, and these tests are about the arithmetic nobody does until an
//! engine starts refusing connections.

use yadgar_store::pool::{PoolConfig, PoolError};

fn cfg() -> PoolConfig {
    PoolConfig {
        host: "mariadb".into(),
        port: 3306,
        database: "task".into(),
        username: "task".into(),
        max_connections: 10,
        replicas: 2,
        engine_max_connections: 151,
        require_tls: true,
    }
}

#[test]
fn a_dsn_never_contains_the_password() {
    // The DSN reaches logs, tracing spans and error messages. The credential is
    // applied separately, at connect time.
    let dsn = cfg().dsn();
    assert!(dsn.starts_with("mysql://"));
    assert!(dsn.contains("mariadb:3306"), "got {dsn}");
    assert!(
        !dsn.contains("password"),
        "credential leaked into the DSN: {dsn}"
    );
}

#[test]
fn total_connections_across_replicas_must_fit_the_engine() {
    // 10 per pool x 2 replicas = 20, comfortably under 151.
    assert!(cfg().check_engine_headroom().is_ok());
}

#[test]
fn a_replica_count_that_would_exhaust_the_engine_is_rejected_at_boot() {
    // The failure this prevents does not look like a configuration error. It
    // looks like intermittent "too many connections" under load, on whichever
    // service happens to connect last — and scaling up makes it worse.
    let mut c = cfg();
    c.max_connections = 50;
    c.replicas = 4; // 200 > 151

    let err = c.check_engine_headroom().unwrap_err();
    assert!(matches!(
        err,
        PoolError::WouldExhaustEngine {
            requested: 200,
            available: 151,
            ..
        }
    ));
    let msg = err.to_string();
    assert!(msg.contains("200") && msg.contains("151"), "got: {msg}");
}

#[test]
fn the_engines_own_reserved_connections_are_accounted_for() {
    // MariaDB reserves connections for SUPER so an operator can still get in
    // when the pool has taken everything. A check that ignores that passes
    // right up to the moment nobody can log in to diagnose it.
    let mut c = cfg();
    c.max_connections = 151;
    c.replicas = 1;
    assert!(
        c.check_engine_headroom().is_err(),
        "using every connection must fail: it leaves nothing for an operator"
    );
}

#[test]
fn zero_connections_is_rejected() {
    let mut c = cfg();
    c.max_connections = 0;
    assert!(matches!(
        c.check_engine_headroom(),
        Err(PoolError::InvalidSize { .. })
    ));
}

#[test]
fn tls_is_required_by_default_and_the_dsn_says_so() {
    // D58 puts every -db on TLS to its engine, and the RUSTSEC-2023-0071
    // exception recorded in deny.toml depends on that being true.
    assert!(
        cfg().dsn().contains("ssl-mode=REQUIRED"),
        "TLS must be explicit in the DSN"
    );
}
