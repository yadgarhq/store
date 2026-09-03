//! The pool, and D4's actual reason for existing.
//!
//! The `-db` twin is not only a boundary — it is the CONNECTION CONCENTRATOR.
//! N replicas of a logic service with embedded pools multiply connections
//! against an engine with hard limits; one `-db` in front of the engine bounds
//! them. So the pool's ceiling is a correctness property of the topology, not a
//! tuning knob, and these tests are about the arithmetic nobody does until an
//! engine starts refusing connections.

use yadgar_store::credentials::Secret;
use yadgar_store::pool::{
    connect_options, parse_ssl_mode, MySqlSslMode, PoolConfig, PoolError, DEFAULT_SSL_MODE,
};

fn cfg() -> PoolConfig {
    PoolConfig {
        host: "mariadb".into(),
        port: 3306,
        database: "task".into(),
        username: "task".into(),
        max_connections: 10,
        replicas: 2,
        engine_max_connections: 151,
        ssl_mode: MySqlSslMode::Required,
        ssl_ca: None,
    }
}

/// `MySqlSslMode` is `Debug + Clone + Copy` and nothing else — sqlx derives no
/// `PartialEq` on it — so equality is spelled through the debug rendering rather
/// than through an operator that does not exist.
fn mode_name(mode: MySqlSslMode) -> String {
    format!("{mode:?}")
}

/// Whether the built options carry a CA path, and WHICH one.
///
/// sqlx exposes `get_ssl_mode` and no `get_ssl_ca`, so the only reachable
/// evidence that the path was handed over is the options' own `Debug`. That
/// rendering ALSO CONTAINS THE PASSWORD — `MySqlConnectOptions` derives `Debug`
/// over an `Option<String>` password with no redaction — so it is reduced to a
/// yes-or-no here and NEVER put in an assertion message. A failing assertion's
/// message reaches CI logs, which is exactly the leak `PoolConfig::dsn` exists
/// to avoid.
fn carries_ca(options: &sqlx::mysql::MySqlConnectOptions, path: &str) -> bool {
    format!("{options:?}").contains(path)
}

#[test]
fn a_dsn_never_contains_the_password() {
    // The DSN reaches logs, tracing spans and error messages. The credential is
    // applied separately, at connect time.
    let dsn = cfg().dsn();
    assert!(dsn.starts_with("mysql://"));
    assert!(dsn.contains("mariadb:3306"), "got {dsn}");
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
    //
    // `DEFAULT_SSL_MODE` is the token the binary and the chart both name, so it
    // is asserted against the two modes that would betray the decision rather
    // than against whatever it happens to say today. `preferred` is the trap:
    // sqlx documents it as falling back to an unencrypted connection, and it is
    // sqlx's own default for anything that does not set a mode.
    assert_eq!(
        mode_name(parse_ssl_mode(DEFAULT_SSL_MODE).expect("the default must parse")),
        "Required",
        "the default must encrypt and refuse to fall back"
    );
    assert!(
        cfg().dsn().contains("ssl-mode=REQUIRED"),
        "TLS must be explicit in the DSN"
    );
}

/// D80: configuration is the seam.
///
/// A `bool` used to sit where the mode does, and it could express exactly two of
/// sqlx's five modes. `Required` encrypts and checks NO certificate; `VerifyCa`
/// and `VerifyIdentity` are the only ones that check one. So an operator on a
/// managed engine had no value to set at all.
///
/// **THIS TEST IS ABOUT THE PARSER AND NOTHING ELSE, and its name has now
/// promised too much twice.** It first claimed a verification that no CA was
/// pointed at. It then claimed that pointing a CA at `verify_ca` was the missing
/// half — and that is false: sqlx seeds the trust store with the public web
/// roots before appending the CA, so `verify_ca` accepts any publicly-trusted
/// certificate for any name however it is configured. `verify_ca` is therefore
/// refused when a connection is built.
///
/// **So PARSING IS NOT CONNECTING, and this asserts only the first.**
/// `parse_ssl_mode` still accepts `verify_ca`, deliberately: it is a token
/// parser, it has no business knowing what a TLS backend can do, and refusing
/// the token would make `UnknownSslMode`'s list of five accepted modes a lie.
/// The refusal belongs to [`PoolConfig::check_ssl_mode`], asserted by
/// [`the refusal test`](verify_ca_is_refused_because_it_cannot_bind_the_engines_identity).
#[test]
fn both_verifying_modes_parse_but_only_one_reaches_a_connection() {
    for (written, expected) in [
        ("verify_ca", "VerifyCa"),
        ("verify_identity", "VerifyIdentity"),
    ] {
        let mode = parse_ssl_mode(written).unwrap_or_else(|e| panic!("{written}: {e}"));
        assert_eq!(mode_name(mode), expected, "{written}");
    }

    let mut c = cfg();
    c.ssl_mode = parse_ssl_mode("verify_identity").expect("verify_identity is a mode");

    // Only the mode is lifted out, never the whole DSN. A DSN carries the
    // username, an assertion message reaches CI logs, and CodeQL's
    // `rust/cleartext-logging` rule is right to call that out even in a test
    // whose username is the literal "task".
    let dsn = c.dsn();
    let mode_in_dsn = dsn.rsplit("ssl-mode=").next().unwrap_or("");
    assert_eq!(
        mode_in_dsn, "VERIFY_IDENTITY",
        "the DSN in an error message must name the mode actually in force"
    );
}

/// THE FAIL-OPEN PARSE, which is the defect this function replaces.
///
/// Its predecessor was `env_or("DB_REQUIRE_TLS", "true") == "true"`. Under that
/// expression `1`, `TRUE`, `True`, `yes` and `on` all evaluated FALSE and
/// selected `Disabled` — silently, with no log line, while the operator's
/// configuration said the opposite. The operator states the configuration and
/// the code misreads it, which is worse than not offering the knob.
#[test]
fn an_unrecognised_ssl_mode_is_refused_rather_than_guessed() {
    for written in ["yes", "on", "1", "TRUE", "true", "false", "", "requird"] {
        let refused = parse_ssl_mode(written);
        assert!(
            refused.is_err(),
            "{written:?} is not an ssl-mode and must be refused at boot, not guessed \
             into one — got {:?}",
            refused.map(mode_name)
        );
    }

    let message = parse_ssl_mode("yes")
        .expect_err("yes is not a mode")
        .to_string();
    assert!(
        message.contains("yes"),
        "the message must quote what the operator wrote: {message}"
    );
    assert!(
        message.contains("verify_identity") && message.contains("required"),
        "the message must name what is accepted: {message}"
    );
}

/// A chart writes `verify-identity` and sqlx writes `verify_identity`. Two
/// spellings of one mode is a trap, so both reach the same mode.
#[test]
fn case_and_separator_do_not_change_the_mode() {
    for written in [
        "VERIFY_IDENTITY",
        "Verify_Identity",
        "verify-identity",
        "  verify-identity  ",
    ] {
        let mode = parse_ssl_mode(written).unwrap_or_else(|e| panic!("{written:?}: {e}"));
        assert_eq!(mode_name(mode), "VerifyIdentity", "{written:?}");
    }
}

/// TWO CODE PATHS THAT MUST AGREE ABOUT TLS WERE THE BUG.
///
/// The D7 capability probe in each `-db` binary built its own connection string
/// with `format!` and no `ssl-mode` in it, so it inherited sqlx's default —
/// `Preferred`, documented as "falling back to an unencrypted connection if an
/// encrypted connection cannot be established" — while the pool beside it was on
/// `Required`. What that cost is the GUARANTEE rather than the password: the
/// credential is a challenge-response scramble or an RSA-encrypted blob under
/// every default plugin, and an engine that offers TLS will have upgraded the
/// probe's connection anyway. But nothing required it to, so on an engine that
/// permits cleartext the probe's whole connection — handshake, queries and
/// results — could go unencrypted at every pod boot, with no log line either
/// way.
///
/// This asserts the one property that makes the second path impossible to get
/// wrong: the options are built HERE, once, and the mode in them is the
/// configured mode rather than any default.
#[test]
fn the_probe_and_the_pool_are_built_from_one_set_of_options() {
    let mut c = cfg();
    // Not `Required`, and not sqlx's `Preferred`: a constructor that ignored the
    // config and hardcoded either would still be green against those.
    c.ssl_mode = MySqlSslMode::VerifyIdentity;

    let options = connect_options(&c, &Secret::new("unused".into())).expect("verify_identity");

    assert_eq!(
        mode_name(options.get_ssl_mode()),
        "VerifyIdentity",
        "the connection carries the CONFIGURED mode, not a default"
    );
    assert_eq!(options.get_host(), "mariadb");
    assert_eq!(options.get_port(), 3306);
    assert_eq!(options.get_username(), "task");
    assert_eq!(options.get_database(), Some("task"));
}

/// **A VERIFYING MODE WITH NOTHING TO VERIFY AGAINST WAS THE WHOLE DEFECT.**
///
/// `connect_options` chained `.ssl_mode(...)` and stopped there. `PoolConfig`
/// carried no CA path and no `.ssl_ca(...)` call existed anywhere, so under
/// `tls-rustls-ring` sqlx built its trust store from
/// `webpki_roots::TLS_SERVER_ROOTS` — the public web roots, which sign no
/// operator-issued, RDS or Aurora engine certificate. Both verifying modes
/// therefore failed closed against every engine this estate runs, and `VerifyCa`
/// additionally routes through sqlx's `NoHostnameTlsVerifier`, which swallows
/// `NotValidForName`: it accepted ANY publicly-trusted certificate for ANY name.
///
/// So the assertion is that the CONFIGURED path reaches the connection. A mode
/// alone is not the capability, which is what `tests/pool.rs` used to imply.
///
/// Spelled with `verify_identity` rather than `verify_ca` because `verify_ca` no
/// longer reaches a connection at all — see
/// [`the refusal`](verify_ca_is_refused_because_it_cannot_bind_the_engines_identity).
#[test]
fn the_configured_ca_is_handed_to_sqlx() {
    const CA: &str = "/var/run/config/engine-ca/ca.crt";

    let mut c = cfg();
    c.ssl_mode = MySqlSslMode::VerifyIdentity;
    c.ssl_ca = Some(CA.into());

    let options = connect_options(&c, &Secret::new("unused".into())).expect("verify_identity");
    assert!(
        carries_ca(&options, CA),
        "the connection must be built with the authority the operator named; \
         without it sqlx trusts the public web roots, which sign no engine \
         certificate this estate issues"
    );
    assert_eq!(
        mode_name(options.get_ssl_mode()),
        "VerifyIdentity",
        "naming a CA must not change the mode the operator asked for"
    );
}

/// **`verify_ca` CANNOT BIND THE ENGINE'S IDENTITY UNDER THIS TLS BACKEND, WITH
/// OR WITHOUT A CA, so it is refused rather than offered.**
///
/// Read from the vendored crates rather than inferred. `sqlx-core 0.9.0`,
/// `src/net/tls/tls_rustls.rs`: the non-`accept_invalid_certs` branch opens with
/// `let mut cert_store = import_root_certs();` and only THEN appends the
/// operator's CA. Under the `webpki-roots` feature this crate resolves to — the
/// lockfile carries `webpki-roots` and not `rustls-native-certs` —
/// `import_root_certs` is `RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS)`.
/// So naming a CA WIDENS the trust set and never restricts it.
///
/// `sqlx-mysql 0.9.0`, `src/connection/tls.rs` then sets
/// `accept_invalid_hostnames` for every mode except `VerifyIdentity`, which
/// routes `VerifyCa` through `NoHostnameTlsVerifier` — and that verifier maps
/// `CertificateError::NotValidForName` to `Ok(ServerCertVerified::assertion())`.
///
/// Put together: under `verify_ca` **anyone holding any publicly-trusted
/// certificate for any name at all is accepted as the engine**. Adding the
/// operator's own CA does not close that, because the public roots stay in the
/// store beside it. A mode named for verification that accepts an arbitrary
/// stranger is worse than one that refuses, because it reports success — which
/// is the same shape as the `DB_REQUIRE_TLS` boolean this crate already deleted.
///
/// `verify_identity` keeps the public roots too, and that is fine: it checks the
/// hostname, and no public authority may issue for a private, cluster-internal
/// name. The NAME is what makes the operator's own CA the only usable signer,
/// which is why the hostname check is the half that carries the guarantee.
#[test]
fn verify_ca_is_refused_because_it_cannot_bind_the_engines_identity() {
    // BOTH arms, because the CA is exactly what does not rescue this mode.
    for ca in [None, Some("/var/run/config/engine-ca/ca.crt".into())] {
        let mut c = cfg();
        c.ssl_mode = MySqlSslMode::VerifyCa;
        c.ssl_ca = ca;

        let err = connect_options(&c, &Secret::new("unused".into()))
            .expect_err("verify_ca accepts any publicly-trusted certificate for any name");
        assert!(matches!(err, PoolError::SslModeCannotVerify { .. }));

        // The same refusal must be reachable WITHOUT a credential, so a consumer
        // can stop while assembling its config rather than only at connect time.
        assert!(matches!(
            c.check_ssl_mode(),
            Err(PoolError::SslModeCannotVerify { .. })
        ));

        let msg = err.to_string();
        // **THE INSTRUCTION, NOT A MENTION.** Asserting only that
        // `verify_identity` appears somewhere is a test that passes while the
        // guidance is gone — the message names that mode three more times in
        // passing, and deleting the sentence that tells the operator what to DO
        // left this green when it was tried. So the assertion is the imperative
        // itself, on the `msg.contains("migration lock")` precedent above:
        // refusing a mode without naming the replacement reads as "no
        // verification is available here", and the operator downgrades.
        assert!(
            msg.contains("Use verify_identity"),
            "the refusal must TELL the operator which mode to use, not merely \
             mention it: {msg}"
        );
        // Spelled as `ssl_mode_name` renders it, which is the spelling a DSN in
        // an adjacent error message also carries. One mode, one rendering: two
        // spellings across two messages is what `parse_ssl_mode` normalises away
        // at the boundary and must not reappear inside.
        assert!(
            msg.to_ascii_lowercase().contains("verify_ca"),
            "the message must quote the mode the operator asked for: {msg}"
        );
    }
}

/// **THE DEPLOYMENT THE PREVIOUS CHANGE WAS PROTECTING STILL WORKS.**
///
/// `store#14` left `verify_ca` reachable on the reasoning that refusing a
/// verifying mode with no CA would break an engine whose authority IS a public
/// root — Azure MySQL flexible-server. That reasoning conflated two things. The
/// honest mode for such an engine is `verify_identity`: public roots for the
/// chain, plus the hostname check that makes the chain mean something. It needs
/// no CA file and is refused by nothing here.
#[test]
fn a_public_root_engine_still_verifies_with_no_ca_file() {
    let mut c = cfg();
    c.ssl_mode = MySqlSslMode::VerifyIdentity;
    c.ssl_ca = None;

    let options = connect_options(&c, &Secret::new("unused".into()))
        .expect("verify_identity with no CA is a real deployment, not an omission");
    assert_eq!(mode_name(options.get_ssl_mode()), "VerifyIdentity");
}

/// The non-verifying modes are untouched. `required` stays the default, and this
/// change is a capability fix rather than a cut-over.
#[test]
fn the_non_verifying_modes_are_not_refused() {
    for mode in [
        MySqlSslMode::Disabled,
        MySqlSslMode::Preferred,
        MySqlSslMode::Required,
    ] {
        let mut c = cfg();
        c.ssl_mode = mode;
        assert!(
            connect_options(&c, &Secret::new("unused".into())).is_ok(),
            "{} is honest about checking no certificate and stays available",
            mode_name(mode)
        );
    }
}

/// **NO CA IS A LEGITIMATE DEPLOYMENT, so nothing is invented for it.**
///
/// An engine whose authority IS a public root — Azure MySQL flexible-server is
/// the case — needs no file, and a default path substituted here would be one
/// sqlx tries to read and fails on. `None` must therefore reach sqlx as nothing
/// at all rather than as a guess.
///
/// The residue this used to leave is closed by
/// [`the refusal`](verify_ca_is_refused_because_it_cannot_bind_the_engines_identity):
/// `verify_ca` skipped the hostname check while keeping the public web roots in
/// the trust store, so it accepted any publicly-trusted certificate for any
/// name. That is the mode's own property and no CA file fixed it, so the mode
/// is refused rather than documented.
#[test]
fn no_ca_is_carried_when_none_is_configured() {
    let mut c = cfg();
    c.ssl_mode = MySqlSslMode::VerifyIdentity;
    c.ssl_ca = None;

    let options = connect_options(&c, &Secret::new("unused".into())).expect("verify_identity");
    assert!(
        !carries_ca(&options, "ssl_ca: Some"),
        "an unset CA must reach sqlx as unset, never as a path nobody configured"
    );
}

/// `preferred` stays reachable, because refusing to name it would not remove it
/// — it would only leave sqlx's silent default as the one way to get it.
#[test]
fn the_falling_back_mode_is_selectable_only_by_asking_for_it_out_loud() {
    assert_eq!(
        mode_name(parse_ssl_mode("preferred").expect("preferred is a real mode")),
        "Preferred"
    );
    assert_eq!(
        mode_name(parse_ssl_mode("disabled").expect("disabled is a real mode")),
        "Disabled"
    );
}

/// ONE CONNECTION IS A DEADLOCK, NOT A TIGHT BUDGET.
///
/// `migrate::apply` holds the migration lock on one connection while the
/// migrations run on a second. With `max_connections = 1` the lock connection IS
/// the pool, so `apply_locked` waits the full acquire timeout and boot fails
/// after 30 seconds with "pool timed out while waiting for an open connection" —
/// which names the pool and not the cause. Measured before this check existed.
///
/// Only 0 used to be rejected, so 1 passed the headroom check and failed 30
/// seconds later, one layer from the reason.
#[test]
fn one_connection_is_rejected_because_the_migration_lock_needs_a_second() {
    let mut c = cfg();
    c.max_connections = 1;

    let err = c
        .check_engine_headroom()
        .expect_err("a single-connection pool deadlocks its own migration");
    assert!(matches!(err, PoolError::InvalidSize { .. }));

    let msg = err.to_string();
    assert!(
        msg.contains("migration lock"),
        "the message must name the cause, not just the number: {msg}"
    );
}

#[test]
fn two_connections_is_the_floor_and_is_accepted() {
    let mut c = cfg();
    c.max_connections = 2;
    assert!(c.check_engine_headroom().is_ok());
}
