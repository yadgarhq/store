//! The capability probe against a real engine (D69).
//!
//! These tests need a MariaDB. CI supplies one as a service container; locally,
//! `YADGAR_TEST_DSN` points at any instance. They are NOT skipped silently when
//! it is absent — `require_dsn` panics with the reason, because a probe suite
//! that quietly passes with nothing to probe is the failure D69 exists to stop
//! one level up. The whole point of this file is that it cannot pass in 0.00s.

use yadgar_store::capability::{Capability, CapabilitySet, Determination};
use yadgar_store::probe;

fn require_dsn() -> String {
    std::env::var("YADGAR_TEST_DSN").unwrap_or_else(|_| {
        panic!(
            "YADGAR_TEST_DSN is unset, so there is no engine to probe.\n\
             These tests assert what a real MariaDB does; running them without \
             one would report success while proving nothing (D69).\n\
             CI provides a service container. Locally:\n  \
             podman run -d --name mdb -e MARIADB_ROOT_PASSWORD=probe \\\n    \
             -e MARIADB_DATABASE=probe -p 3306:3306 mariadb:11.8\n  \
             export YADGAR_TEST_DSN='mysql://root:probe@127.0.0.1:3306/probe'"
        )
    })
}

async fn connect() -> sqlx::MySqlConnection {
    use sqlx::Connection;
    sqlx::MySqlConnection::connect(&require_dsn())
        .await
        .expect("could not reach the engine named by YADGAR_TEST_DSN")
}

/// The measurement D69 rests on: vector distance needs no table and no DDL, so
/// the serving credential can probe and no second credential is required.
#[tokio::test]
async fn vector_distance_is_provable_without_a_table() {
    let mut conn = connect().await;
    let report = probe::run(&mut conn).await.expect("probe failed");

    assert!(
        report.offers(Capability::Vector),
        "MariaDB 11.8+ evaluates VEC_DISTANCE_EUCLIDEAN over literals; \
         report said otherwise: {report:?}"
    );
    assert_eq!(
        report.determination(Capability::Vector),
        Some(&Determination::Probed),
        "vector must be PROBED, never asserted from a version string (D69)"
    );
}

#[tokio::test]
async fn json_transactions_and_row_locking_are_probed() {
    let mut conn = connect().await;
    let report = probe::run(&mut conn).await.expect("probe failed");

    for cap in [
        Capability::Json,
        Capability::Transactions,
        Capability::RowLocking,
    ] {
        assert!(report.offers(cap), "{cap} should be present on MariaDB");
        assert_eq!(
            report.determination(cap),
            Some(&Determination::Probed),
            "{cap} is executable, so it must be probed rather than asserted"
        );
    }
}

/// MDEV-36568: InnoDB scores with a TF-IDF variant, so the BM25 `recall/v1`
/// declares is unsatisfiable on any shipping MariaDB. A structured negative
/// carrying its own provenance, not a comment somewhere.
#[tokio::test]
async fn bm25_is_absent_and_says_why() {
    let mut conn = connect().await;
    let report = probe::run(&mut conn).await.expect("probe failed");

    assert!(
        !report.offers(Capability::FullTextBm25),
        "InnoDB does not implement BM25 (MDEV-36568)"
    );

    match report.determination(Capability::FullTextBm25) {
        Some(Determination::Asserted {
            observed_version,
            source,
            ..
        }) => {
            assert!(
                observed_version.contains("MariaDB"),
                "the assertion must record the version it was made from, got {observed_version:?}"
            );
            assert!(
                source.contains("MDEV-36568"),
                "the citation is data, not prose in a comment; got {source:?}"
            );
        }
        other => panic!(
            "scoring identity is not discoverable by any query, so it must be \
             ASSERTED with provenance, not probed. Got {other:?}"
        ),
    }
}

/// D7: a gap is a boot failure, and the message is what an operator reads.
#[tokio::test]
async fn a_ranked_module_is_refused_and_the_error_names_the_provenance() {
    let mut conn = connect().await;
    let report = probe::run(&mut conn).await.expect("probe failed");

    let ranked = CapabilitySet::from([Capability::Transactions, Capability::FullTextBm25]);
    let err = report
        .satisfies(&ranked)
        .expect_err("a ranked module must not boot against InnoDB full-text");

    let msg = err.to_string();
    assert!(msg.contains("fulltext-bm25"), "names the gap: {msg}");
    assert!(
        msg.contains("MDEV-36568"),
        "an asserted gap must carry its citation into the boot error, or an \
         operator cannot tell a measurement from a belief: {msg}"
    );
}

/// The addressed modules must not require vector search (D10), so they boot.
#[tokio::test]
async fn an_addressed_module_boots() {
    let mut conn = connect().await;
    let report = probe::run(&mut conn).await.expect("probe failed");
    report
        .satisfies(&CapabilitySet::from([Capability::Transactions]))
        .expect("an addressed module needs only transactions");
}
