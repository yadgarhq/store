//! Asking an engine what it can actually do (D69).
//!
//! **Execute the capability; do not infer it from a version string.** A version
//! table is a per-engine hardcoded assumption, which is the coupling D7 exists
//! to refuse, and its failure mode is the worst available: a build flag, a
//! distribution variant or a vendor fork makes it answer YES, and the truth
//! arrives later as a query error on a live request.
//!
//! **Every probe here runs on a `SELECT`-only grant.** That is measured, not
//! assumed — verified 2026-08-30 against MariaDB 11.8.8 with a user holding
//! `USAGE` on `*.*` and `SELECT` on one schema, with `CREATE TEMPORARY TABLE`
//! confirmed refused on the same connection. It is the reason D58 needs no
//! second, wider probe credential: the serving credential probes.
//!
//! One result contradicted the documentation and is why this was measured.
//! MySQL's manual requires `SELECT` plus one of `DELETE`/`LOCK TABLES`/`UPDATE`
//! for `SELECT ... FOR UPDATE`; MariaDB's own docs are silent and it forked
//! before that clarification. MariaDB grants it on `SELECT` alone. Inheriting
//! the MySQL rule would have widened the credential to satisfy a restriction
//! this engine does not impose.

use sqlx::{MySqlConnection, Row};

use crate::capability::{Capability, CapabilityReport, Determination};

/// MDEV-36568 — open, priority Critical, targeted at a 13.2 rolling release —
/// describes InnoDB's current relevance scoring as "TF-IDF-based" and frames
/// BM25 as future feasibility research.
///
/// MariaDB's own documentation names no algorithm at all and no runtime flag
/// exposes one, which is itself the finding: scoring identity is not
/// discoverable by any query. So this is the one capability that must be
/// ASSERTED, and when the ticket ships this constant is the single place that
/// changes.
const BM25_SOURCE: &str = "MDEV-36568 (open, targeted 13.2)";
const BM25_CONCLUSION: &str =
    "InnoDB scores full-text with a TF-IDF variant, not the BM25 recall/v1 declares";

/// Run every probe against a live connection.
///
/// Takes a borrowed connection rather than owning a pool so the caller controls
/// lifetime, and so D69's two-pass ordering can reuse one connection: function
/// probes run before migrations, index-dependent probes after.
pub async fn run(conn: &mut MySqlConnection) -> Result<CapabilityReport, sqlx::Error> {
    let mut report = CapabilityReport::default();

    let version: String = sqlx::query("SELECT VERSION()")
        .fetch_one(&mut *conn)
        .await?
        .try_get(0)?;

    // Vector distance over literals. No table, no FROM, no DDL — which is the
    // measurement the read-only grant conclusion rests on.
    report.record(
        Capability::Vector,
        probe_ok(
            conn,
            "SELECT VEC_DISTANCE_EUCLIDEAN(VEC_FromText('[1,2]'), VEC_FromText('[3,4]'))",
        )
        .await?,
        Determination::Probed,
    );

    report.record(
        Capability::Json,
        probe_ok(conn, "SELECT JSON_VALID('{\"a\":1}')").await?,
        Determination::Probed,
    );

    report.record(
        Capability::Transactions,
        probe_ok(conn, "SELECT @@autocommit").await?,
        Determination::Probed,
    );

    // FOR UPDATE parses and executes only inside a transaction, and DUAL gives
    // it something to lock without needing a table the credential can see.
    report.record(
        Capability::RowLocking,
        probe_ok(conn, "SELECT 1 FROM DUAL FOR UPDATE").await?,
        Determination::Probed,
    );

    // The one that cannot be asked. Absent on every shipping MariaDB, and the
    // record says so with its provenance attached rather than in a comment.
    report.record(
        Capability::FullTextBm25,
        false,
        Determination::Asserted {
            observed_version: version,
            conclusion: BM25_CONCLUSION.to_string(),
            source: BM25_SOURCE.to_string(),
        },
    );

    Ok(report)
}

/// Did the engine evaluate this expression?
///
/// `sql` is `&'static str` deliberately: every probe is a literal in this file,
/// and a probe assembled from anything a caller supplies would be a place to
/// inject SQL on a connection that exists to answer yes-or-no questions.
///
/// A syntax or unknown-function error means the capability is absent, which is
/// the answer we want — but a dropped connection or a timeout is NOT an absent
/// capability, and reporting it as one would turn a network blip into a
/// confident "your engine lacks vectors". Only errors the SERVER returned count
/// as absence; everything else propagates.
async fn probe_ok(conn: &mut MySqlConnection, sql: &'static str) -> Result<bool, sqlx::Error> {
    match sqlx::query(sql).fetch_optional(&mut *conn).await {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(_)) => Ok(false),
        Err(other) => Err(other),
    }
}
