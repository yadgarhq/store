//! Whether [`PoolConfig::ssl_ca`] reaches the TLS handshake, measured against a
//! real engine serving a certificate signed by a CA this suite controls.
//!
//! **THE OBVIOUS TEST FOR THIS IS WORTHLESS, AND THAT IS WHY THIS FILE EXISTS.**
//! The intuitive proof points `ssl_ca` at a bogus CA and asserts the connection
//! is REFUSED. That test passes even if `ssl_ca` is ignored entirely: sqlx seeds
//! its trust store with `webpki_roots::TLS_SERVER_ROOTS` BEFORE appending the
//! named file, and the public web roots sign no private engine certificate — so
//! the refusal arm is produced by the seeded roots alone and carries no
//! information about whether the appended CA was ever consulted. A suite built
//! that way asserts a value the implementation would produce with the
//! `.ssl_ca(path)` call deleted.
//!
//! **The proof is a PAIR, and only the positive arm carries the information.**
//!
//! - [`the_named_ca_is_what_makes_a_private_ca_engine_reachable`] points
//!   `ssl_ca` at the CA that ACTUALLY SIGNED the engine's certificate and
//!   requires the connection to SUCCEED. This one can only pass if the appended
//!   CA reached the TLS configuration, because the seeded public roots do not
//!   contain a private development CA.
//! - [`a_valid_but_unrelated_ca_is_refused`] points it at a second, unrelated CA
//!   and requires REFUSAL. Alone it proves nothing; paired with the positive arm
//!   it excludes "this configuration accepts everything".
//! - [`without_a_ca_the_same_engine_is_refused`] is the arm that makes the pair
//!   attributable. It is what the code does with the `.ssl_ca(path)` call
//!   removed, so it states the mutation verdict as a test rather than as a claim
//!   in a commit message.
//!
//! **The mode is `verify_identity` and cannot be anything else.** `verify_ca` is
//! refused at [`PoolConfig::check_ssl_mode`] (store#15) because sqlx routes it
//! through `NoHostnameTlsVerifier`; `required` and `preferred` set
//! `accept_invalid_certs` and would accept this engine with any CA or none. So
//! `verify_identity` is the only mode under which a CA file changes an outcome,
//! and the engine's certificate must carry a SAN matching the DSN's host.
//!
//! **THESE TESTS ARE `#[ignore]`, WHICH IS NOT THE SAME AS SKIPPED.** Every
//! other engine-backed suite here panics when its fixture is absent, because CI
//! supplies that fixture and a silent pass would be the failure D69 exists to
//! stop. CI supplies NO private-CA engine today — the MariaDB in
//! `yadgarhq/actions` is a service container, service containers start before
//! any step runs, and MariaDB reads `ssl_cert`/`ssl_key` only at startup, so
//! there is no point at which generated certificates could reach it. A panic CI
//! cannot satisfy is not a tripwire, it is a permanently red build. `#[ignore]`
//! keeps the non-execution STATED: every `cargo test` run in every CI log counts
//! these in its `ignored` total, where an early `return` would hide them. The
//! helpers below still panic once the suite is asked to run, so it cannot pass
//! against nothing.
//!
//! **Standing the fixture up**, which is also what CI would need to do in a
//! step rather than a service:
//!
//! ```text
//! D=/tmp/yadgar-store-tls; mkdir -p $D
//! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//!   -keyout $D/good-ca.key -out $D/good-ca.pem -subj "/CN=yadgar-store-test-good-ca"
//! openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
//!   -keyout $D/wrong-ca.key -out $D/wrong-ca.pem -subj "/CN=yadgar-store-test-wrong-ca"
//! openssl req -newkey rsa:2048 -nodes \
//!   -keyout $D/server.key -out $D/server.csr -subj "/CN=localhost"
//! printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > $D/server.ext
//! openssl x509 -req -in $D/server.csr -CA $D/good-ca.pem -CAkey $D/good-ca.key \
//!   -CAcreateserial -out $D/server.pem -days 3650 -extfile $D/server.ext
//! chmod 644 $D/*.pem $D/*.key   # the container's mysql uid must READ these
//!
//! podman run -d --name yadgar-store-tls-probe -p 127.0.0.1:3307:3306 \
//!   -e MARIADB_ROOT_PASSWORD=probe -e MARIADB_DATABASE=probe -v $D:/certs:ro \
//!   mariadb:11.8 --ssl-ca=/certs/good-ca.pem --ssl-cert=/certs/server.pem \
//!   --ssl-key=/certs/server.key --require-secure-transport=ON
//!
//! export YADGAR_TEST_TLS_DSN='mysql://root:probe@localhost:3307/probe'
//! export YADGAR_TEST_TLS_CA=$D/good-ca.pem
//! export YADGAR_TEST_TLS_WRONG_CA=$D/wrong-ca.pem
//! cargo test --test engine_tls -- --ignored
//! ```
//!
//! `localhost` rather than `127.0.0.1` in the DSN deliberately: `verify_identity`
//! checks the host against the certificate, and the `DNS:localhost` SAN is the
//! better-trodden path of the two the certificate carries.
//!
//! **A fixture whose key the server cannot read produces this suite's one
//! false verdict.** MariaDB then starts with TLS off, `require_secure_transport`
//! refuses every connection, and all three arms error — which looks exactly like
//! "the CA was never consulted". The positive arm therefore asserts the
//! connection it opened is genuinely encrypted, and the refusing arms assert the
//! refusal names a CERTIFICATE rather than accepting any error at all.

use yadgar_store::credentials::Secret;
use yadgar_store::pool::{connect, MySqlSslMode, PoolConfig, PoolError};

const DSN: &str = "YADGAR_TEST_TLS_DSN";
const CA: &str = "YADGAR_TEST_TLS_CA";
const WRONG_CA: &str = "YADGAR_TEST_TLS_WRONG_CA";

/// The recipe, repeated where a runner will actually see it. A suite asked to
/// run against nothing must say what is missing, not report success.
fn require(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        panic!(
            "{var} is unset, so there is no private-CA engine to verify against.\n\
             This suite asserts that PoolConfig::ssl_ca reaches the TLS handshake; \
             running it without an engine whose certificate a KNOWN CA signed would \
             report success while proving nothing.\n\
             See this file's header for the openssl and podman recipe. All three of \
             {DSN}, {CA} and {WRONG_CA} are required."
        )
    })
}

/// A config pointed at the TLS fixture, under the only mode a CA can change.
///
/// Deliberately NOT built through `tests/common/mod.rs`. That helper hardcodes
/// `ssl_mode: Disabled` and `ssl_ca: None` for the plaintext CI engine, so
/// reusing it here would open a plaintext connection and assert nothing about a
/// certificate.
fn tls_config(ca: Option<String>) -> (PoolConfig, Secret) {
    let url = require(DSN);
    let rest = url.trim_start_matches("mysql://");
    let (creds, hostpart) = rest.split_once('@').expect("dsn needs user:pass@host");
    let (user, pass) = creds.split_once(':').expect("dsn needs a password");
    let (hostport, database) = hostpart.split_once('/').expect("dsn needs a database");
    let (host, port) = hostport.split_once(':').expect("dsn needs a port");

    (
        PoolConfig {
            // The certificate is checked against THIS string. A DSN naming an
            // address the SAN does not carry fails on the name, which is a
            // different defect wearing this suite's failure message.
            host: host.to_string(),
            port: port.parse().expect("port"),
            database: database.to_string(),
            username: user.to_string(),
            max_connections: 2,
            replicas: 1,
            engine_max_connections: 151,
            ssl_mode: MySqlSslMode::VerifyIdentity,
            ssl_ca: ca.map(Into::into),
        },
        Secret::new(pass.to_string()),
    )
}

/// The refusal every arm but the positive one expects, reduced to its reason.
///
/// A refusal is only evidence when it names a CERTIFICATE. "Connection refused"
/// against a stopped container would satisfy an `is_err()` assertion and satisfy
/// it forever, which is the shape of test this whole file is a correction to.
fn assert_refused_over_the_certificate(err: PoolError, arm: &str) {
    let PoolError::Connect { source, .. } = &err else {
        panic!("{arm}: expected a connect failure, got {err:?}");
    };
    let message = source.to_string();
    assert!(
        message.contains("certificate"),
        "{arm}: the refusal must be about the engine's CERTIFICATE, or this arm \
         would pass just as well against a stopped engine. rustls said: {message}"
    );
}

/// THE ARM THAT CARRIES THE INFORMATION.
///
/// sqlx seeds its root store with the public web roots and only then appends
/// `ssl_ca`, so no public authority signs this engine and nothing in the seeded
/// set can accept it. A success here is therefore attributable to the appended
/// file and to nothing else — which is precisely what
/// [`without_a_ca_the_same_engine_is_refused`] measures from the other side.
#[tokio::test]
#[ignore = "needs a private-CA MariaDB; see this file's header for the recipe"]
async fn the_named_ca_is_what_makes_a_private_ca_engine_reachable() {
    let (config, secret) = tls_config(Some(require(CA)));

    let pool = connect(&config, &secret)
        .await
        .expect("the CA that signed this engine's certificate must make it reachable");

    // FIXTURE SANITY, not decoration. Were the server's key unreadable, MariaDB
    // would serve no TLS at all, and a suite about certificate verification
    // would be reporting on a plaintext connection.
    let (_, cipher): (String, String) = sqlx::query_as("SHOW STATUS LIKE 'Ssl_cipher'")
        .fetch_one(&pool)
        .await
        .expect("the engine must answer a status query");
    assert!(
        !cipher.is_empty(),
        "the connection is not encrypted, so this arm proves nothing about a CA"
    );
}

/// The other half of the pair: a CA that is perfectly valid and simply did not
/// sign this engine. Alone this arm is uninformative — it passes with `ssl_ca`
/// ignored entirely — and it is here only to exclude "everything is accepted"
/// from the positive arm's success.
#[tokio::test]
#[ignore = "needs a private-CA MariaDB; see this file's header for the recipe"]
async fn a_valid_but_unrelated_ca_is_refused() {
    let (config, secret) = tls_config(Some(require(WRONG_CA)));

    let err = connect(&config, &secret)
        .await
        .expect_err("a CA that signed nothing here must not make this engine reachable");

    assert_refused_over_the_certificate(err, "wrong CA");
}

/// WHAT THE CODE DOES WITH THE `.ssl_ca(path)` CALL DELETED, asserted rather
/// than assumed.
///
/// Deleting the application at `pool.rs`'s `connect_options` makes every
/// configuration behave as this arm does. So this arm and the positive one
/// disagree exactly when the CA reaches the handshake, and the mutation verdict
/// is a property of the suite instead of a claim someone has to re-run by hand.
///
/// It also documents the deployment shape [`PoolConfig::ssl_ca`]'s own docs call
/// legitimate: `verify_identity` with no CA is right for an engine whose
/// authority IS a public root, and wrong for this one.
#[tokio::test]
#[ignore = "needs a private-CA MariaDB; see this file's header for the recipe"]
async fn without_a_ca_the_same_engine_is_refused() {
    let (config, secret) = tls_config(None);

    let err = connect(&config, &secret)
        .await
        .expect_err("the public web roots sign no private engine certificate");

    assert_refused_over_the_certificate(err, "no CA");
}
