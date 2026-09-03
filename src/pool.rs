//! Connection pooling, and the arithmetic D4 exists to make possible.
//!
//! The `-db` twin is not only a boundary. D4 names it the **connection
//! concentrator**: N replicas of a logic service with embedded pools multiply
//! connections against an engine with hard limits, and one `-db` in front of the
//! engine bounds them. That makes the pool ceiling a correctness property of the
//! topology rather than a tuning knob — which is why the check below runs at
//! boot and refuses, in the same spirit as D7's capability probe.
//!
//! The failure it prevents does not present as a configuration error. It
//! presents as intermittent "too many connections" under load, on whichever
//! service happens to connect last, and scaling up makes it worse.

use std::path::PathBuf;

use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::MySqlPool;

use crate::credentials::Secret;

/// Re-exported so a `-db` binary names the transport mode through the seam that
/// already owns connections, instead of reaching into sqlx for a type this crate
/// is responsible for choosing.
pub use sqlx::mysql::MySqlSslMode;

/// Connections an engine keeps back for `SUPER`, so an operator can still get in
/// when the pools have taken everything.
///
/// A headroom check that ignores this passes right up to the moment nobody can
/// log in to diagnose why nothing else can.
const OPERATOR_RESERVE: u32 = 5;

/// The smallest pool that can migrate itself.
///
/// [`crate::migrate::apply`] holds the cluster-wide migration lock on ONE
/// connection — MariaDB ties `GET_LOCK` to a connection, which is the property
/// that stops a killed replica stranding it — while the migrations themselves
/// run on a SECOND. A pool of one therefore waits for a connection it is itself
/// holding.
///
/// Measured before this floor existed: boot hung for 30.0s and then failed with
/// "pool timed out while waiting for an open connection", which names the pool
/// and not the cause. Only 0 was rejected, so 1 passed the headroom check and
/// failed half a minute later, one layer away from the reason. Refusing at boot
/// with a message that says *migration lock* is the whole fix.
const MIN_CONNECTIONS: u32 = 2;

/// The mode a `-db` uses when its deployment says nothing: encrypt, and refuse
/// to fall back.
///
/// A STRING rather than a [`MySqlSslMode`], so the binary's environment default,
/// the chart's value and this crate all name one token. It is deliberately NOT
/// `preferred`: that is sqlx's own default, and sqlx documents it as falling
/// back to an unencrypted connection when an encrypted one cannot be
/// established.
pub const DEFAULT_SSL_MODE: &str = "required";

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,

    /// Per-replica ceiling.
    pub max_connections: u32,
    /// How many replicas of this `-db` will run. Part of the config precisely
    /// because the ceiling that matters is the product, not this pool alone.
    pub replicas: u32,
    /// The engine's own limit, so the arithmetic can be checked rather than
    /// assumed.
    pub engine_max_connections: u32,

    /// How TLS is negotiated to the engine, and how far the engine's identity is
    /// checked. D58 puts every `-db` on TLS, and the RUSTSEC-2023-0071 exception
    /// recorded in each module's `deny.toml` depends on that staying true.
    ///
    /// A `bool` used to sit here, and it could express two of sqlx's five modes.
    /// `Required` encrypts and verifies NO certificate; `VerifyCa` and
    /// `VerifyIdentity` are the ones that check the engine is who it claims. So
    /// an operator on a managed engine had no value to set at all, which is what
    /// D80 forbids: configuration is the seam.
    ///
    /// **A MODE ALONE IS NOT THE CAPABILITY, and saying it was is what this
    /// field's own documentation got wrong.** Selecting `verify_ca` reached the
    /// mode and reached nothing else: [`PoolConfig::ssl_ca`] did not exist, so
    /// there was no way to name the authority that signs the engine's
    /// certificate, and sqlx fell back to the public web roots — which sign no
    /// operator-issued, RDS or Aurora engine certificate. Both verifying modes
    /// therefore failed against the estate's own engines. That is what
    /// [`PoolConfig::ssl_ca`] closes, and until it shipped the honest statement
    /// was that verification was NOT reachable rather than that it merely needed
    /// a recompile.
    ///
    /// Build it with [`parse_ssl_mode`], which refuses what it does not
    /// recognise.
    pub ssl_mode: MySqlSslMode,

    /// The authority whose signature makes the engine's certificate acceptable,
    /// as a path to a PEM file. Read by sqlx at connect time.
    ///
    /// **`None` IS NOT "no opinion" — it is sqlx's own trust store, and under
    /// `tls-rustls-ring` that is `webpki_roots::TLS_SERVER_ROOTS`: the public web
    /// roots and nothing else.** No operator-issued CA is in that set, and
    /// neither is the Amazon RDS or Aurora authority, so under `verify_ca` and
    /// `verify_identity` a private-CA engine is refused with a certificate error
    /// that names no missing file.
    ///
    /// **The second consequence is the one that decides the shape of this
    /// field.** `VerifyCa` routes through sqlx's `NoHostnameTlsVerifier`, which
    /// swallows `NotValidForName` — so it accepts ANY publicly-trusted
    /// certificate for ANY name. A mode called `verify_ca` that verifies neither
    /// the authority the operator meant nor the hostname is worse than one that
    /// fails closed, because it reports success.
    ///
    /// **AND SETTING THIS FIELD DOES NOT CLOSE THAT, which is why `verify_ca`
    /// is refused rather than documented.** The paragraph above was once
    /// written as "with no CA named", which reads as though a CA were the
    /// missing half. It is not. `sqlx-core`'s `tls_rustls.rs` seeds the trust
    /// store with the public web roots and only THEN appends this file, so a CA
    /// WIDENS the trust set and never restricts it: `verify_ca` keeps accepting
    /// any publicly-trusted certificate for any name with this field set.
    /// [`connect_options`] refuses that mode.
    ///
    /// So this field's job is narrower than it first looks. It makes a
    /// PRIVATE-CA engine REACHABLE under `verify_identity`; the hostname check
    /// is what makes the connection SAFE. The two are separate properties, and
    /// only the pair is a guarantee.
    ///
    /// A PATH, never a PEM in the configuration, and never an issuer-specific
    /// resource (D80). A file is what a mounted Secret, a ConfigMap and a bare
    /// VM all produce, and it is what rotates without a redeploy.
    ///
    /// Leaving it `None` under `verify_identity` is a legitimate deployment
    /// rather than an omission — an Azure MySQL engine whose authority IS a
    /// public root needs no file — so it is not refused at boot. That
    /// deployment is exactly why the refusal lands on the MODE and not on an
    /// absent CA: the file is genuinely optional, and `verify_ca` is unsafe
    /// with one or without one.
    pub ssl_ca: Option<PathBuf>,
}

/// Parse an operator-supplied ssl-mode, refusing anything unrecognised.
///
/// **Refusing is the point.** The expression this replaces was
/// `env_or("DB_REQUIRE_TLS", "true") == "true"`, under which `1`, `TRUE`,
/// `True`, `yes` and `on` all evaluated FALSE and selected an unencrypted
/// connection — silently, with no log line, while the operator's configuration
/// said the opposite. A value nobody recognises is a question, and the answer to
/// a question about transport security is not a guess.
///
/// Case and separator are normalised because a chart writes `verify-identity`
/// and sqlx writes `verify_identity`. Two spellings of one mode is a trap rather
/// than a dialect.
pub fn parse_ssl_mode(value: &str) -> Result<MySqlSslMode, PoolError> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "disabled" => Ok(MySqlSslMode::Disabled),
        "preferred" => Ok(MySqlSslMode::Preferred),
        "required" => Ok(MySqlSslMode::Required),
        "verify_ca" => Ok(MySqlSslMode::VerifyCa),
        "verify_identity" => Ok(MySqlSslMode::VerifyIdentity),
        _ => Err(PoolError::UnknownSslMode {
            value: value.to_string(),
        }),
    }
}

/// The name sqlx itself gives a mode in a connection string, so an error message
/// and a real DSN cannot disagree about which mode was in force.
fn ssl_mode_name(mode: MySqlSslMode) -> &'static str {
    match mode {
        MySqlSslMode::Disabled => "DISABLED",
        MySqlSslMode::Preferred => "PREFERRED",
        MySqlSslMode::Required => "REQUIRED",
        MySqlSslMode::VerifyCa => "VERIFY_CA",
        MySqlSslMode::VerifyIdentity => "VERIFY_IDENTITY",
    }
}

impl PoolConfig {
    /// Connection string **without** the credential.
    ///
    /// The credential is applied separately at connect time, because a DSN
    /// reaches logs, tracing spans and error messages, and one carrying a
    /// password is one that leaks eventually — the same reasoning that makes
    /// `Secret` redact itself in `Debug`.
    pub fn dsn(&self) -> String {
        let mode = ssl_mode_name(self.ssl_mode);
        format!(
            "mysql://{user}@{host}:{port}/{db}?ssl-mode={mode}",
            user = self.username,
            host = self.host,
            port = self.port,
            db = self.database,
            mode = mode,
        )
    }

    /// Refuse an ssl-mode that cannot do what its name says.
    ///
    /// **A `PoolConfig` METHOD, beside [`PoolConfig::check_engine_headroom`],
    /// because that is where this estate already puts a boot refusal** — and
    /// because a consumer can then refuse while ASSEMBLING the config, before
    /// any credential has been read. [`connect_options`] calls it too, so the
    /// refusal holds whether or not a caller remembers; a correctness property
    /// enforced by convention is one that holds until the first service forgets.
    ///
    /// Only `verify_ca` is refused. See [`connect_options`] for the measurement.
    pub fn check_ssl_mode(&self) -> Result<(), PoolError> {
        if matches!(self.ssl_mode, MySqlSslMode::VerifyCa) {
            return Err(PoolError::SslModeCannotVerify {
                mode: ssl_mode_name(self.ssl_mode),
            });
        }
        Ok(())
    }

    /// Refuse a configuration whose replicas would exhaust the engine.
    pub fn check_engine_headroom(&self) -> Result<(), PoolError> {
        if self.max_connections < MIN_CONNECTIONS {
            return Err(PoolError::InvalidSize {
                max_connections: self.max_connections,
                minimum: MIN_CONNECTIONS,
            });
        }

        let requested = self.max_connections.saturating_mul(self.replicas.max(1));
        let usable = self.engine_max_connections.saturating_sub(OPERATOR_RESERVE);

        if requested > usable {
            return Err(PoolError::WouldExhaustEngine {
                requested,
                available: self.engine_max_connections,
                reserved: OPERATOR_RESERVE,
            });
        }
        Ok(())
    }
}

/// Open the pool, refusing first.
///
/// The headroom check runs HERE rather than being something a caller is trusted
/// to remember. D4 makes the ceiling a correctness property of the topology, and
/// a correctness property enforced by convention is one that holds until the
/// first service forgets — at which point the symptom is intermittent "too many
/// connections" on whichever service connected last, not a configuration error
/// anyone can read.
///
/// The credential is applied here and never in [`PoolConfig::dsn`], because a
/// DSN reaches logs, spans and error messages.
/// The ONE description of a connection to the engine.
///
/// **Two code paths that must agree about TLS were the bug; one path is the
/// fix.** D7's capability probe runs on a connection of its own, before the pool
/// exists, and each `-db` binary used to build that connection by `format!`-ing
/// its own string with no `ssl-mode` in it. That inherited sqlx's default —
/// `Preferred`, which sqlx documents as "falling back to an unencrypted
/// connection if an encrypted connection cannot be established" — while the pool
/// beside it was on `Required`.
///
/// **What was missing is the GUARANTEE, and that is worth stating precisely,
/// because the obvious way to describe it is wrong twice over.**
///
/// It was not the password in cleartext. Under the default plugins the
/// credential never crosses as itself: `mysql_native_password` and
/// `caching_sha2_password` send a challenge-response scramble over the server's
/// nonce, and `sha256_password` — and `caching_sha2_password` when its fast path
/// misses — send the password RSA-encrypted under the server's public key
/// (`sqlx-mysql`'s `AuthPlugin::scramble`). What was unguaranteed is the whole
/// CONNECTION: handshake, queries and every row of every result.
///
/// Nor was it necessarily unencrypted. `Preferred` upgrades whenever the server
/// advertises the SSL capability, and RDS or Aurora with
/// `require_secure_transport=OFF` still OFFERS TLS — so the probe most likely
/// did negotiate it. It is genuinely plaintext only where no TLS is offered,
/// where a proxy terminates before the engine, or where the upgrade fails; and
/// under `Preferred` every one of those is a silent success rather than an
/// error. `Required` makes the same failure loud. The reference deployment hid
/// the whole thing either way: MariaDB behind the operator refuses plaintext, so
/// the probe negotiated TLS because the SERVER insisted, not because the client
/// asked.
///
/// **What neither mode gives is the engine's identity.** `Preferred` and
/// `Required` both set `accept_invalid_certs`, so an encrypted connection here
/// is encrypted to whoever answered. `VerifyCa` and `VerifyIdentity` are the
/// modes that check, which is why [`PoolConfig::ssl_mode`] is configuration
/// rather than a `bool`.
///
/// **AND A MODE THAT CHECKS STILL NEEDS SOMETHING TO CHECK AGAINST**, which is
/// why [`PoolConfig::ssl_ca`] is passed to sqlx below. Without it sqlx trusts
/// `webpki_roots::TLS_SERVER_ROOTS` — the public web roots, which sign no
/// operator-issued, RDS or Aurora engine certificate — so both verifying modes
/// failed closed against the estate's own engines. `VerifyCa` also routes
/// through sqlx's `NoHostnameTlsVerifier`, which swallows `NotValidForName`, so
/// it additionally accepted any publicly-trusted certificate for any name. With
/// a CA named, a private-CA engine becomes reachable at all.
///
/// **A CA IS NOT ENOUGH ON ITS OWN EITHER, and that is what this function now
/// refuses.** sqlx appends `ssl_ca` to a store already seeded with the public
/// web roots, so it widens trust rather than narrowing it, and `VerifyCa` routes
/// through `NoHostnameTlsVerifier`, which maps `NotValidForName` to a verified
/// assertion. `verify_ca` therefore accepts any publicly-trusted certificate for
/// any name whether or not a CA is configured. Only `verify_identity` binds the
/// connection to a NAME — and the name is what makes a private CA the only
/// usable signer, since no public authority may issue for a private,
/// cluster-internal name.
///
/// **The consequence the `deny.toml` exception rests on is unchanged.**
/// `sqlx-mysql`'s `encrypt_rsa` — the RUSTSEC-2023-0071 path — opens with
/// `if stream.is_tls { return Ok(to_asciz(password)) }`, so over TLS the RSA
/// exchange never happens. That holds for a connection that IS TLS, and fails
/// for one that fell back, which is the whole reason `DEFAULT_SSL_MODE` is
/// `required` rather than `preferred`.
///
/// So the probe takes these options too, and neither caller decides anything
/// about transport on its own.
///
/// **IT RETURNS A `Result` FOR THAT SAME REASON.** The refusal of `verify_ca`
/// below has to be unescapable, and the only place both callers meet is here. A
/// check that lived in [`connect`] alone would let the probe open its connection
/// first, under the very verifier being refused — which is the original defect
/// wearing a different hat.
pub fn connect_options(
    config: &PoolConfig,
    secret: &Secret,
) -> Result<MySqlConnectOptions, PoolError> {
    // **A MODE THAT CANNOT DO WHAT ITS NAME SAYS IS NOT OFFERED.** Read from the
    // vendored crates, not inferred: `sqlx-core 0.9.0`'s
    // `net/tls/tls_rustls.rs` seeds the trust store with `import_root_certs()`
    // BEFORE appending `ssl_ca`, and under the `webpki-roots` feature this crate
    // resolves to that is `webpki_roots::TLS_SERVER_ROOTS`. Naming a CA
    // therefore WIDENS the trust set and never restricts it. `sqlx-mysql`'s
    // `connection/tls.rs` then routes every mode but `VerifyIdentity` through
    // `NoHostnameTlsVerifier`, which maps `NotValidForName` to a verified
    // assertion. Under `verify_ca` any publicly-trusted certificate for any name
    // is accepted as the engine, with or without a CA file.
    config.check_ssl_mode()?;

    let options = MySqlConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .database(&config.database)
        .username(&config.username)
        .password(secret.expose())
        .ssl_mode(config.ssl_mode);

    // Applied only when there is one. sqlx reads no file when `ssl_ca` is unset
    // and falls back to its own trust store — see [`PoolConfig::ssl_ca`] for why
    // that fallback is a decision rather than a default.
    Ok(match &config.ssl_ca {
        Some(path) => options.ssl_ca(path),
        None => options,
    })
}

pub async fn connect(config: &PoolConfig, secret: &Secret) -> Result<MySqlPool, PoolError> {
    config.check_engine_headroom()?;

    let options = connect_options(config, secret)?;

    MySqlPoolOptions::new()
        .max_connections(config.max_connections)
        .connect_with(options)
        .await
        .map_err(|source| PoolError::Connect {
            // config.dsn() deliberately: it carries no credential.
            dsn: config.dsn(),
            source,
        })
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("could not connect to {dsn}: {source}")]
    Connect {
        dsn: String,
        #[source]
        source: sqlx::Error,
    },

    #[error(
        "pool would exhaust the engine: {requested} connections requested \
         (max_connections x replicas) against an engine allowing {available}, \
         of which {reserved} stay reserved so an operator can still connect. \
         Refusing at boot — the alternative surfaces as intermittent \
         'too many connections' under load, on whichever service connects last."
    )]
    WouldExhaustEngine {
        requested: u32,
        available: u32,
        reserved: u32,
    },

    #[error(
        "max_connections is {max_connections}; a pool needs at least {minimum}. \
         Zero cannot connect at all, and one deadlocks on its own migration: \
         `migrate::apply` holds the migration lock on one connection while the \
         migrations run on a second. Refusing at boot, because the alternative \
         is a 30-second hang ending in 'pool timed out while waiting for an open \
         connection' — which names the pool rather than the cause."
    )]
    InvalidSize { max_connections: u32, minimum: u32 },

    #[error(
        "{value:?} is not an ssl-mode. Accepted: disabled, preferred, required, \
         verify_ca, verify_identity. Refusing at boot rather than guessing — the \
         expression this replaces read a boolean and treated every spelling but \
         `true` as DISABLED, so a deployment that asked for TLS got an \
         unencrypted connection and no log line either way. Of the five: \
         `preferred` falls back to cleartext when the engine will not negotiate \
         TLS; `required` encrypts but checks no certificate; `verify_ca` names a \
         check it does not perform and is refused when a connection is built, \
         see SslModeCannotVerify; `verify_identity` checks the certificate \
         chain AND the hostname, and is the only mode that binds the connection \
         to the engine it names. A verifying mode checks against the CA named by \
         `ssl_ca` IN ADDITION TO the public web roots, never instead of them — \
         and those roots sign no operator-issued, RDS or Aurora engine \
         certificate."
    )]
    UnknownSslMode { value: String },

    #[error(
        "ssl-mode {mode} cannot verify the engine's identity, so it is refused at \
         boot rather than offered. Use verify_identity, which checks the same \
         certificate chain AND the hostname; it needs no other change. Measured in \
         sqlx 0.9: the trust store is seeded from the public web roots before the \
         configured ssl_ca is appended, so naming an authority widens it and never \
         restricts it, and every mode except verify_identity skips the hostname \
         check. Together those accept ANY publicly-trusted certificate for ANY \
         name as the engine — a stranger holding a certificate for their own \
         domain passes. A CA file does not close that, which is why this refuses \
         the mode instead of demanding one. If the engine's certificate does not \
         carry the name being dialled, the fix is that certificate; `required` \
         states the same real guarantee without naming a check nobody performs."
    )]
    SslModeCannotVerify { mode: &'static str },
}
