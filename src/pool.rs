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

use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlSslMode};
use sqlx::MySqlPool;

use crate::credentials::Secret;

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

    /// D58 puts every `-db` on TLS to its engine. The RUSTSEC-2023-0071
    /// exception recorded in `deny.toml` depends on this staying true.
    pub require_tls: bool,
}

impl PoolConfig {
    /// Connection string **without** the credential.
    ///
    /// The credential is applied separately at connect time, because a DSN
    /// reaches logs, tracing spans and error messages, and one carrying a
    /// password is one that leaks eventually — the same reasoning that makes
    /// `Secret` redact itself in `Debug`.
    pub fn dsn(&self) -> String {
        let mode = if self.require_tls {
            "REQUIRED"
        } else {
            "DISABLED"
        };
        format!(
            "mysql://{user}@{host}:{port}/{db}?ssl-mode={mode}",
            user = self.username,
            host = self.host,
            port = self.port,
            db = self.database,
            mode = mode,
        )
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
pub async fn connect(config: &PoolConfig, secret: &Secret) -> Result<MySqlPool, PoolError> {
    config.check_engine_headroom()?;

    let options = MySqlConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .database(&config.database)
        .username(&config.username)
        .password(secret.expose())
        .ssl_mode(if config.require_tls {
            MySqlSslMode::Required
        } else {
            MySqlSslMode::Disabled
        });

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
}
