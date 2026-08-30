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

/// Connections an engine keeps back for `SUPER`, so an operator can still get in
/// when the pools have taken everything.
///
/// A headroom check that ignores this passes right up to the moment nobody can
/// log in to diagnose why nothing else can.
const OPERATOR_RESERVE: u32 = 5;

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
        if self.max_connections == 0 {
            return Err(PoolError::InvalidSize { max_connections: 0 });
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

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
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

    #[error("max_connections is {max_connections}; a pool that cannot connect is not a pool")]
    InvalidSize { max_connections: u32 },
}
