//! Every refusal the pool makes, in one place.
//!
//! Split from `pool.rs` along the seam between what the pool does and what it
//! says when it will not: each message here carries its own argument, and
//! together they outgrew the file that raises them.

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
        "{field} is {value}, and zero is not a pool setting. Set the chart key \
         {chart_key} to an integer of at least 1. Refusing at boot: a zero \
         acquire timeout fails every acquire that waits, a zero idle timeout or \
         lifetime churns connections, and a zero operator reserve leaves a \
         non-admin operator no way into a full engine."
    )]
    InvalidPoolSetting {
        field: &'static str,
        chart_key: &'static str,
        value: String,
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
