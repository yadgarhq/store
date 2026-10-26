//! The database ACCOUNT's connection cap, checked at boot (yaadgaar #200,
//! ADR-1006).
//!
//! [`PoolConfig::check_engine_headroom`] compares the pool arithmetic with the
//! engine's `max_connections`. MariaDB also caps each account: the user's
//! `MAX_USER_CONNECTIONS`, or the global `max_user_connections` when the
//! account sets none. The two are independent, and the second is the one the
//! estate hit: mariadb-operator writes 20 for every app user, while each `-db`
//! ran 8 connections x 6 KEDA replicas. The engine check passed (48 < 146) and
//! the 21st connection would have failed with error 1226 under load.
//!
//! **READ FROM THE ENGINE, NOT FROM CONFIGURATION.** The session value of
//! `@@max_user_connections` is the limit that applies to THIS account — measured
//! on MariaDB 11.8.9: an account created `WITH MAX_USER_CONNECTIONS 20` reads
//! 20 while the global is 0 or 7, and an account with no limit reads the
//! global. A chart value for the same number could only drift from the account
//! it describes; the engine cannot.

use sqlx::mysql::MySqlConnectOptions;
use sqlx::{ConnectOptions, Connection};

use super::{PoolConfig, PoolError};

impl PoolConfig {
    /// Refuse a pool whose replicas together would exceed the account's
    /// connection cap.
    ///
    /// `cap` is `@@max_user_connections` as the engine reports it for this
    /// session. Zero means no per-user limit. A negative value (MariaDB's -1,
    /// "only SUPER may connect") cannot reach here as a limit on this account:
    /// a session that connected under it holds the privilege that exempts it.
    /// So only a positive cap is checked.
    ///
    /// The product is the same `max_connections x replicas.max(1)` as the
    /// engine check, and `replicas` is already the KEDA ceiling (`REPLICAS`
    /// renders `autoscaling.maxReplicas` when autoscaling is on), so the check
    /// is against the most replicas that can run, not the ones running now.
    pub fn check_user_connection_cap(&self, cap: i64) -> Result<(), PoolError> {
        if cap <= 0 {
            return Ok(());
        }
        let requested = self.max_connections.saturating_mul(self.replicas.max(1));
        if i64::from(requested) > cap {
            return Err(PoolError::WouldExceedUserCap {
                requested,
                cap,
                username: self.username.clone(),
            });
        }
        Ok(())
    }
}

/// The cap the engine applies to the account `options` connects as, read on
/// ONE connection of its own that is closed before this returns — before any
/// pool exists, so a refused boot never opens a pool against that same cap.
///
/// CAST because MariaDB types the variable as an unsigned integer, and decoding
/// it straight into `i64` is the kind of mismatch that only shows at runtime.
pub(super) async fn read(
    config: &PoolConfig,
    options: &MySqlConnectOptions,
) -> Result<i64, PoolError> {
    // config.dsn() deliberately: it carries no credential.
    let mut conn = options
        .connect()
        .await
        .map_err(|source| PoolError::Connect {
            dsn: config.dsn(),
            source,
        })?;
    let cap = sqlx::query_scalar("SELECT CAST(@@max_user_connections AS SIGNED)")
        .fetch_one(&mut conn)
        .await
        .map_err(|source| PoolError::UserCapUnreadable {
            dsn: config.dsn(),
            source,
        });
    // Closed on both paths; a failed close leaves nothing a caller can act on.
    let _ = conn.close().await;
    cap
}
