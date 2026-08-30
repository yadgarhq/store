//! `yadgar-store` — engine primitives for every `-db` service.
//!
//! **This crate knows zero entity schemas, and that is the whole point (D7).**
//! Abstraction sits at the capability level, never the SQL level. Abstracting
//! at the SQL level forces lowest-common-denominator SQL and forfeits exactly
//! what retrieval needs — vector search, JSON columns, full-text. And a driver
//! crate holding every module's adapters becomes the new coupling point: every
//! schema change touches it, every module waits on its release. That is the
//! monolith one layer down.
//!
//! So: this crate provides pools, transactions, migration running, capability
//! probing, credential acquisition and a backup harness. The adapters that
//! encode a module's schema ship inside that module's own repository.

#![forbid(unsafe_code)]

pub mod backup;
pub mod capability;
pub mod credentials;
pub mod migrate;
pub mod pool;
pub mod probe;
