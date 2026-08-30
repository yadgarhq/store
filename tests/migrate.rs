//! Migrations: `store` runs them, modules own them.
//!
//! D7 keeps this crate free of entity schemas, so it cannot hold anyone's
//! migrations — it can only apply what a module hands it, in order, exactly
//! once. That constraint is what these tests are about.

use yadgar_store::migrate::{Migration, MigrationError, MigrationSet};

fn m(version: u64, name: &str, sql: &str) -> Migration {
    Migration {
        version,
        name: name.into(),
        sql: sql.into(),
    }
}

#[test]
fn migrations_are_ordered_by_version_not_by_declaration() {
    // A module builds this list by reading a directory, and directory order is
    // not sorted order on every filesystem. Ordering here rather than trusting
    // the caller is the difference between deterministic schema and a schema
    // that depends on which machine ran it.
    let set = MigrationSet::new(vec![
        m(3, "third", "SELECT 3"),
        m(1, "first", "SELECT 1"),
        m(2, "second", "SELECT 2"),
    ])
    .unwrap();

    assert_eq!(set.versions(), vec![1, 2, 3]);
}

#[test]
fn a_duplicate_version_is_rejected_before_anything_runs() {
    // Two migrations claiming version 2 means one of them silently never
    // applies, and which one depends on ordering. Fail at construction, where
    // the mistake is visible, rather than at apply time on one deployment.
    let err = MigrationSet::new(vec![
        m(1, "first", "SELECT 1"),
        m(2, "second", "SELECT 2"),
        m(2, "also-second", "SELECT 2"),
    ])
    .unwrap_err();

    assert!(matches!(
        err,
        MigrationError::DuplicateVersion { version: 2, .. }
    ));
    assert!(
        err.to_string().contains("also-second"),
        "error must name the collision: {err}"
    );
}

#[test]
fn version_zero_is_rejected_because_it_is_the_empty_database() {
    // The applied-version marker starts at 0 meaning "nothing applied". A
    // migration numbered 0 is indistinguishable from that.
    let err = MigrationSet::new(vec![m(0, "zeroth", "SELECT 0")]).unwrap_err();
    assert!(matches!(err, MigrationError::ZeroVersion { .. }));
}

#[test]
fn an_empty_set_is_valid_because_a_new_module_has_no_migrations_yet() {
    let set = MigrationSet::new(vec![]).unwrap();
    assert!(set.versions().is_empty());
    assert_eq!(set.pending_after(0).count(), 0);
}

#[test]
fn pending_after_returns_only_what_has_not_been_applied() {
    let set = MigrationSet::new(vec![
        m(1, "first", "SELECT 1"),
        m(2, "second", "SELECT 2"),
        m(3, "third", "SELECT 3"),
    ])
    .unwrap();

    assert_eq!(set.pending_after(0).count(), 3);
    assert_eq!(
        set.pending_after(2).map(|x| x.version).collect::<Vec<_>>(),
        vec![3]
    );
    assert_eq!(set.pending_after(3).count(), 0);
}

#[test]
fn a_database_ahead_of_the_binary_is_an_error_not_a_no_op() {
    // The deployment that matters: a rollback leaves the database at version 5
    // while the older binary knows 4. Treating that as "nothing pending" runs
    // old code against a newer schema, silently, which is how data gets
    // corrupted rather than how an outage happens.
    let set = MigrationSet::new(vec![m(1, "first", "SELECT 1")]).unwrap();
    let err = set.check_not_ahead(5).unwrap_err();
    assert!(matches!(
        err,
        MigrationError::DatabaseAhead {
            applied: 5,
            known: 1
        }
    ));
}

#[test]
fn a_database_level_with_the_binary_is_fine() {
    let set = MigrationSet::new(vec![m(1, "a", "SELECT 1"), m(2, "b", "SELECT 2")]).unwrap();
    assert!(set.check_not_ahead(2).is_ok());
    assert!(set.check_not_ahead(0).is_ok());
}
