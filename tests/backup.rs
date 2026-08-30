//! D6 makes backup discipline contract-enforced so no module can ship without
//! one. The incident behind that rule is specific: on 2026-06-16 a faulty
//! restore-verification check destroyed 3,622 memories. **A backup nobody has
//! restored is a hypothesis**, so the contract is backup *and* verified restore,
//! never backup alone.

use yadgar_store::backup::{BackupError, RestoreReport, VerifyOutcome};

#[test]
fn a_restore_that_returns_fewer_rows_than_it_backed_up_fails() {
    // The 2026-06-16 shape. The restore "succeeded" and the check passed while
    // rows were missing.
    let report = RestoreReport {
        rows_backed_up: 3622,
        rows_restored: 0,
        tables: 12,
    };
    assert!(matches!(
        report.verify(),
        VerifyOutcome::Failed(BackupError::RowCountMismatch {
            expected: 3622,
            found: 0
        })
    ));
}

#[test]
fn the_failure_message_names_both_counts() {
    let report = RestoreReport {
        rows_backed_up: 3622,
        rows_restored: 3600,
        tables: 12,
    };
    let VerifyOutcome::Failed(err) = report.verify() else {
        panic!("expected failure")
    };
    let msg = err.to_string();
    assert!(msg.contains("3622") && msg.contains("3600"), "got: {msg}");
}

#[test]
fn an_exact_match_passes() {
    let report = RestoreReport {
        rows_backed_up: 3622,
        rows_restored: 3622,
        tables: 12,
    };
    assert!(matches!(report.verify(), VerifyOutcome::Verified));
}

#[test]
fn restoring_more_rows_than_were_backed_up_also_fails() {
    // Not pedantry: it means the restore landed on a database that was not
    // empty, so the result is a mix of two states and nobody knows which rows
    // came from where.
    let report = RestoreReport {
        rows_backed_up: 100,
        rows_restored: 120,
        tables: 3,
    };
    assert!(matches!(
        report.verify(),
        VerifyOutcome::Failed(BackupError::RowCountMismatch { .. })
    ));
}

#[test]
fn a_backup_of_an_empty_database_is_valid_but_reported_as_such() {
    // Zero equals zero, so a naive row-count check passes and says nothing. A
    // new module legitimately has no rows — but so does one whose backup silently
    // captured nothing, and those must not look alike.
    let report = RestoreReport {
        rows_backed_up: 0,
        rows_restored: 0,
        tables: 0,
    };
    assert!(matches!(report.verify(), VerifyOutcome::VerifiedEmpty));
}

#[test]
fn zero_tables_with_rows_is_incoherent_and_rejected() {
    let report = RestoreReport {
        rows_backed_up: 5,
        rows_restored: 5,
        tables: 0,
    };
    assert!(matches!(
        report.verify(),
        VerifyOutcome::Failed(BackupError::Incoherent { .. })
    ));
}
