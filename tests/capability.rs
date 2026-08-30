//! D7: "any database" means "any database with the required capabilities". A
//! module declares what it needs, the driver probes, and the module FAILS AT
//! BOOT when something is missing. Never degrade silently — a module that
//! quietly loses vector search returns worse answers rather than an error, and
//! nothing surfaces it.

use yadgar_store::capability::{Capability, CapabilityError, CapabilitySet};

#[test]
fn satisfied_when_engine_has_everything_required() {
    let engine = CapabilitySet::from([Capability::Transactions, Capability::FullTextBm25]);
    let required = CapabilitySet::from([Capability::Transactions]);
    assert!(engine.satisfies(&required).is_ok());
}

#[test]
fn missing_capability_is_an_error_naming_every_gap_not_just_the_first() {
    // Reporting one gap at a time turns a boot failure into a guessing game:
    // fix one, redeploy, discover the next. Name them all at once.
    let engine = CapabilitySet::from([Capability::Transactions]);
    let required = CapabilitySet::from([
        Capability::Transactions,
        Capability::Vector,
        Capability::FullTextBm25,
    ]);

    let err = engine.satisfies(&required).unwrap_err();
    // Set-based satisfies has no provenance to report; CapabilityReport's
    // variant carries it (D69). Two variants because they know different things.
    let CapabilityError::Missing(missing) = err else {
        panic!("set-based satisfies reports the plain variant, got {err:?}");
    };

    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&Capability::Vector));
    assert!(missing.contains(&Capability::FullTextBm25));
}

#[test]
fn error_message_names_the_missing_capabilities() {
    let engine = CapabilitySet::from([]);
    let required = CapabilitySet::from([Capability::Vector]);
    let msg = engine.satisfies(&required).unwrap_err().to_string();
    assert!(
        msg.contains("vector"),
        "message should name the gap, got: {msg}"
    );
}

#[test]
fn an_engine_may_exceed_what_is_required() {
    let engine = CapabilitySet::from([Capability::Transactions, Capability::Vector]);
    let required = CapabilitySet::from([Capability::Transactions]);
    assert!(engine.satisfies(&required).is_ok());
}
