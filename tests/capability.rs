//! D7: "any database" means "any database with the required capabilities". A
//! module declares what it needs, the driver probes, and the module FAILS AT
//! BOOT when something is missing. Never degrade silently — a module that
//! quietly loses vector search returns worse answers rather than an error, and
//! nothing surfaces it.

use yadgar_store::capability::{Capability, CapabilityError, CapabilitySet, Determination};

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

/// A CAPABILITY MUST BE MARKABLE ABSENT BY A LATER PASS.
///
/// `probe::run` documents a two-pass flow — function probes before migrations,
/// index-dependent probes after — and both passes write into one report. If the
/// first pass records a capability present and the second finds it absent, the
/// report that reaches `satisfies` must say ABSENT. Anything else boots a module
/// against an engine that cannot serve it, which is precisely the silent
/// degradation D7 refuses.
#[test]
fn a_later_pass_may_mark_a_capability_absent() {
    let mut report = yadgar_store::capability::CapabilityReport::default();
    report.record(Capability::Vector, true, Determination::Probed);
    report.record(
        Capability::Vector,
        false,
        Determination::Asserted {
            observed_version: "11.8.8-MariaDB".into(),
            conclusion: "the index the second pass needs was never created".into(),
            source: "second pass".into(),
        },
    );

    assert!(
        !report.offers(Capability::Vector),
        "the later determination must win, or a gap boots as a pass"
    );
    assert!(
        !report.offered().contains(Capability::Vector),
        "the offered set must agree with offers()"
    );
    assert!(
        report.absent().contains(Capability::Vector),
        "and the absent set must carry it, or the gap has no provenance to print"
    );
    assert!(
        matches!(
            report.determination(Capability::Vector),
            Some(Determination::Asserted { .. })
        ),
        "determination must report the SECOND record, not a stale one: {:?}",
        report.determination(Capability::Vector)
    );
    report
        .satisfies(&CapabilitySet::from([Capability::Vector]))
        .expect_err("a module requiring an absent capability must fail to boot");
}

/// The same in the other order. A capability found absent by the first pass and
/// present by the second — an index-dependent probe that only becomes
/// answerable after migrations — must end up present, and once.
#[test]
fn a_later_pass_may_mark_a_capability_present() {
    let mut report = yadgar_store::capability::CapabilityReport::default();
    report.record(Capability::Vector, false, Determination::Probed);
    report.record(
        Capability::Vector,
        true,
        Determination::Asserted {
            observed_version: "11.8.8-MariaDB".into(),
            conclusion: "the index exists once migrations have run".into(),
            source: "second pass".into(),
        },
    );

    assert!(report.offers(Capability::Vector), "the later pass wins");
    assert!(report.offered().contains(Capability::Vector));
    // THE ASSERTION THAT WATCHES THE OTHER MAP, and the reason `absent()`
    // exists. `record`'s present branch removes the capability from `absent`,
    // and until this line nothing observed that: `offers` never reads `absent`,
    // and `determination` reads `offered` first and finds the fresh entry there.
    // Deleting `self.absent.remove(&cap)` left the whole suite green while the
    // report held both a "present" and a superseded "absent" determination for
    // one capability — so the provenance printed for a gap could be a belief the
    // second pass had already overturned.
    assert!(
        !report.absent().contains(Capability::Vector),
        "the superseded absent entry must be removed, not merely shadowed"
    );
    assert!(
        matches!(
            report.determination(Capability::Vector),
            Some(Determination::Asserted { .. })
        ),
        "determination must report the SECOND record: {:?}",
        report.determination(Capability::Vector)
    );
    report
        .satisfies(&CapabilitySet::from([Capability::Vector]))
        .expect("the capability is present, so the module boots");
}
