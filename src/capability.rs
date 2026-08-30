//! What an engine can do, and what a module needs it to do.
//!
//! D7's consequence: "any database" means "any database with the required
//! capabilities". The module declares, [`crate::probe`] establishes, and a gap
//! is a boot failure — never a silent degradation. A module that quietly loses
//! vector search returns worse answers instead of an error, and nothing
//! surfaces it.
//!
//! "Establishes" rather than "probes", because D69 splits the two and the
//! difference is load-bearing. A capability is either PROBED — an expression the
//! engine evaluates or rejects — or ASSERTED from engine identity where no query
//! can reveal it. Full-text scoring is the second kind: MariaDB publishes no
//! algorithm and no runtime flag exposes one, so the only honest answer carries
//! the version it was concluded from and a citation. Letting an assertion pass
//! as a measurement is the failure this split exists to prevent.

use std::collections::{BTreeMap, BTreeSet};

/// A capability a module may require of its engine.
///
/// Deliberately coarse and domain-shaped rather than a feature matrix. The
/// question is "can this module run here", not "which SQL dialect is this".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// Multi-statement transactions with rollback. Required by every module:
    /// D5 makes one `-db` call one business operation and one transaction.
    Transactions,
    /// Vector similarity search. Required by the ranked modules only — memory,
    /// wiki, graph. The addressed modules must not require it (D10).
    ///
    /// Deliberately COARSE, and that is a decision rather than an oversight
    /// (D69): it separates neither exact from approximate search nor one
    /// distance metric from another, because no module's contract currently
    /// turns on either. It splits the day one does — which is what makes
    /// `#[non_exhaustive]` load-bearing here, since a split is a compile error
    /// at every call site, and that is the correct blast radius.
    Vector,
    /// Full-text search scored with **BM25**, which is what `recall/v1`
    /// declares.
    ///
    /// Named at the granularity the MODULE requires rather than the one the
    /// engine advertises (D69), and MariaDB is why. InnoDB has full-text search,
    /// so a boolean `FullText` would pass — while it scores with a TF-IDF
    /// variant, and the module would return worse answers having satisfied its
    /// own check. A boolean model cannot express "present but wrong"; naming it
    /// precisely can.
    FullTextBm25,
    /// Server-side JSON storage and querying.
    Json,
    /// `SELECT ... FOR UPDATE` or equivalent. Not needed for D8's optimistic
    /// compare-and-set, but a module doing queue-like work may want it.
    RowLocking,
}

impl Capability {
    /// The name used in error messages. Lowercase and stable — it is what an
    /// operator greps for.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transactions => "transactions",
            Self::Vector => "vector",
            Self::FullTextBm25 => "fulltext-bm25",
            Self::Json => "json",
            Self::RowLocking => "row-locking",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of capabilities — either what an engine offers or what a module needs.
///
/// Ordered, so a missing-capability error lists gaps deterministically. An
/// error message that changes order between runs is one nobody can diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl<const N: usize> From<[Capability; N]> for CapabilitySet {
    fn from(caps: [Capability; N]) -> Self {
        Self(caps.into_iter().collect())
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl CapabilitySet {
    pub fn contains(&self, cap: Capability) -> bool {
        self.0.contains(&cap)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.0.iter().copied()
    }

    /// Check this engine's capabilities against what a module requires.
    ///
    /// Reports **every** gap, not the first. One at a time turns a boot failure
    /// into a guessing game: fix one, redeploy, discover the next.
    pub fn satisfies(&self, required: &CapabilitySet) -> Result<(), CapabilityError> {
        let missing: Vec<Capability> = required.iter().filter(|cap| !self.contains(*cap)).collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(CapabilityError::Missing(missing))
        }
    }
}

/// HOW a capability was established (D69).
///
/// Recorded per capability, and never collapsed to a bare boolean, because an
/// operator reading a boot failure must be able to tell a measurement from a
/// belief. The two carry different weight and age differently: a probe is true
/// of the engine in front of you, an assertion is true of what was documented
/// about a version on the day someone wrote it down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Determination {
    /// An expression the engine evaluated or rejected. Authoritative.
    Probed,

    /// Concluded from engine identity, because no query reveals it.
    ///
    /// A deliberate, bounded re-entry of the version table D69's first rule
    /// otherwise rejects — permitted ONLY where no probe exists, and required to
    /// carry its own provenance so the boundary stays visible. The citation is
    /// DATA rather than a comment: when the upstream ticket ships, the table
    /// changes in one place and the assertion flips, instead of the fix
    /// depending on someone grepping for a comment.
    Asserted {
        /// The version string actually observed, e.g. "11.8.8-MariaDB-ubu2404".
        observed_version: String,
        /// What was concluded, in one line.
        conclusion: String,
        /// Where the conclusion comes from — a ticket, a spec, a release note.
        source: String,
    },
}

impl std::fmt::Display for Determination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Probed => f.write_str("probed"),
            Self::Asserted {
                observed_version,
                source,
                ..
            } => write!(f, "asserted from {observed_version}, {source}"),
        }
    }
}

/// What one engine offers, and how each answer was reached.
///
/// `satisfies` stays set-based so the arithmetic is unchanged; the report adds
/// provenance to the ERROR, which is the text an operator reads at boot.
/// "missing fulltext-bm25 (asserted from 11.8.8-MariaDB, MDEV-36568)" is worth
/// strictly more than "missing fulltext-bm25", and costs one line to carry.
#[derive(Debug, Clone, Default)]
pub struct CapabilityReport {
    offered: BTreeMap<Capability, Determination>,
    absent: BTreeMap<Capability, Determination>,
}

impl CapabilityReport {
    pub fn record(&mut self, cap: Capability, present: bool, how: Determination) {
        if present {
            self.offered.insert(cap, how);
        } else {
            self.absent.insert(cap, how);
        }
    }

    pub fn offers(&self, cap: Capability) -> bool {
        self.offered.contains_key(&cap)
    }

    /// How this capability was established, present or not.
    pub fn determination(&self, cap: Capability) -> Option<&Determination> {
        self.offered.get(&cap).or_else(|| self.absent.get(&cap))
    }

    pub fn offered(&self) -> CapabilitySet {
        self.offered.keys().copied().collect()
    }

    /// Check against what a module requires, reporting **every** gap with the
    /// provenance of each.
    pub fn satisfies(&self, required: &CapabilitySet) -> Result<(), CapabilityError> {
        let missing: Vec<(Capability, Option<Determination>)> = required
            .iter()
            .filter(|cap| !self.offers(*cap))
            .map(|cap| (cap, self.determination(cap).cloned()))
            .collect();

        if missing.is_empty() {
            Ok(())
        } else {
            Err(CapabilityError::MissingWithProvenance(missing))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error(
        "engine is missing required capabilities: {}. \
         This is a boot failure by design (D7): a module that silently loses a \
         capability degrades its answers instead of failing.",
        .0.iter().copied().map(Capability::as_str).collect::<Vec<_>>().join(", ")
    )]
    Missing(Vec<Capability>),

    #[error(
        "engine is missing required capabilities: {}. \
         This is a boot failure by design (D7): a module that silently loses a \
         capability degrades its answers instead of failing. Each gap names how \
         it was established (D69) — an asserted gap is a documented belief about \
         a version, not something this engine was asked.",
        .0.iter()
            .map(|(cap, how)| match how {
                Some(d) => format!("{cap} ({d})"),
                None => format!("{cap} (not established)"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    )]
    MissingWithProvenance(Vec<(Capability, Option<Determination>)>),
}
