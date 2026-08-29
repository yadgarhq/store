//! What an engine can do, and what a module needs it to do.
//!
//! D7's consequence: "any database" means "any database with the required
//! capabilities". The driver probes, the module declares, and a gap is a boot
//! failure — never a silent degradation. A module that quietly loses vector
//! search returns worse answers instead of an error, and nothing surfaces it.

use std::collections::BTreeSet;

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
    Vector,
    /// Full-text search over a text column.
    FullText,
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
            Self::FullText => "fulltext",
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

#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error(
        "engine is missing required capabilities: {}. \
         This is a boot failure by design (D7): a module that silently loses a \
         capability degrades its answers instead of failing.",
        .0.iter().copied().map(Capability::as_str).collect::<Vec<_>>().join(", ")
    )]
    Missing(Vec<Capability>),
}
