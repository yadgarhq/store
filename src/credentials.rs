//! How a `-db` service obtains its database credential — and the reason that is
//! this crate's job rather than the module's (D58).
//!
//! In-cluster, a credential is a mounted Secret. A managed engine has no
//! password at all and authenticates with a token derived from a workload
//! identity. Two mechanisms means what is tested is not what runs, unless the
//! seam that already owns pools, transactions and connection handling owns this
//! too. Module code sees neither.

use std::path::PathBuf;

/// A resolved credential.
///
/// Deliberately opaque: `Debug` renders a placeholder, because debug formatting
/// reaches logs, panic messages and tracing spans, and a credential that
/// formats itself is one that leaks eventually.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Read the credential. Named to be conspicuous at the call site — this is
    /// the one place the value escapes, so it should be greppable.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Where a credential comes from. Adding a variant is how a new deployment
/// target arrives; no module changes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CredentialSource {
    /// A file, typically a projected Kubernetes Secret. The in-cluster default
    /// under D58, where the database operator owns credential creation.
    SecretFile(PathBuf),
}

impl CredentialSource {
    pub fn resolve(&self) -> Result<Secret, CredentialError> {
        match self {
            Self::SecretFile(path) => {
                let raw = std::fs::read_to_string(path).map_err(|source| {
                    CredentialError::Unreadable {
                        path: path.clone(),
                        source,
                    }
                })?;

                // Kubernetes Secrets and text editors both add a trailing
                // newline. Left in place it produces a password that is wrong
                // by one byte and presents as an authentication failure, which
                // sends you looking one layer away from the cause.
                let value = raw.trim_end_matches(['\n', '\r']).to_owned();

                if value.is_empty() {
                    return Err(CredentialError::Empty { path: path.clone() });
                }
                Ok(Secret(value))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("could not read credential from {path}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Caught here rather than at the engine, where it presents as an
    /// authentication error one layer from the cause.
    #[error("credential file {path} is empty")]
    Empty { path: PathBuf },
}
