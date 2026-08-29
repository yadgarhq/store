//! D58: credential acquisition lives behind `store`, so no module knows how it
//! authenticates. In-cluster that is a mounted Secret; a managed engine has no
//! password at all and authenticates with a token from a workload identity.
//! Two mechanisms means what is tested is not what runs — unless the seam that
//! already owns pools and connections owns this too (D7).

use std::io::Write;
use yadgar_store::credentials::{CredentialError, CredentialSource};

#[test]
fn reads_a_password_from_a_mounted_secret_file() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "hunter2").unwrap();

    let source = CredentialSource::SecretFile(f.path().to_path_buf());
    assert_eq!(source.resolve().unwrap().expose(), "hunter2");
}

#[test]
fn trailing_newline_is_stripped_because_kubernetes_secrets_and_editors_add_one() {
    // The failure this prevents is a password that is silently wrong by one
    // byte, which presents as an authentication error and sends you looking at
    // the wrong thing entirely.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "hunter2").unwrap();

    let source = CredentialSource::SecretFile(f.path().to_path_buf());
    assert_eq!(source.resolve().unwrap().expose(), "hunter2");
}

#[test]
fn a_missing_secret_file_is_an_error_that_names_the_path() {
    let source = CredentialSource::SecretFile("/nonexistent/db-password".into());
    let err = source.resolve().unwrap_err();
    assert!(matches!(err, CredentialError::Unreadable { .. }));
    assert!(err.to_string().contains("/nonexistent/db-password"));
}

#[test]
fn an_empty_secret_file_is_rejected_rather_than_returned_as_an_empty_password() {
    // An empty password reaches the engine and fails there, one layer further
    // from the cause. Catch it where the cause is visible.
    let f = tempfile::NamedTempFile::new().unwrap();
    let source = CredentialSource::SecretFile(f.path().to_path_buf());
    assert!(matches!(
        source.resolve(),
        Err(CredentialError::Empty { .. })
    ));
}

#[test]
fn a_secret_never_appears_in_debug_output() {
    // Debug formatting reaches logs, panics and tracing spans. A credential
    // that formats itself is a credential that leaks eventually.
    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(f, "hunter2").unwrap();

    let secret = CredentialSource::SecretFile(f.path().to_path_buf())
        .resolve()
        .unwrap();
    let rendered = format!("{secret:?}");
    assert!(
        !rendered.contains("hunter2"),
        "secret leaked into Debug: {rendered}"
    );
}
