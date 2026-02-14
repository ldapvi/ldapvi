use std::io;

#[derive(Debug, thiserror::Error)]
pub enum LdapviError {
    #[error("{0}")]
    User(String),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("parse error at byte {position}: {message}")]
    Parse { position: u64, message: String },

    #[error("LDAP error: {0}")]
    Ldap(String),

    #[error("base64 decode error")]
    Base64Decode,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, LdapviError>;

/// Fatal user-facing error (equivalent of C yourfault()).
pub fn yourfault(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}
