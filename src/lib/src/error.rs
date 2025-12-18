use std::io;

#[derive(Debug, thiserror::Error)]
pub enum WSRError {
    #[error("Internal error: [{0}]")]
    InternalError(String),
    #[error("Configuration error: [{0}]")]
    ConfigError(String),
    #[error("Verification error for signer set [{0}]")]
    VerificationError(String),
    #[error("Rejected signatures have been found")]
    RejectedSignaturesError,
    #[error("I/O error: [{0}]")]
    IOError(#[from] io::Error),
    #[error("YAML error: [{0}]")]
    YAMLError(#[from] serde_yml::Error),
    #[error("WASMSign error: [{0}]")]
    WSError(#[from] wasmsign2::WSError),
}
