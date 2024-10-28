use ed25519_dalek::SignatureError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BwError {
    #[error("token is expired")]
    Expired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid token format")]
    InvalidTokenFormat,
    #[error("failed to generate a salt")]
    FailedSaltGeneration,
    #[error("incorrect timestamp")]
    IncorrectTimestamp,
    #[error("invalid salt length: expected {expected} bytes but got {actual} bytes")]
    InvalidSaltLength { expected: usize, actual: usize },
    #[error(transparent)]
    InvalidDigest(#[from] SignatureError)
}
