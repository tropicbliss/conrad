use conrad_core::errors::AuthError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("{0:?}")]
    AuthError(#[from] AuthError),
    #[error("invalid user id")]
    InvalidUserId,
    #[error("duplicate token")]
    DuplicateToken,
    #[error("invalid token")]
    InvalidToken,
    #[error("expired token")]
    ExpiredToken,
}
