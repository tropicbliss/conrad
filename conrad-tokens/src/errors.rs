use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("auth error: {0:?}")]
    AuthError(Box<dyn Error>),
    #[error("invalid user id")]
    InvalidUserId,
    #[error("duplicate token")]
    DuplicateToken,
    #[error("invalid token")]
    InvalidToken,
    #[error("expired token")]
    ExpiredToken,
}
