use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("database error: {0}")]
    DatabaseError(String),

    #[error("invalid user id")]
    InvalidUserId,

    #[error("duplicate session id")]
    DuplicateSessionId,

    #[error("invalid session id")]
    InvalidSessionId,

    #[error("invalid key id")]
    InvalidKeyId,

    #[error("invalid password")]
    InvalidPassword,

    #[error("outdated password")]
    OutdatedPassword,
}
