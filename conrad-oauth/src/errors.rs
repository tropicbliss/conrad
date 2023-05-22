use std::error::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OAuthError {
    #[error("{0:?}")]
    RequestError(Box<dyn Error + Send>),
}
