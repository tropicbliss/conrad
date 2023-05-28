use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("error running migrations")]
    MigrationError,
    #[error("error connecting to {0}")]
    ConnectionError(String),
}
