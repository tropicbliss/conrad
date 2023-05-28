use crate::{errors::AuthError, User, UserId};
use async_trait::async_trait;
use std::error::Error;

#[async_trait]
pub trait DatabaseAdapter<U> {
    async fn create_user_and_key(
        &self,
        user_attributes: &U,
        key: &KeySchema,
    ) -> Result<(), CreateUserError>;
    async fn read_user(&self, user_id: &UserId) -> Result<User<U>, UserError>;
    async fn create_session(&self, session_data: &SessionSchema) -> Result<(), CreateSessionError>;
    async fn read_sessions(&self, user_id: &UserId) -> Result<Vec<SessionSchema>, GeneralError>;
    async fn delete_session(&self, session_id: &str) -> Result<(), GeneralError>;
    async fn read_session(&self, session_id: &str) -> Result<SessionSchema, SessionError>;
    async fn read_key(&self, key_id: &str) -> Result<KeySchema, KeyError>;
    async fn update_user(&self, user_id: &UserId, user_attributes: &U) -> Result<(), UserError>;
    async fn delete_sessions_by_user_id(&self, user_id: &UserId) -> Result<(), GeneralError>;
    async fn delete_keys(&self, user_id: &UserId) -> Result<(), GeneralError>;
    async fn delete_user(&self, user_id: &UserId) -> Result<(), GeneralError>;
    async fn create_key(&self, key: &KeySchema) -> Result<(), CreateKeyError>;
    async fn delete_non_primary_key(&self, key_id: &str) -> Result<(), GeneralError>;
    async fn read_keys_by_user_id(&self, user_id: &UserId) -> Result<Vec<KeySchema>, GeneralError>;
    async fn update_key_password(
        &self,
        key_id: &str,
        hashed_password: Option<&str>,
    ) -> Result<(), KeyError>;
    async fn read_session_and_user_by_session_id(
        &self,
        session_id: &str,
    ) -> Result<DatabaseUserSession<U>, SessionError>;
}

#[derive(Clone, Debug)]
pub struct KeySchema {
    pub id: String,
    pub hashed_password: Option<String>,
    pub user_id: UserId,
    pub primary_key: bool,
    pub expires: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct SessionData {
    pub session_id: String,
    pub active_period_expires_at: i64,
    pub idle_period_expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct SessionSchema {
    pub session_data: SessionData,
    pub user_id: UserId,
}

#[derive(Debug)]
pub enum CreateUserError {
    UserAlreadyExists,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum UserError {
    UserDoesNotExist,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug, Clone)]
pub struct DatabaseUserSession<U> {
    pub user: User<U>,
    pub session: SessionSchema,
}

#[derive(Debug)]
pub enum SessionError {
    SessionNotFound,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum CreateSessionError {
    InvalidUserId,
    DuplicateSessionId,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum GeneralError {
    DatabaseError(Box<dyn Error>),
}

impl From<GeneralError> for AuthError {
    fn from(value: GeneralError) -> Self {
        match value {
            GeneralError::DatabaseError(err) => AuthError::DatabaseError(err),
        }
    }
}

#[derive(Debug)]
pub enum CreateKeyError {
    DatabaseError(Box<dyn Error>),
    UserDoesNotExist,
    KeyAlreadyExists,
}

#[derive(Debug)]
pub enum KeyError {
    DatabaseError(Box<dyn Error>),
    KeyDoesNotExist,
}
