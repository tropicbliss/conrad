use crate::{User, UserId};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::error::Error;

#[async_trait]
pub trait DatabaseAdapter<U>
where
    U: Serialize + DeserializeOwned,
{
    async fn create_user_and_key(&self, user_attributes: &U, key: &KeySchema) -> CreateUserStatus;
    async fn read_user(&self, user_id: &UserId) -> ReadUserStatus<U>;
    async fn create_session(&self, session_data: &SessionSchema) -> CreateSessionStatus;
    async fn read_sessions(&self, user_id: &UserId) -> ReadSessionsStatus;
    async fn delete_session(&self, session_id: &str) -> GeneralStatus<()>;
    async fn read_session(&self, session_id: &str) -> ReadSessionStatus;
    async fn read_key(&self, key_id: &str) -> ReadKeyStatus;
    async fn update_user(&self, user_id: &UserId, user_attributes: &U) -> UpdateUserStatus;
    async fn delete_sessions_by_user_id(&self, user_id: &UserId) -> GeneralStatus<()>;
    async fn delete_keys(&self, user_id: &UserId) -> GeneralStatus<()>;
    async fn delete_user(&self, user_id: &UserId) -> GeneralStatus<()>;
    async fn create_key(&self, key: &KeySchema) -> CreateKeyStatus;
    async fn delete_non_primary_key(&self, key_id: &str) -> GeneralStatus<()>;
    async fn read_keys_by_user_id(&self, user_id: &UserId) -> GeneralStatus<Vec<KeySchema>>;
    async fn update_key_password(
        &self,
        key_id: &str,
        hashed_password: Option<&str>,
    ) -> UpdateKeyStatus;
    async fn read_session_and_user_by_session_id(
        &self,
        session_id: &str,
    ) -> ReadSessionAndUserStatus<U>;
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
pub enum CreateUserStatus {
    Ok,
    UserAlreadyExists,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum ReadUserStatus<U> {
    Ok(User<U>),
    UserDoesNotExist,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub struct DatabaseUserSession<U> {
    pub user: User<U>,
    pub session: SessionSchema,
}

#[derive(Debug)]
pub enum ReadSessionAndUserStatus<U> {
    Ok(DatabaseUserSession<U>),
    SessionNotFound,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum CreateSessionStatus {
    Ok,
    InvalidUserId,
    DuplicateSessionId,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum ReadSessionsStatus {
    Ok(Vec<SessionSchema>),
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum GeneralStatus<T> {
    Ok(T),
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum ReadSessionStatus {
    Ok(SessionSchema),
    DatabaseError(Box<dyn Error>),
    SessionNotFound,
}

#[derive(Debug)]
pub enum ReadKeyStatus {
    Ok(KeySchema),
    DatabaseError(Box<dyn Error>),
    NoKeyFound,
}

#[derive(Debug)]
pub enum UpdateUserStatus {
    Ok,
    UserDoesNotExist,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum CreateKeyStatus {
    Ok,
    DatabaseError(Box<dyn Error>),
    UserDoesNotExist,
    KeyAlreadyExists,
}

#[derive(Debug)]
pub enum UpdateKeyStatus {
    Ok,
    DatabaseError(Box<dyn Error>),
    KeyDoesNotExist,
}
