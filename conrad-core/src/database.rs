use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use std::error::Error;

#[async_trait]
pub trait DatabaseAdapter
where
    Self::UserAttributes: Serialize + DeserializeOwned,
{
    type UserAttributes;

    async fn create_user_and_key(
        &self,
        user_attributes: &Self::UserAttributes,
        key: KeySchema,
    ) -> CreateUserStatus;
    async fn read_user(&self, user_id: &UserId) -> ReadUserStatus<Self::UserAttributes>;
    async fn create_session(&self, session_data: SessionSchema) -> CreateSessionStatus;
    async fn read_sessions(&self, user_id: &UserId) -> ReadSessionsStatus;
    async fn delete_session(&self, session_id: &str) -> GeneralStatus<()>;
    async fn read_session(&self, session_id: &str) -> ReadSessionStatus;
    async fn read_key(&self, key_id: &str) -> ReadKeyStatus;
    async fn update_user(
        &self,
        user_id: &UserId,
        user_attributes: &Self::UserAttributes,
    ) -> UpdateUserStatus;
    async fn delete_sessions_by_user_id(&self, user_id: &UserId) -> GeneralStatus<()>;
    async fn delete_keys(&self, user_id: &UserId) -> GeneralStatus<()>;
    async fn delete_user(&self, user_id: &UserId) -> GeneralStatus<()>;
    async fn create_key(&self, key: KeySchema) -> CreateKeyStatus;
    async fn delete_non_primary_key(&self, key_id: &str) -> GeneralStatus<()>;
    async fn read_keys_by_user_id(&self, user_id: &UserId) -> GeneralStatus<Vec<KeySchema>>;
    async fn update_key_password(
        &self,
        key_id: &str,
        hashed_password: Option<&str>,
    ) -> UpdateKeyStatus;
}

#[derive(Clone, Debug)]
pub struct KeySchema<'a> {
    pub id: &'a str,
    pub hashed_password: Option<&'a str>,
    pub user_id: &'a UserId,
    pub primary_key: bool,
    pub expires: Option<i64>,
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
pub enum CreateSessionStatus {
    Ok,
    InvalidUserId,
    DuplicateSessionId,
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum ReadSessionsStatus<'a> {
    Ok(Vec<SessionSchema<'a>>),
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum GeneralStatus<T> {
    Ok(T),
    DatabaseError(Box<dyn Error>),
}

#[derive(Debug)]
pub enum ReadSessionStatus<'a> {
    Ok(SessionSchema<'a>),
    DatabaseError(Box<dyn Error>),
    SessionNotFound,
}

#[derive(Debug)]
pub enum ReadKeyStatus<'a> {
    Ok(KeySchema<'a>),
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

#[derive(Clone, Debug)]
pub struct User<U> {
    pub user_id: UserId,
    pub user_attributes: U,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub active_period_expires_at: i64,
    pub session_id: String,
    pub idle_period_expires_at: i64,
    pub state: SessionState,
    pub fresh: bool,
}

#[derive(Clone, Debug)]
pub struct SessionData {
    pub session_id: String,
    pub active_period_expires_at: i64,
    pub idle_period_expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct SessionSchema<'a> {
    pub session_data: &'a SessionData,
    pub user_id: &'a UserId,
}

#[derive(Clone, Debug)]
pub struct ValidationSuccess<U> {
    pub session: Session,
    pub user: User<U>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SessionState {
    Active,
    Idle,
}

#[derive(Clone, Debug)]
pub struct UserData {
    pub provider_id: String,
    pub provider_user_id: String,
    pub password: Option<String>,
}

impl UserData {
    pub fn new<T>(provider_id: T, provider_user_id: T, password: Option<T>) -> Self
    where
        T: AsRef<str>,
    {
        Self {
            provider_id: provider_id.as_ref().to_string(),
            provider_user_id: provider_user_id.as_ref().to_string(),
            password: password.map(|p| p.as_ref().to_string()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyType {
    Persistent,
    SingleUse { expires_in: KeyTimestamp },
}

pub struct SessionId<'a>(&'a str);

impl<'a> SessionId<'a> {
    pub fn new(session_id: &'a str) -> Self {
        Self(session_id)
    }

    pub fn as_str(&self) -> &str {
        self.0
    }
}

impl<'a> ToString for SessionId<'a> {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

impl<'a> From<&'a str> for SessionId<'a> {
    fn from(value: &'a str) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Copy)]
pub struct KeyTimestamp(pub(crate) i64);

#[derive(Clone, Debug)]
pub struct Key {
    pub key_type: KeyType,
    pub password_defined: bool,
    pub user_id: UserId,
}

#[derive(Clone, Debug)]
pub struct UserId(String);

impl UserId {
    pub fn new<T>(user_id: T) -> Self
    where
        T: AsRef<str>,
    {
        Self(user_id.as_ref().to_string())
    }
}

impl ToString for UserId {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}
