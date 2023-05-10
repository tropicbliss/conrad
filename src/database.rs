use async_trait::async_trait;
use std::error::Error;

#[async_trait]
pub trait DatabaseAdapter {
    type UserAttributes;

    async fn create_user_and_key(
        &self,
        user_attributes: &Self::UserAttributes,
        key: KeySchema,
    ) -> CreateUserStatus;
    async fn read_user(&self, user_id: &str) -> ReadUserStatus<Self::UserAttributes>;
    async fn create_session(&self, session_data: SessionSchema) -> CreateSessionStatus;
    async fn read_sessions(&self, user_id: &str) -> ReadSessionsStatus;
    async fn delete_session_by_session_id(&self, session_id: &str) -> GeneralStatus;
    async fn read_session(&self, session_id: &str) -> ReadSessionStatus;
    async fn read_key(&self, key_id: &str) -> ReadKeyStatus;
    async fn update_user(
        &self,
        user_id: &str,
        user_attributes: &Self::UserAttributes,
    ) -> UpdateUserStatus;
    async fn delete_session_by_user_id(&self, user_id: &str) -> GeneralStatus;
    async fn delete_key(&self, user_id: &str) -> GeneralStatus;
    async fn delete_user(&self, user_id: &str) -> GeneralStatus;
}

#[derive(Clone, Debug)]
pub struct KeySchema<'a> {
    pub id: &'a str,
    pub hashed_password: Option<&'a str>,
    pub user_id: &'a str,
    // check the use_key() method if expires is added back in
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
pub enum GeneralStatus {
    Ok,
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

#[derive(Clone, Debug)]
pub struct User<U> {
    pub user_id: String,
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
    pub user_id: &'a str,
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
pub struct UserMetadata {
    pub provider_id: String,
    pub provider_user_id: String,
    pub user_id: String,
}
