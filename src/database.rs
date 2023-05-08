use async_trait::async_trait;
use std::error::Error;

#[async_trait]
pub trait DatabaseAdapter<U> {
    async fn create_user_and_key(&self, user_attributes: &U, key: KeySchema) -> CreateUserStatus;
    async fn read_user(&self, user_id: &UserId) -> ReadUserStatus<U>;
    async fn create_session(&self, session_data: SessionSchema) -> CreateSessionStatus;
    async fn read_sessions(&self, user_id: &UserId) -> ReadSessionsStatus;
    async fn delete_session(&self, session_id: &str) -> DeleteSessionStatus;
    async fn read_session(&self, session_id: &str) -> ReadSessionStatus;
    async fn read_key(&self, key_id: &str) -> ReadKeyStatus;
}

#[derive(Clone, Debug)]
pub struct KeySchema<'a> {
    pub id: &'a str,
    pub hashed_password: &'a str,
    pub user_id: &'a UserId,
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
pub enum DeleteSessionStatus {
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

#[derive(Clone, Debug)]
pub struct UserId(String);

impl UserId {
    pub(crate) fn new(user_id: String) -> Self {
        Self(user_id)
    }
}

impl ToString for UserId {
    fn to_string(&self) -> String {
        self.0.clone()
    }
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
pub struct UserMetadata {
    pub provider_id: String,
    pub provider_user_id: String,
    pub user_id: UserId,
}
