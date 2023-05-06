use async_trait::async_trait;

#[async_trait]
pub trait DatabaseAdapter<U> {
    async fn set_user(
        &self,
        user_id: &UserId,
        user_attributes: &U,
        key: KeySchema,
    ) -> CreateUserStatus;
    async fn get_user(&self, user_id: &UserId) -> ReadUserStatus<U>;
    async fn create_session(
        &self,
        user_id: &UserId,
        session_data: &SessionData,
    ) -> CreateSessionStatus;
    async fn read_sessions(&self, user_id: &UserId) -> ReadSessionsStatus;
    async fn delete_session(&self, session_id: &str) -> DeleteSessionStatus;
}

#[derive(Clone, Debug)]
pub struct KeySchema<'a> {
    pub id: &'a str,
    pub hashed_password: &'a str,
    pub primary_key: bool,
    pub user_id: &'a UserId,
    pub expires: Option<i32>,
}

#[derive(Clone, Debug)]
pub enum CreateUserStatus {
    Ok,
    UserAlreadyExists,
    DatabaseError(String),
}

#[derive(Clone, Debug)]
pub enum ReadUserStatus<U> {
    Ok(User<U>),
    UserDoesNotExist,
    DatabaseError(String),
}

#[derive(Clone, Debug)]
pub enum CreateSessionStatus {
    Ok,
    InvalidUserId,
    DuplicateSessionId,
    DatabaseError(String),
}

#[derive(Clone, Debug)]
pub enum ReadSessionsStatus {
    Ok(Vec<(SessionData, UserId)>),
    DatabaseError(String),
}

#[derive(Clone, Debug)]
pub enum DeleteSessionStatus {
    Ok,
    DatabaseError(String),
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
    pub state: &'static str,
    pub fresh: bool,
}

#[derive(Clone, Debug)]
pub struct SessionData {
    pub session_id: String,
    pub active_period_expires_at: i64,
    pub idle_period_expires_at: i64,
}
