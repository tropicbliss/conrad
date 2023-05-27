pub mod auth;
pub mod database;
pub mod errors;
mod utils;

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
    pub fn new(provider_id: String, provider_user_id: String, password: Option<String>) -> Self {
        assert!(
            !provider_id.contains(':'),
            "provider id must not contain any ':' characters"
        );
        Self {
            provider_id,
            provider_user_id,
            password,
        }
    }
}

#[derive(Clone, Debug)]
pub enum KeyType {
    Persistent { primary: bool },
    SingleUse { expires_in: KeyTimestamp },
}

#[derive(Clone, Debug)]
pub enum NaiveKeyType {
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
    pub provider_id: String,
    pub provider_user_id: String,
}

#[derive(Clone, Debug)]
pub struct UserId(String);

impl UserId {
    pub fn new(user_id: String) -> Self {
        assert!(
            !user_id.contains('.'),
            "user id must not contain any '.' characters"
        );
        Self(user_id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ToString for UserId {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}
