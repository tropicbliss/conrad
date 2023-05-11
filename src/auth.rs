use crate::{
    database::{
        CreateKeyStatus, CreateSessionStatus, CreateUserStatus, DatabaseAdapter, GeneralStatus,
        Key, KeySchema, KeyTimestamp, KeyType, ReadKeyStatus, ReadSessionStatus,
        ReadSessionsStatus, ReadUserStatus, Session, SessionData, SessionSchema, SessionState,
        UpdateKeyStatus, UpdateUserStatus, User, UserData, UserId, ValidationSuccess,
    },
    errors::AuthError,
    utils,
};
use cookie::{time::OffsetDateTime, Cookie, CookieJar};
use futures::{stream, StreamExt};
use http::{HeaderMap, Method};
use std::time::Duration;
use tokio::join;
use url::Url;
use uuid::Uuid;

const SESSION_COOKIE_NAME: &str = "auth_session";

pub struct Authenticator<D, F> {
    adapter: D,
    generate_custom_user_id: Option<F>,
}

impl<D, F> Authenticator<D, F>
where
    D: DatabaseAdapter,
    F: Fn() -> String,
{
    pub fn new(adapter: D) -> Self {
        Self {
            adapter,
            generate_custom_user_id: None,
        }
    }

    pub fn generate_custom_user_id(&mut self, closure: F) {
        self.generate_custom_user_id = Some(closure);
    }

    /// `attributes` represent extra user metadata that can be stored on user creation.
    pub async fn create_user(
        &self,
        data: &UserData,
        attributes: D::UserAttributes,
    ) -> Result<User<D::UserAttributes>, AuthError>
    where
        F: FnOnce() -> String,
    {
        let user_id = UserId::new(if let Some(closure) = &self.generate_custom_user_id {
            closure()
        } else {
            Uuid::new_v4().to_string()
        });
        let key_id = format!("{}:{}", data.provider_id, data.provider_user_id);
        let hashed_password = if let Some(password) = &data.password {
            Some(utils::hash_password(password).await)
        } else {
            None
        };
        let res = self
            .adapter
            .create_user_and_key(
                &attributes,
                KeySchema {
                    id: &key_id,
                    user_id: &user_id,
                    hashed_password: hashed_password.as_deref(),
                    primary_key: true,
                    expires: None,
                },
            )
            .await;
        match res {
            CreateUserStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            CreateUserStatus::UserAlreadyExists => {
                let attributes = self.get_user(&user_id).await?;
                Ok(User {
                    user_id,
                    user_attributes: attributes,
                })
            }
            CreateUserStatus::Ok => Ok(User {
                user_id,
                user_attributes: attributes,
            }),
        }
    }

    pub async fn use_key(
        &self,
        provider_id: &str,
        provider_user_id: &str,
        password: Option<&str>,
    ) -> Result<Key, AuthError> {
        let key_id = format!("{}:{}", provider_id, provider_user_id);
        let res = self.adapter.read_key(&key_id).await;
        let database_key_data = match res {
            ReadKeyStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            ReadKeyStatus::Ok(k) => k,
            ReadKeyStatus::NoKeyFound => return Err(AuthError::InvalidKeyId),
        };
        let single_use = if let Some(expires) = database_key_data.expires {
            if expires != 0 {
                Some(expires)
            } else {
                None
            }
        } else {
            None
        };
        let hashed_password = database_key_data.hashed_password;
        if let Some(hashed_password) = hashed_password {
            if let Some(password) = password {
                if password.is_empty() || hashed_password.is_empty() {
                    return Err(AuthError::InvalidPassword);
                }
                if hashed_password.starts_with("$2a") {
                    return Err(AuthError::OutdatedPassword);
                }
                let valid_password = utils::validate_password(password, hashed_password).await;
                if !valid_password {
                    return Err(AuthError::InvalidPassword);
                }
                if let Some(expires) = single_use {
                    let within_expiration = utils::is_within_expiration(expires);
                    if !within_expiration {
                        return Err(AuthError::ExpiredKey);
                    }
                    let res = self
                        .adapter
                        .delete_non_primary_key(database_key_data.id)
                        .await;
                    match res {
                        GeneralStatus::Ok(_) => (),
                        GeneralStatus::DatabaseError(err) => {
                            return Err(AuthError::DatabaseError(err))
                        }
                    }
                }
            } else {
                return Err(AuthError::InvalidPassword);
            }
        }
        Ok(database_key_data.into())
    }

    pub async fn create_session(&self, user_id: &UserId) -> Result<Session, AuthError> {
        let session_info = Self::generate_session_id();
        let session_schema = SessionSchema {
            session_data: &session_info,
            user_id: &user_id,
        };
        let (res, _) = join!(
            self.adapter.create_session(session_schema.clone()),
            self.delete_dead_user_sessions(user_id)
        );
        match res {
            CreateSessionStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            CreateSessionStatus::DuplicateSessionId => Err(AuthError::DuplicateSessionId),
            CreateSessionStatus::InvalidUserId => Err(AuthError::InvalidUserId),
            CreateSessionStatus::Ok => Ok(Session {
                active_period_expires_at: session_schema.session_data.active_period_expires_at,
                session_id: session_schema.session_data.session_id.clone(),
                idle_period_expires_at: session_schema.session_data.idle_period_expires_at,
                state: SessionState::Active,
                fresh: true,
            }),
        }
    }

    fn parse_request_headers<'c>(
        cookies: &'c CookieJar,
        method: &Method,
        headers: &HeaderMap,
        origin_url: &Url,
    ) -> Option<&'c str> {
        let session_id = cookies.get(SESSION_COOKIE_NAME).map(|c| c.value());
        let csrf_check = method != Method::GET && method != Method::HEAD;
        let mut error = false;
        let request_origin = headers.get("origin");
        if csrf_check {
            match request_origin {
                Some(request_origin) => {
                    if let Ok(request_origin) = request_origin.to_str() {
                        if origin_url.as_str() != request_origin {
                            error = true;
                        }
                    } else {
                        error = true;
                    }
                }
                None => {
                    error = true;
                }
            }
        }
        if error {
            None
        } else {
            session_id
        }
    }

    pub async fn validate<'c>(
        &self,
        cookies: &mut CookieJar,
        method: &Method,
        headers: &HeaderMap,
        origin_url: &Url,
    ) -> Result<Option<Session>, AuthError> {
        let session_id = Self::parse_request_headers(cookies, method, headers, origin_url);
        match session_id {
            Some(session_id) => {
                let session = self.validate_session(session_id).await?;
                Self::set_session(cookies, Some(&session));
                Ok(Some(session))
            }
            _ => {
                Self::set_session(cookies, None);
                Ok(None)
            }
        }
    }

    pub async fn invalidate_session(&self, session_id: &str) -> Result<(), AuthError> {
        let res = self.adapter.delete_session(session_id).await;
        match res {
            GeneralStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(_) => Ok(()),
        }
    }

    pub async fn validate_user<'c>(
        &self,
        cookies: &mut CookieJar,
        method: &Method,
        headers: &HeaderMap,
        origin_url: &Url,
    ) -> Result<Option<ValidationSuccess<D::UserAttributes>>, AuthError> {
        let session_id = Self::parse_request_headers(cookies, method, headers, origin_url);
        match session_id {
            Some(session_id) => {
                let info = self.validate_session_user(session_id).await?;
                Self::set_session(cookies, Some(&info.session));
                Ok(Some(info))
            }
            None => {
                Self::set_session(cookies, None);
                Ok(None)
            }
        }
    }

    pub fn set_session(cookies: &mut CookieJar, session: Option<&Session>) {
        let cookie = if let Some(session) = session {
            Cookie::build(SESSION_COOKIE_NAME, session.session_id.clone())
                .same_site(cookie::SameSite::Lax)
                .path("/")
                .http_only(true)
                .expires(
                    OffsetDateTime::from_unix_timestamp(session.idle_period_expires_at).unwrap(),
                )
                .secure(true)
                .finish()
        } else {
            Cookie::build(SESSION_COOKIE_NAME, "")
                .same_site(cookie::SameSite::Lax)
                .path("/")
                .http_only(true)
                .expires(OffsetDateTime::UNIX_EPOCH)
                .secure(true)
                .finish()
        };
        cookies.add(cookie);
    }

    async fn validate_session_user(
        &self,
        session_id: &str,
    ) -> Result<ValidationSuccess<D::UserAttributes>, AuthError> {
        let info = self.get_session_user(session_id).await?;
        if info.session.state == SessionState::Active {
            Ok(info)
        } else {
            let renewed_session = self.get_session(session_id, true).await?;
            Ok(ValidationSuccess {
                session: renewed_session,
                ..info
            })
        }
    }

    async fn get_session_user(
        &self,
        session_id: &str,
    ) -> Result<ValidationSuccess<D::UserAttributes>, AuthError> {
        if Uuid::try_parse(session_id).is_err() {
            return Err(AuthError::InvalidSessionId);
        }
        let res = self.adapter.read_session(session_id).await;
        let session_data = match res {
            ReadSessionStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            ReadSessionStatus::Ok(s) => s,
            ReadSessionStatus::SessionNotFound => return Err(AuthError::InvalidSessionId),
        };
        let session = Self::validate_database_session(session_data.session_data);
        if let Some(session) = session {
            let res = self.adapter.read_user(session_data.user_id).await;
            let database_user = match res {
                ReadUserStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
                ReadUserStatus::Ok(u) => u,
                ReadUserStatus::UserDoesNotExist => return Err(AuthError::InvalidUserId),
            };
            Ok(ValidationSuccess {
                session,
                user: database_user,
            })
        } else {
            self.adapter
                .delete_session(&session_data.session_data.session_id)
                .await;
            Err(AuthError::InvalidSessionId)
        }
    }

    async fn validate_session(&self, session_id: &str) -> Result<Session, AuthError> {
        let session = self.get_session(session_id, false).await?;
        if session.state == SessionState::Active {
            Ok(session)
        } else {
            self.get_session(session_id, true).await
        }
    }

    fn validate_database_session(database_session: &SessionData) -> Option<Session> {
        if utils::is_within_expiration(database_session.idle_period_expires_at) {
            let active_key = utils::is_within_expiration(database_session.active_period_expires_at);
            Some(Session {
                state: if active_key {
                    SessionState::Active
                } else {
                    SessionState::Idle
                },
                fresh: false,
                active_period_expires_at: database_session.active_period_expires_at,
                idle_period_expires_at: database_session.idle_period_expires_at,
                session_id: database_session.session_id.clone(),
            })
        } else {
            None
        }
    }

    async fn get_session(&self, session_id: &str, renew: bool) -> Result<Session, AuthError> {
        if Uuid::try_parse(session_id).is_err() {
            return Err(AuthError::InvalidSessionId);
        }
        let res = self.adapter.read_session(session_id).await;
        let database_session = match res {
            ReadSessionStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            ReadSessionStatus::Ok(session) => session,
            ReadSessionStatus::SessionNotFound => return Err(AuthError::InvalidSessionId),
        };
        let session = Self::validate_database_session(database_session.session_data);
        if let Some(session) = session {
            if renew {
                let user_id = database_session.user_id;
                let (renewed_session, _) = join!(
                    self.create_session(&user_id),
                    self.delete_dead_user_sessions(&user_id)
                );
                Ok(renewed_session?)
            } else {
                Ok(session)
            }
        } else {
            let res = self.adapter.delete_session(session_id).await;
            match res {
                GeneralStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
                GeneralStatus::Ok(_) => Err(AuthError::InvalidSessionId),
            }
        }
    }

    pub async fn get_user(&self, user_id: &UserId) -> Result<D::UserAttributes, AuthError> {
        let res = self.adapter.read_user(user_id).await;
        match res {
            ReadUserStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            ReadUserStatus::Ok(att) => Ok(att.user_attributes),
            ReadUserStatus::UserDoesNotExist => Err(AuthError::InvalidUserId),
        }
    }

    fn generate_session_id() -> SessionData {
        const ACTIVE_PERIOD: u64 = 1000 * 60 * 60 * 24;
        const IDLE_PERIOD: u64 = 1000 * 60 * 60 * 24 * 14;
        let session_id = Uuid::new_v4().to_string();
        let active_period_expires_at =
            OffsetDateTime::now_utc() + Duration::from_millis(ACTIVE_PERIOD);
        let idle_period_expires_at = active_period_expires_at + Duration::from_millis(IDLE_PERIOD);
        SessionData {
            active_period_expires_at: active_period_expires_at.unix_timestamp(),
            idle_period_expires_at: idle_period_expires_at.unix_timestamp(),
            session_id,
        }
    }

    async fn delete_dead_user_sessions(&self, user_id: &UserId) -> Result<(), AuthError> {
        let res = self.adapter.read_sessions(user_id).await;
        let database_sessions = match res {
            ReadSessionsStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            ReadSessionsStatus::Ok(s) => s,
        };
        let dead_session_ids = database_sessions.into_iter().filter_map(|s| {
            if !utils::is_within_expiration(s.session_data.idle_period_expires_at) {
                Some(&s.session_data.session_id)
            } else {
                None
            }
        });
        stream::iter(dead_session_ids)
            .for_each_concurrent(3, |id| async move {
                self.adapter.delete_session(&id).await;
            })
            .await;
        Ok(())
    }

    pub async fn update_user_attributes(
        &self,
        user_id: &UserId,
        attributes: &D::UserAttributes,
    ) -> Result<(), AuthError> {
        let (res, _) = join!(
            self.adapter.update_user(user_id, attributes),
            self.delete_dead_user_sessions(user_id)
        );
        match res {
            UpdateUserStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            UpdateUserStatus::UserDoesNotExist => Err(AuthError::InvalidUserId),
            UpdateUserStatus::Ok => Ok(()),
        }
    }

    pub async fn invalidate_all_user_sessions(&self, user_id: &UserId) -> Result<(), AuthError> {
        let res = self.adapter.delete_sessions_by_user_id(user_id).await;
        match res {
            GeneralStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(_) => Ok(()),
        }
    }

    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), AuthError> {
        let res = self.adapter.delete_sessions_by_user_id(user_id).await;
        match res {
            GeneralStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(_) => (),
        }
        let res = self.adapter.delete_keys(user_id).await;
        match res {
            GeneralStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(_) => (),
        }
        let res = self.adapter.delete_user(user_id).await;
        match res {
            GeneralStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(_) => Ok(()),
        }
    }

    pub async fn create_key(
        &self,
        user_id: &UserId,
        user_data: &UserData,
        key_type: &KeyType,
    ) -> Result<Key, AuthError> {
        let key_id = format!("{}:{}", user_data.provider_id, user_data.provider_user_id);
        let hashed_password = if let Some(password) = &user_data.password {
            Some(utils::hash_password(password).await)
        } else {
            None
        };
        if let KeyType::SingleUse { expires_in } = key_type {
            let expires_at = Self::get_one_time_key_expiration(expires_in.get_timestamp());
            let res = self
                .adapter
                .create_key(KeySchema {
                    id: &key_id,
                    hashed_password: hashed_password.as_deref(),
                    user_id,
                    primary_key: false,
                    expires: Some(expires_at),
                })
                .await;
            match res {
                CreateKeyStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
                CreateKeyStatus::KeyAlreadyExists => Err(AuthError::DuplicateKeyId),
                CreateKeyStatus::UserDoesNotExist => Err(AuthError::InvalidUserId),
                CreateKeyStatus::Ok => Ok(Key {
                    key_type: KeyType::SingleUse {
                        expires_in: expires_at.into(),
                    },
                    password_defined: if let Some(password) = &user_data.password {
                        !password.is_empty()
                    } else {
                        false
                    },
                    user_id: user_id.clone(),
                }),
            }
        } else {
            let res = self
                .adapter
                .create_key(KeySchema {
                    id: &key_id,
                    hashed_password: hashed_password.as_deref(),
                    user_id,
                    primary_key: false,
                    expires: None,
                })
                .await;
            match res {
                CreateKeyStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
                CreateKeyStatus::KeyAlreadyExists => Err(AuthError::DuplicateKeyId),
                CreateKeyStatus::UserDoesNotExist => Err(AuthError::InvalidUserId),
                CreateKeyStatus::Ok => Ok(Key {
                    key_type: KeyType::Persistent,
                    password_defined: if let Some(password) = &user_data.password {
                        !password.is_empty()
                    } else {
                        false
                    },
                    user_id: user_id.clone(),
                }),
            }
        }
    }

    fn get_one_time_key_expiration(duration: i64) -> i64 {
        (OffsetDateTime::now_utc() + Duration::from_millis(duration as u64 * 1000 * 1000))
            .unix_timestamp()
    }

    pub async fn get_key(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Key, AuthError> {
        let key_id = format!("{}:{}", provider_id, provider_user_id);
        let res = self.adapter.read_key(&key_id).await;
        let database_key = match res {
            ReadKeyStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            ReadKeyStatus::NoKeyFound => return Err(AuthError::InvalidKeyId),
            ReadKeyStatus::Ok(k) => k,
        };
        Ok(database_key.into())
    }

    pub async fn get_all_user_keys(&self, user_id: &UserId) -> Result<Vec<Key>, AuthError> {
        let res = self.adapter.read_keys_by_user_id(user_id).await;
        let database_data = match res {
            GeneralStatus::DatabaseError(err) => return Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(k) => k,
        };
        Ok(database_data.into_iter().map(|d| d.into()).collect())
    }

    pub async fn update_key_password(&self, data: &UserData) -> Result<(), AuthError> {
        let key_id = format!("{}:{}", data.provider_id, data.provider_user_id);
        let res = if let Some(password) = &data.password {
            let hashed_password = utils::hash_password(password).await;
            self.adapter
                .update_key_password(&key_id, Some(&hashed_password))
                .await
        } else {
            self.adapter.update_key_password(&key_id, None).await
        };
        match res {
            UpdateKeyStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            UpdateKeyStatus::KeyDoesNotExist => Err(AuthError::InvalidKeyId),
            UpdateKeyStatus::Ok => Ok(()),
        }
    }

    pub async fn delete_key(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<(), AuthError> {
        let key_id = format!("{}:{}", provider_id, provider_user_id);
        let res = self.adapter.delete_non_primary_key(&key_id).await;
        match res {
            GeneralStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            GeneralStatus::Ok(_) => Ok(()),
        }
    }
}

impl KeyTimestamp {
    pub fn get_timestamp(&self) -> i64 {
        self.0
    }

    pub fn is_expired(&self) -> bool {
        !utils::is_within_expiration(self.get_timestamp())
    }
}

impl From<i64> for KeyTimestamp {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<KeySchema<'_>> for Key {
    fn from(database_key: KeySchema) -> Self {
        let user_id = database_key.user_id;
        let is_password_defined = if let Some(hashed_password) = database_key.hashed_password {
            !hashed_password.is_empty()
        } else {
            false
        };
        if let Some(expires) = database_key.expires {
            Self {
                key_type: KeyType::SingleUse {
                    expires_in: expires.into(),
                },
                password_defined: is_password_defined,
                user_id: user_id.clone(),
            }
        } else {
            Self {
                key_type: KeyType::Persistent,
                password_defined: is_password_defined,
                user_id: user_id.clone(),
            }
        }
    }
}
