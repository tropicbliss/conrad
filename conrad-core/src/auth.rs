use crate::{
    database::{
        CreateKeyError, CreateSessionError, CreateUserError, DatabaseAdapter, KeyError, KeySchema,
        SessionData, SessionError, SessionSchema, UserError,
    },
    errors::AuthError,
    request::Request,
    utils, Key, KeyTimestamp, KeyType, NaiveKeyType, Session, SessionId, SessionState, User,
    UserData, UserId, ValidationSuccess,
};
use cookie::{time::OffsetDateTime, Cookie, CookieJar};
use futures::{stream, StreamExt, TryStreamExt};
use http::{HeaderMap, Method};
use std::{marker::PhantomData, time::Duration};
use tokio::join;
use url::Url;
use uuid::Uuid;

const SESSION_COOKIE_NAME: &str = "auth_session";

pub struct AuthenticatorBuilder<D> {
    adapter: D,
    generate_custom_user_id: fn() -> UserId,
    auto_database_cleanup: bool,
}

impl<D> AuthenticatorBuilder<D> {
    pub fn new(adapter: D) -> Self {
        Self {
            adapter,
            generate_custom_user_id: || UserId::new(Uuid::new_v4().to_string()),
            auto_database_cleanup: true,
        }
    }

    pub fn set_user_id_generator<F>(self, function: fn() -> UserId) -> Self {
        Self {
            generate_custom_user_id: function,
            ..self
        }
    }

    pub fn enable_auto_database_cleanup(self, enable: bool) -> Self {
        Self {
            auto_database_cleanup: enable,
            ..self
        }
    }

    pub fn build<U>(self) -> Authenticator<D, U> {
        Authenticator {
            adapter: self.adapter,
            generate_custom_user_id: self.generate_custom_user_id,
            auto_database_cleanup: self.auto_database_cleanup,
            _user_attributes: PhantomData::default(),
        }
    }
}

pub struct Authenticator<D, U> {
    adapter: D,
    generate_custom_user_id: fn() -> UserId,
    auto_database_cleanup: bool,
    _user_attributes: PhantomData<U>,
}

impl<D, U> Authenticator<D, U>
where
    D: DatabaseAdapter<U>,
{
    /// `attributes` represent extra user metadata that can be stored on user creation.
    pub async fn create_user(&self, data: UserData, attributes: U) -> Result<User<U>, AuthError> {
        let user_id = (self.generate_custom_user_id)();
        let key_id = format!("{}:{}", data.provider_id, data.provider_user_id);
        let hashed_password = if let Some(password) = data.password {
            Some(utils::hash_password(password).await)
        } else {
            None
        };
        let res = self
            .adapter
            .create_user_and_key(
                &attributes,
                &KeySchema {
                    id: key_id,
                    user_id: user_id.clone(),
                    hashed_password,
                    primary_key: true,
                    expires: None,
                },
            )
            .await;
        match res {
            Err(CreateUserError::DatabaseError(err)) => Err(AuthError::DatabaseError(err)),
            Err(CreateUserError::UserAlreadyExists) => {
                let attributes = self.get_user(&user_id).await?;
                Ok(User {
                    user_id,
                    user_attributes: attributes,
                })
            }
            Ok(()) => Ok(User {
                user_id,
                user_attributes: attributes,
            }),
        }
    }

    pub async fn use_key(
        &self,
        provider_id: &str,
        provider_user_id: &str,
        password: Option<String>,
    ) -> Result<Key, AuthError> {
        let key_id = format!("{provider_id}:{provider_user_id}");
        let database_key_data = self
            .adapter
            .read_key(&key_id)
            .await
            .map_err(|err| match err {
                KeyError::DatabaseError(err) => AuthError::DatabaseError(err),
                KeyError::KeyDoesNotExist => AuthError::InvalidKeyId,
            })?;
        let single_use = database_key_data.expires.filter(|&expires| expires != 0);
        let hashed_password = database_key_data.hashed_password.clone();
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
                    self.adapter
                        .delete_non_primary_key(&database_key_data.id)
                        .await?;
                }
            } else {
                return Err(AuthError::InvalidPassword);
            }
        }
        Ok(database_key_data.into())
    }

    pub async fn create_session(&self, user_id: UserId) -> Result<Session, AuthError> {
        let session_info = generate_session_id();
        let session_schema = SessionSchema {
            session_data: session_info,
            user_id: user_id.clone(),
        };
        if self.auto_database_cleanup {
            let (res, _) = join!(
                self.adapter.create_session(&session_schema),
                self.delete_dead_user_sessions(&user_id)
            );
            res
        } else {
            self.adapter.create_session(&session_schema).await
        }
        .map_err(|err| match err {
            CreateSessionError::DatabaseError(err) => AuthError::DatabaseError(err),
            CreateSessionError::DuplicateSessionId => AuthError::DuplicateSessionId,
            CreateSessionError::InvalidUserId => AuthError::InvalidUserId,
        })?;
        Ok(Session {
            active_period_expires_at: session_schema.session_data.active_period_expires_at,
            session_id: session_schema.session_data.session_id,
            idle_period_expires_at: session_schema.session_data.idle_period_expires_at,
            state: SessionState::Active,
            fresh: true,
        })
    }

    pub async fn invalidate_session(&self, session_id: &str) -> Result<(), AuthError> {
        Ok(self.adapter.delete_session(session_id).await?)
    }

    pub(crate) async fn validate_session_user(
        &self,
        session_id: &str,
    ) -> Result<ValidationSuccess<U>, AuthError> {
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

    async fn get_session_user(&self, session_id: &str) -> Result<ValidationSuccess<U>, AuthError> {
        if Uuid::try_parse(session_id).is_err() {
            return Err(AuthError::InvalidSessionId);
        }
        let database_user_session = self
            .adapter
            .read_session_and_user_by_session_id(session_id)
            .await
            .map_err(|err| match err {
                SessionError::SessionNotFound => AuthError::InvalidSessionId,
                SessionError::DatabaseError(err) => AuthError::DatabaseError(err),
            })?;
        let database_user = database_user_session.user;
        let session_data = database_user_session.session;
        let session = utils::validate_database_session(session_data.session_data.clone());
        if let Some(session) = session {
            Ok(ValidationSuccess {
                session,
                user: database_user,
            })
        } else {
            if self.auto_database_cleanup {
                self.adapter
                    .delete_session(&session_data.session_data.session_id)
                    .await?;
            }
            Err(AuthError::InvalidSessionId)
        }
    }

    async fn get_session(&self, session_id: &str, renew: bool) -> Result<Session, AuthError> {
        if Uuid::try_parse(session_id).is_err() {
            return Err(AuthError::InvalidSessionId);
        }
        let database_session =
            self.adapter
                .read_session(session_id)
                .await
                .map_err(|err| match err {
                    SessionError::DatabaseError(err) => AuthError::DatabaseError(err),
                    SessionError::SessionNotFound => AuthError::InvalidSessionId,
                })?;
        let session = utils::validate_database_session(database_session.session_data);
        if let Some(session) = session {
            if renew {
                let user_id = database_session.user_id;
                let renewed_session = if self.auto_database_cleanup {
                    let (renewed_session, _) = join!(
                        self.create_session(user_id.clone()),
                        self.delete_dead_user_sessions(&user_id)
                    );
                    renewed_session
                } else {
                    self.create_session(user_id).await
                };
                Ok(renewed_session?)
            } else {
                Ok(session)
            }
        } else {
            if self.auto_database_cleanup {
                self.adapter.delete_session(session_id).await?;
            }
            Err(AuthError::InvalidSessionId)
        }
    }

    pub async fn get_user(&self, user_id: &UserId) -> Result<U, AuthError> {
        Ok(self
            .adapter
            .read_user(user_id)
            .await
            .map_err(|err| match err {
                UserError::DatabaseError(err) => AuthError::DatabaseError(err),
                UserError::UserDoesNotExist => AuthError::InvalidUserId,
            })?
            .user_attributes)
    }

    pub fn handle_request<'a>(
        &'a self,
        cookies: &CookieJar,
        method: &Method,
        headers: &HeaderMap,
        origin_url: &Url,
    ) -> Request<'a, D, U> {
        Request::new(self, cookies, method, headers, origin_url)
    }

    async fn delete_dead_user_sessions(&self, user_id: &UserId) -> Result<(), AuthError> {
        let database_sessions = self.adapter.read_sessions(user_id).await?;
        let dead_session_ids = database_sessions.into_iter().filter_map(|s| {
            if utils::is_within_expiration(s.session_data.idle_period_expires_at) {
                None
            } else {
                Some(s.session_data.session_id)
            }
        });
        stream::iter(dead_session_ids)
            .map(|id| async move { self.adapter.delete_session(&id).await })
            .buffer_unordered(10)
            .try_collect()
            .await?;
        Ok(())
    }

    pub async fn update_user_attributes(
        &self,
        user_id: &UserId,
        attributes: U,
    ) -> Result<(), AuthError> {
        if self.auto_database_cleanup {
            let (res, _) = join!(
                self.adapter.update_user(user_id, &attributes),
                self.delete_dead_user_sessions(user_id)
            );
            res
        } else {
            self.adapter.update_user(user_id, &attributes).await
        }
        .map_err(|err| match err {
            UserError::DatabaseError(err) => AuthError::DatabaseError(err),
            UserError::UserDoesNotExist => AuthError::InvalidUserId,
        })
    }

    pub async fn invalidate_all_user_sessions(&self, user_id: &UserId) -> Result<(), AuthError> {
        Ok(self.adapter.delete_sessions_by_user_id(user_id).await?)
    }

    pub async fn delete_user(&self, user_id: UserId) -> Result<(), AuthError> {
        self.adapter.delete_sessions_by_user_id(&user_id).await?;
        self.adapter.delete_keys(&user_id).await?;
        Ok(self.adapter.delete_user(&user_id).await?)
    }

    pub async fn create_key(
        &self,
        user_id: UserId,
        user_data: UserData,
        key_type: &NaiveKeyType,
    ) -> Result<Key, AuthError> {
        let key_id = format!("{}:{}", user_data.provider_id, user_data.provider_user_id);
        let hashed_password = if let Some(password) = user_data.password.clone() {
            Some(utils::hash_password(password).await)
        } else {
            None
        };
        let key_type = if let NaiveKeyType::SingleUse { expires_in } = key_type {
            let expires_at = get_one_time_key_expiration(expires_in.get_timestamp());
            self.adapter
                .create_key(&KeySchema {
                    id: key_id,
                    hashed_password,
                    user_id: user_id.clone(),
                    primary_key: false,
                    expires: Some(expires_at),
                })
                .await
                .map_err(|err| match err {
                    CreateKeyError::DatabaseError(err) => AuthError::DatabaseError(err),
                    CreateKeyError::KeyAlreadyExists => AuthError::DuplicateKeyId,
                    CreateKeyError::UserDoesNotExist => AuthError::InvalidUserId,
                })?;
            KeyType::SingleUse {
                expires_in: expires_at.into(),
            }
        } else {
            self.adapter
                .create_key(&KeySchema {
                    id: key_id,
                    hashed_password,
                    user_id: user_id.clone(),
                    primary_key: false,
                    expires: None,
                })
                .await
                .map_err(|err| match err {
                    CreateKeyError::DatabaseError(err) => AuthError::DatabaseError(err),
                    CreateKeyError::KeyAlreadyExists => AuthError::DuplicateKeyId,
                    CreateKeyError::UserDoesNotExist => AuthError::InvalidUserId,
                })?;
            KeyType::Persistent { primary: false }
        };
        Ok(Key {
            key_type,
            password_defined: if let Some(password) = user_data.password {
                !password.is_empty()
            } else {
                false
            },
            user_id,
            provider_id: user_data.provider_id,
            provider_user_id: user_data.provider_user_id,
        })
    }

    pub async fn get_key(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<Key, AuthError> {
        let key_id = format!("{provider_id}:{provider_user_id}");
        let database_key = self
            .adapter
            .read_key(&key_id)
            .await
            .map_err(|err| match err {
                KeyError::DatabaseError(err) => AuthError::DatabaseError(err),
                KeyError::KeyDoesNotExist => AuthError::InvalidKeyId,
            })?;
        Ok(database_key.into())
    }

    pub async fn get_all_user_keys(&self, user_id: &UserId) -> Result<Vec<Key>, AuthError> {
        let database_data = self.adapter.read_keys_by_user_id(user_id).await?;
        Ok(database_data
            .into_iter()
            .map(std::convert::Into::into)
            .collect())
    }

    pub async fn update_key_password(&self, data: UserData) -> Result<(), AuthError> {
        let key_id = format!("{}:{}", data.provider_id, data.provider_user_id);
        if let Some(password) = data.password {
            let hashed_password = utils::hash_password(password).await;
            self.adapter
                .update_key_password(&key_id, Some(&hashed_password))
                .await
        } else {
            self.adapter.update_key_password(&key_id, None).await
        }
        .map_err(|err| match err {
            KeyError::DatabaseError(err) => AuthError::DatabaseError(err),
            KeyError::KeyDoesNotExist => AuthError::InvalidKeyId,
        })
    }

    pub async fn delete_key(
        &self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<(), AuthError> {
        let key_id = format!("{provider_id}:{provider_user_id}");
        Ok(self.adapter.delete_non_primary_key(&key_id).await?)
    }
}

#[must_use]
pub fn parse_request_headers<'c>(
    cookies: &'c CookieJar,
    method: &Method,
    headers: &HeaderMap,
    origin_url: &Url,
) -> Option<SessionId<'c>> {
    let session_id = cookies.get(SESSION_COOKIE_NAME).map(|c| c.value().into());
    let csrf_check = method != Method::GET && method != Method::HEAD;
    if csrf_check {
        let request_origin = headers.get("origin");
        match request_origin {
            Some(request_origin) => {
                if let Ok(request_origin) = request_origin.to_str() {
                    if origin_url.as_str() != request_origin {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            None => {
                return None;
            }
        }
    }
    session_id
}

fn generate_session_id() -> SessionData {
    const ACTIVE_PERIOD: u64 = 1000 * 60 * 60 * 24;
    const IDLE_PERIOD: u64 = 1000 * 60 * 60 * 24 * 14;
    let session_id = Uuid::new_v4().to_string();
    let active_period_expires_at = OffsetDateTime::now_utc() + Duration::from_millis(ACTIVE_PERIOD);
    let idle_period_expires_at = active_period_expires_at + Duration::from_millis(IDLE_PERIOD);
    SessionData {
        active_period_expires_at: active_period_expires_at.unix_timestamp(),
        idle_period_expires_at: idle_period_expires_at.unix_timestamp(),
        session_id,
    }
}

fn get_one_time_key_expiration(duration: i64) -> i64 {
    assert!(duration >= 0, "duration cannot be negative");
    (OffsetDateTime::now_utc() + Duration::from_millis(duration as u64 * 1000 * 1000))
        .unix_timestamp()
}

#[must_use]
pub fn create_session_cookie<'c>(session: Option<Session>) -> Cookie<'c> {
    if let Some(session) = session {
        Cookie::build(SESSION_COOKIE_NAME, session.session_id)
            .same_site(cookie::SameSite::Lax)
            .path("/")
            .http_only(true)
            .expires(OffsetDateTime::from_unix_timestamp(session.idle_period_expires_at).unwrap())
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
    }
}

impl KeyTimestamp {
    #[must_use]
    pub fn get_timestamp(&self) -> i64 {
        self.0
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        !utils::is_within_expiration(self.get_timestamp())
    }
}

impl From<i64> for KeyTimestamp {
    fn from(value: i64) -> Self {
        Self(value)
    }
}

impl From<KeySchema> for Key {
    fn from(database_key: KeySchema) -> Self {
        let user_id = database_key.user_id;
        let is_password_defined = if let Some(hashed_password) = database_key.hashed_password {
            !hashed_password.is_empty()
        } else {
            false
        };
        let (provider_id, provider_user_id) = database_key.id.split_once(':').unwrap();
        let key_type = if let Some(expires) = database_key.expires {
            KeyType::SingleUse {
                expires_in: expires.into(),
            }
        } else {
            KeyType::Persistent {
                primary: database_key.primary_key,
            }
        };
        Self {
            key_type,
            password_defined: is_password_defined,
            user_id,
            provider_id: provider_id.to_string(),
            provider_user_id: provider_user_id.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{database::SessionData, utils::validate_database_session, Session, SessionState};
    use cookie::time::OffsetDateTime;
    use std::time::Duration;

    #[test]
    fn validate_database_session_returns_none_if_dead_state() {
        let output = validate_database_session(SessionData {
            active_period_expires_at: OffsetDateTime::now_utc().unix_timestamp(),
            idle_period_expires_at: (OffsetDateTime::now_utc() - Duration::from_millis(10 * 1000))
                .unix_timestamp(),
            session_id: String::new(),
        });
        assert!(output.is_none());
    }

    #[test]
    fn validate_database_session_returns_idle_session_if_idle_state() {
        let output = validate_database_session(SessionData {
            active_period_expires_at: (OffsetDateTime::now_utc()
                - Duration::from_millis(10 * 1000))
            .unix_timestamp(),
            idle_period_expires_at: (OffsetDateTime::now_utc() + Duration::from_millis(10 * 1000))
                .unix_timestamp(),
            session_id: String::new(),
        });
        assert!(matches!(
            output,
            Some(Session {
                state: SessionState::Idle,
                ..
            })
        ))
    }

    #[test]
    fn validate_database_session_returns_active_session_if_active_state() {
        let output = validate_database_session(SessionData {
            active_period_expires_at: (OffsetDateTime::now_utc()
                + Duration::from_millis(10 * 1000))
            .unix_timestamp(),
            idle_period_expires_at: (OffsetDateTime::now_utc() + Duration::from_millis(10 * 1000))
                .unix_timestamp(),
            session_id: String::new(),
        });
        assert!(matches!(
            output,
            Some(Session {
                state: SessionState::Active,
                ..
            })
        ))
    }
}
