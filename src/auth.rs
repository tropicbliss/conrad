use crate::{
    database::{
        CreateSessionStatus, CreateUserStatus, DatabaseAdapter, DeleteSessionStatus, KeySchema,
        ReadSessionStatus, ReadSessionsStatus, ReadUserStatus, Session, SessionData, SessionSchema,
        User, UserId,
    },
    errors::AuthError,
    utils,
};
use cookie::{time::OffsetDateTime, Cookie};
use futures::{stream, StreamExt};
use http::{HeaderMap, Method};
use std::{marker::PhantomData, time::Duration};
use tokio::join;
use url::Url;
use uuid::Uuid;

pub struct Authenticator<D, U> {
    user_attributes: PhantomData<U>,
    adapter: D,
}

impl<D, U> Authenticator<D, U>
where
    D: DatabaseAdapter<U>,
{
    pub fn new(adapter: D) -> Self {
        Self {
            user_attributes: PhantomData::default(),
            adapter,
        }
    }

    /// `attributes` represent extra user metadata that can be stored on user creation.
    pub async fn create_user(
        &self,
        provider_id: &str,
        provider_user_id: &str,
        password: &str,
        attributes: U,
    ) -> Result<User<U>, AuthError> {
        let user_id = Uuid::new_v4().to_string();
        let key_id = format!("{}:{}", provider_id, provider_user_id);
        let hashed_password = {
            let password = password.to_string();
            tokio::task::spawn_blocking(move || utils::hash_password(&password))
                .await
                .unwrap()
        };
        let user_id = UserId::new(user_id);
        let res = self
            .adapter
            .set_user(
                &attributes,
                KeySchema {
                    id: &key_id,
                    user_id: &user_id,
                    hashed_password: &hashed_password,
                    primary_key: true,
                    expires: None,
                },
            )
            .await;
        match res {
            CreateUserStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            CreateUserStatus::UserAlreadyExists => self.get_user(&user_id).await,
            CreateUserStatus::Ok => Ok(User {
                user_id,
                user_attributes: attributes,
            }),
        }
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
                state: "active",
                fresh: true,
            }),
        }
    }

    pub async fn validate_user<'c>(
        &self,
        cookie: &mut Cookie<'c>,
        method: &Method,
        headers: &HeaderMap,
        origin_url: &Url,
    ) -> Result<Option<Session>, AuthError> {
        let session_id = if cookie.name() == "auth_session" {
            Some(cookie.value())
        } else {
            None
        };
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
        if error || session_id.is_none() {
            cookie.set_value("");
            cookie.set_expires(OffsetDateTime::UNIX_EPOCH);
            Ok(None)
        } else {
            // SAFETY: session_id is always Some(x) in this branch
            let session = self
                .validate_session(unsafe { session_id.unwrap_unchecked() })
                .await?;
            Ok(Some(session))
        }
    }

    async fn validate_session(&self, session_id: &str) -> Result<Session, AuthError> {
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
            if session.state == "active" {
                Ok(session)
            } else {
                let renewed_session = self.renew_session(&database_session.user_id).await?;
                Ok(renewed_session)
            }
        } else {
            let res = self.adapter.delete_session(session_id).await;
            match res {
                DeleteSessionStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
                DeleteSessionStatus::Ok => Err(AuthError::InvalidSessionId),
            }
        }
    }

    // Circle back to this method when it is used again
    async fn get_session(&self, session_id: &str) -> Result<Session, AuthError> {
        todo!()
    }

    fn validate_database_session(database_session: &SessionData) -> Option<Session> {
        if utils::is_within_expiration(database_session.idle_period_expires_at) {
            let active_key = utils::is_within_expiration(database_session.active_period_expires_at);
            Some(Session {
                state: if active_key { "active" } else { "idle" },
                fresh: false,
                active_period_expires_at: database_session.active_period_expires_at,
                idle_period_expires_at: database_session.idle_period_expires_at,
                session_id: database_session.session_id.clone(),
            })
        } else {
            None
        }
    }

    // Circle back to this method when it is used again
    async fn renew_session(&self, user_id: &UserId) -> Result<Session, AuthError> {
        let (renewed_session, _) = join!(
            self.create_session(user_id),
            self.delete_dead_user_sessions(user_id)
        );
        renewed_session
    }

    async fn get_user(&self, user_id: &UserId) -> Result<User<U>, AuthError> {
        let res = self.adapter.get_user(user_id).await;
        match res {
            ReadUserStatus::DatabaseError(err) => Err(AuthError::DatabaseError(err)),
            ReadUserStatus::Ok(att) => Ok(att),
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
}

impl Session {
    pub fn create_cookie(&self) -> Cookie {
        Cookie::build("auth_session", &self.session_id)
            .same_site(cookie::SameSite::Lax)
            .path("/")
            .http_only(true)
            .secure(true)
            .expires(OffsetDateTime::from_unix_timestamp(self.idle_period_expires_at).unwrap())
            .finish()
    }
}
