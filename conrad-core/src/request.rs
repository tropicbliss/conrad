use crate::{
    auth::{self, Authenticator},
    database::DatabaseAdapter,
    errors::AuthError,
    Session, ValidationSuccess,
};
use cookie::CookieJar;
use http::{HeaderMap, Method};
use url::Url;

pub struct Request<'a, D, U> {
    auth: &'a Authenticator<D, U>,
    stored_session_id: Option<String>,
    validated_user: Option<ValidationSuccess<U>>,
}

impl<'a, D, U> Request<'a, D, U>
where
    D: DatabaseAdapter<U>,
{
    pub(crate) fn new(
        auth: &'a Authenticator<D, U>,
        cookies: &CookieJar,
        method: &Method,
        headers: &HeaderMap,
        origin_url: &Url,
    ) -> Self {
        Self {
            stored_session_id: auth::parse_request_headers(cookies, method, headers, origin_url)
                .map(|session_id| session_id.to_string()),
            auth,
            validated_user: None,
        }
    }

    pub fn set_session(&mut self, cookies: &mut CookieJar, session: Option<Session>) {
        let session_id = session.clone().map(|s| s.session_id);
        if self.stored_session_id == session_id {
            return;
        }
        self.validated_user = None;
        self.set_session_cookie(cookies, session);
    }

    fn set_session_cookie(&mut self, cookies: &mut CookieJar, session: Option<Session>) {
        let session_id = session.clone().map(|s| s.session_id);
        if self.stored_session_id == session_id {
            return;
        }
        self.stored_session_id = session_id;
        let cookie = auth::create_session_cookie(session);
        cookies.add(cookie);
    }
}

impl<'a, D, U> Request<'a, D, U>
where
    D: DatabaseAdapter<U>,
    U: Clone,
{
    pub async fn validate_user(
        &mut self,
        cookies: &mut CookieJar,
    ) -> Result<Option<ValidationSuccess<U>>, AuthError> {
        if let Some(validated_user) = &self.validated_user {
            return Ok(Some(validated_user.clone()));
        }
        match &self.stored_session_id {
            Some(stored_session_id) => {
                let res = self.auth.validate_session_user(stored_session_id).await;
                let info = match res {
                    Ok(info) => info,
                    Err(_) => {
                        self.set_session_cookie(cookies, None);
                        return Ok(None);
                    }
                };
                if info.session.fresh {
                    self.set_session_cookie(cookies, Some(info.session.clone()));
                }
                Ok(Some(info))
            }
            None => {
                self.set_session_cookie(cookies, None);
                Ok(None)
            }
        }
    }
}
