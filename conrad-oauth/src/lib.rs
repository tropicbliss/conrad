use async_trait::async_trait;
use conrad_core::{
    auth::Authenticator, database::DatabaseAdapter, errors::AuthError, Key, NaiveKeyType, User,
    UserData, UserId,
};
use errors::OAuthError;
use oauth2::url::Url;
use serde::{de::DeserializeOwned, Serialize};

pub mod errors;
pub mod providers;
mod utils;

#[derive(Clone)]
pub struct OAuthConfig {
    client_id: String,
    client_secret: String,
    scope: Vec<String>,
}

impl OAuthConfig {
    pub fn new(client_id: String, client_secret: String, scope: Vec<String>) -> Self {
        Self {
            client_id,
            client_secret,
            scope,
        }
    }
}

#[async_trait]
pub trait OAuthProvider {
    type Config;
    type UserInfo;

    fn new(config: Self::Config) -> Self;
    fn get_authorization_url(&self) -> RedirectInfo;
    async fn validate_callback(
        &self,
        code: String,
    ) -> Result<ValidationResult<Self::UserInfo>, OAuthError>;
}

#[derive(Clone, Debug)]
pub struct RedirectInfo {
    pub url: Url,
    pub csrf_token: String,
}

#[derive(Clone)]
pub struct ValidationResult<T> {
    pub tokens: Tokens,
    pub provider_user: T,
    pub auth_info: AuthInfo,
}

#[derive(Clone)]
pub struct AuthInfo {
    provider_id: &'static str,
    provider_user_id: String,
}

impl AuthInfo {
    pub fn into_auth_connector<D, U>(self, auth: &Authenticator<D, U>) -> AuthConnector<D, U>
    where
        D: Clone,
    {
        AuthConnector {
            auth_info: self,
            auth,
        }
    }
}

#[derive(Clone)]
pub struct AuthConnector<'a, D, U>
where
    D: Clone,
{
    auth_info: AuthInfo,
    auth: &'a Authenticator<D, U>,
}

impl<'a, D, U> AuthConnector<'a, D, U>
where
    D: Clone + DatabaseAdapter<U>,
    U: Serialize + DeserializeOwned,
{
    pub async fn get_existing_user(&self) -> Result<Option<U>, AuthError> {
        let res = {
            let key = self
                .auth
                .use_key(
                    self.auth_info.provider_id,
                    &self.auth_info.provider_user_id,
                    None,
                )
                .await?;
            self.auth.get_user(&key.user_id).await
        };
        match res {
            Ok(e) => Ok(Some(e)),
            Err(AuthError::InvalidKeyId) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn create_persistent_key(&self, user_id: UserId) -> Result<Key, AuthError> {
        let user_data = UserData::new(
            self.auth_info.provider_id.to_string(),
            self.auth_info.provider_user_id.clone(),
            None,
        );
        self.auth
            .create_key(user_id, user_data, &NaiveKeyType::Persistent)
            .await
    }

    pub async fn create_user(&self, attributes: U) -> Result<User<U>, AuthError> {
        let user_data = UserData::new(
            self.auth_info.provider_id.to_string(),
            self.auth_info.provider_user_id.clone(),
            None,
        );
        self.auth.create_user(user_data, attributes).await
    }
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub expiration_info: Option<ExpirationInfo>,
    pub scope: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ExpirationInfo {
    pub refresh_token: String,
    pub expires_in: i64,
}
