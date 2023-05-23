pub mod errors;
pub mod providers;

use async_trait::async_trait;
use conrad_core::{
    auth::Authenticator,
    database::{DatabaseAdapter, Key, KeyType, User, UserData, UserId},
    errors::AuthError,
};
use errors::OAuthError;
use oauth2::url::Url;

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

pub struct RedirectInfo {
    pub url: Url,
    pub csrf_token: String,
}

pub struct ValidationResult<T> {
    pub tokens: Tokens,
    pub provider_user: T,
    pub auth_info: AuthInfo,
}

pub struct AuthInfo {
    provider_id: &'static str,
    provider_user_id: String,
}

impl AuthInfo {
    pub fn into_auth_connector<D>(self, auth: &Authenticator<D>) -> AuthConnector<D>
    where
        D: Clone,
    {
        AuthConnector {
            auth_info: self,
            authenticator: auth,
        }
    }
}

pub struct AuthConnector<'a, D>
where
    D: Clone,
{
    auth_info: AuthInfo,
    authenticator: &'a Authenticator<D>,
}

impl<'a, D> AuthConnector<'a, D>
where
    D: Clone + DatabaseAdapter,
{
    pub async fn get_existing_user(&self) -> Result<Option<D::UserAttributes>, AuthError> {
        let res = {
            let key = self
                .authenticator
                .use_key(
                    self.auth_info.provider_id,
                    &self.auth_info.provider_user_id,
                    None,
                )
                .await?;
            self.authenticator.get_user(&key.user_id).await
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
        self.authenticator
            .create_key(user_id, user_data, &KeyType::Persistent)
            .await
    }

    pub async fn create_user(
        &self,
        attributes: D::UserAttributes,
    ) -> Result<User<D::UserAttributes>, AuthError> {
        let user_data = UserData::new(
            self.auth_info.provider_id.to_string(),
            self.auth_info.provider_user_id.clone(),
            None,
        );
        self.authenticator.create_user(user_data, attributes).await
    }
}

pub struct Tokens {
    pub access_token: String,
    pub expiration_info: Option<ExpirationInfo>,
}

pub struct ExpirationInfo {
    pub refresh_token: String,
    pub expires_in: i64,
}
