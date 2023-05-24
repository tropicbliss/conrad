use super::utils;
use crate::{
    errors::OAuthError, AuthInfo, OAuthConfig, OAuthProvider, RedirectInfo, ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "google";

pub struct GoogleConfig {
    base: OAuthConfig,
    redirect_uri: String,
}

impl GoogleConfig {
    pub fn new(
        client_id: String,
        client_secret: String,
        scope: Vec<String>,
        redirect_uri: String,
    ) -> Self {
        let base = OAuthConfig {
            client_id,
            client_secret,
            scope,
        };
        Self { base, redirect_uri }
    }
}

pub struct GoogleProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    type Config = GoogleConfig;
    type UserInfo = GoogleUser;

    fn get_authorization_url(&self) -> RedirectInfo {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ));
        for scope in &self.scope {
            req = req.add_scope(Scope::new(scope.to_string()));
        }
        let info = req.url();
        RedirectInfo {
            url: info.0,
            csrf_token: info.1.secret().to_string(),
        }
    }

    fn new(config: Self::Config) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri).unwrap());
        let web_client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("conrad")
            .build()
            .unwrap();
        Self {
            client,
            scope: config.base.scope,
            web_client,
        }
    }

    async fn validate_callback(
        &self,
        code: String,
    ) -> Result<ValidationResult<Self::UserInfo>, OAuthError> {
        let tokens = utils::get_tokens_with_expiration(&self.client, code).await?;
        let provider_user = utils::get_provider_user::<GoogleUser>(
            &self.web_client,
            &tokens.access_token,
            "https://www.googleapis.com/oauth2/v3/userinfo",
        )
        .await?;
        let provider_user_id = provider_user.sub.clone();
        Ok(ValidationResult {
            tokens,
            provider_user,
            auth_info: AuthInfo {
                provider_id: PROVIDER_ID,
                provider_user_id,
            },
        })
    }
}

#[derive(Deserialize)]
pub struct GoogleUser {
    pub sub: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub picture: String,
    pub email: String,
    pub email_verified: bool,
    pub locale: String,
    pub hd: String,
}
