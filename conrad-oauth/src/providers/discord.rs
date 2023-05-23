use super::utils;
use crate::{
    errors::OAuthError, AuthInfo, ExpirationInfo, OAuthConfig, OAuthProvider, RedirectInfo, Tokens,
    ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "discord";

pub struct DiscordConfig {
    base: OAuthConfig,
    redirect_uri: Url,
}

impl DiscordConfig {
    pub fn new(
        client_id: String,
        client_secret: String,
        scope: Vec<String>,
        redirect_uri: Url,
    ) -> Self {
        let base = OAuthConfig {
            client_id,
            client_secret,
            scope,
        };
        Self { base, redirect_uri }
    }
}

pub struct DiscordProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for DiscordProvider {
    type Config = DiscordConfig;
    type UserInfo = DiscordUser;

    fn new(config: Self::Config) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://discord.com/oauth2/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.to_string()).unwrap());
        let web_client = Client::builder()
            .timeout(Duration::from_secs(9))
            .user_agent("conrad")
            .build()
            .unwrap();
        Self {
            client,
            scope: config.base.scope,
            web_client,
        }
    }

    fn get_authorization_url(&self) -> crate::RedirectInfo {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("identify".to_string()));
        for scope in &self.scope {
            req = req.add_scope(Scope::new(scope.to_string()));
        }
        let info = req.url();
        RedirectInfo {
            url: info.0,
            csrf_token: info.1.secret().to_string(),
        }
    }

    async fn validate_callback(
        &self,
        code: String,
    ) -> Result<ValidationResult<Self::UserInfo>, OAuthError> {
        let tokens = self.get_tokens(code).await?;
        let provider_user = utils::get_provider_user::<RawUser>(
            &self.web_client,
            &tokens.access_token,
            "https://discord.com/api/oauth2/@me",
        )
        .await?
        .user;
        let provider_user_id = provider_user.id.clone();
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

impl DiscordProvider {
    pub async fn get_tokens(&self, code: String) -> Result<Tokens, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .map_err(|err| OAuthError::RequestError(Box::new(err)))?;
        let access_token = token_result.access_token().secret().to_string();
        Ok(Tokens {
            access_token,
            expiration_info: Some(ExpirationInfo {
                refresh_token: token_result.refresh_token().unwrap().secret().to_string(),
                expires_in: token_result.expires_in().unwrap().as_millis() as i64,
            }),
        })
    }
}

#[derive(Deserialize)]
struct RawUser {
    user: DiscordUser,
}

#[derive(Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    pub avatar: String,
    pub discriminator: String,
    pub public_flags: usize,
}
