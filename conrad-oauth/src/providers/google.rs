use super::utils;
use crate::{
    errors::OAuthError, AuthInfo, ExpirationInfo, OAuthConfig, OAuthProvider, RedirectInfo, Tokens,
    ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, Scope, TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "google";

pub struct GoogleProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    type Config = OAuthConfig;
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
            ClientId::new(config.client_id),
            Some(ClientSecret::new(config.client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
        );
        let web_client = Client::builder()
            .timeout(Duration::from_secs(9))
            .user_agent("conrad")
            .build()
            .unwrap();
        Self {
            client,
            scope: config.scope,
            web_client,
        }
    }

    async fn validate_callback(
        &self,
        code: String,
    ) -> Result<ValidationResult<Self::UserInfo>, OAuthError> {
        let tokens = self.get_tokens(code).await?;
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

impl GoogleProvider {
    pub async fn get_tokens(&self, code: String) -> Result<Tokens, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .map_err(|err| OAuthError::RequestError(Box::new(err)))?;
        let access_token = token_result.access_token().secret().to_string();
        Ok(if let Some(expires_in) = token_result.expires_in() {
            Tokens {
                access_token,
                expiration_info: Some(ExpirationInfo {
                    refresh_token: token_result.refresh_token().unwrap().secret().to_string(),
                    expires_in: expires_in.as_millis() as i64,
                }),
            }
        } else {
            Tokens {
                access_token,
                expiration_info: None,
            }
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
