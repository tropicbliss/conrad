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
use serde::{Deserialize, Serialize};
use std::time::Duration;

const PROVIDER_ID: &'static str = "github";

pub struct GitHubProvider {
    client: BasicClient,
    scope: Vec<&'static str>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    type Config = OAuthConfig;
    type UserInfo = GitHubUser;

    fn get_authorization_url(&self) -> RedirectInfo {
        let mut req = self.client.authorize_url(CsrfToken::new_random);
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
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
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
        let provider_user = self.get_provider_user(&tokens.access_token).await?;
        let provider_user_id = provider_user.id.to_string();
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

impl GitHubProvider {
    async fn get_tokens(&self, code: String) -> Result<Tokens, OAuthError> {
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

    async fn get_provider_user(&self, access_token: &str) -> Result<GitHubUser, OAuthError> {
        let res = self
            .web_client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|err| OAuthError::RequestError(Box::new(err)))?
            .json::<GitHubUser>()
            .await
            .map_err(|err| OAuthError::RequestError(Box::new(err)))?;
        Ok(res)
    }
}

#[derive(Deserialize, Serialize)]
pub struct GitHubUser {
    pub login: String,
    pub id: usize,
    pub node_id: String,
    pub avatar_url: String,
    pub gravatar_id: String,
    pub url: String,
    pub html_url: String,
    pub followers_url: String,
    pub following_url: String,
    pub gists_url: String,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub organizations_url: String,
    pub repos_url: String,
    pub events_url: String,
    pub received_events_url: String,
    #[serde(rename = "type")]
    pub account_type: String,
    pub site_admin: String,
    pub name: String,
    pub company: String,
    pub blog: String,
    pub location: String,
    pub email: String,
    pub hireable: bool,
    pub bio: String,
    pub twitter_username: String,
    pub public_repos: usize,
    pub public_gists: usize,
    pub followers: usize,
    pub following: usize,
    pub created_at: String,
    pub updated_at: String,
    pub private_gists: Option<usize>,
    pub total_private_repos: Option<usize>,
    pub owned_private_repos: Option<usize>,
    pub disk_usage: Option<usize>,
    pub collaborators: Option<usize>,
    pub two_factor_authentication: Option<bool>,
    pub plan: Option<Plan>,
}

#[derive(Deserialize, Serialize)]
pub struct Plan {
    pub name: String,
    pub space: usize,
    pub private_repos: usize,
    pub collaborators: usize,
}
