use crate::{
    errors::OAuthError, utils, AuthInfo, ExpirationInfo, OAuthConfig, OAuthProvider, RedirectInfo,
    Tokens, ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "github";

#[derive(Clone)]
pub struct GithubConfig {
    base: OAuthConfig,
    redirect_uri: Option<String>,
}

impl GithubConfig {
    pub fn new(client_id: String, client_secret: String, scope: Vec<String>) -> Self {
        let base = OAuthConfig {
            client_id,
            client_secret,
            scope,
        };
        Self {
            base,
            redirect_uri: None,
        }
    }

    pub fn set_redirect_uri(self, redirect_uri: String) -> Self {
        Self {
            redirect_uri: Some(redirect_uri),
            ..self
        }
    }
}

#[derive(Clone)]
pub struct GitHubProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    type Config = GithubConfig;
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
        let mut client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
        );
        if let Some(redirect_uri) = config.redirect_uri {
            client = client.set_redirect_uri(RedirectUrl::new(redirect_uri).unwrap());
        }
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
        let tokens = self.get_tokens(code).await?;
        let provider_user = utils::get_provider_user::<GitHubUser>(
            &self.web_client,
            &tokens.access_token,
            "https://api.github.com/user",
        )
        .await?;
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
                scope: None,
            }
        } else {
            Tokens {
                access_token,
                expiration_info: None,
                scope: None,
            }
        })
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct GitHubUser {
    pub login: String,
    pub id: i64,
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
    pub public_repos: i64,
    pub public_gists: i64,
    pub followers: i64,
    pub following: i64,
    pub created_at: String,
    pub updated_at: String,
    pub private_gists: Option<i64>,
    pub total_private_repos: Option<i64>,
    pub owned_private_repos: Option<i64>,
    pub disk_usage: Option<i64>,
    pub collaborators: Option<i64>,
    pub two_factor_authentication: Option<bool>,
    pub plan: Option<Plan>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Plan {
    pub name: String,
    pub space: i64,
    pub private_repos: i64,
    pub collaborators: i64,
}
