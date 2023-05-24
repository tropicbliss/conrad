use super::utils;
use crate::{
    errors::OAuthError, AuthInfo, OAuthConfig, OAuthProvider, RedirectInfo, ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client,
};
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "twitch";

#[derive(Clone)]
pub struct TwitchConfig {
    base: OAuthConfig,
    redirect_uri: String,
    force_verify: bool,
}

impl TwitchConfig {
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
        Self {
            base,
            redirect_uri,
            force_verify: false,
        }
    }

    pub fn set_force_verify(self, force_verify: bool) -> Self {
        Self {
            force_verify,
            ..self
        }
    }
}

#[derive(Clone)]
pub struct TwitchProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
    force_verify: bool,
}

#[async_trait]
impl OAuthProvider for TwitchProvider {
    type Config = TwitchConfig;
    type UserInfo = TwitchUser;

    fn new(config: Self::Config) -> Self {
        let mut headers = HeaderMap::new();
        let mut client_id = HeaderValue::from_str(&config.base.client_id).unwrap();
        client_id.set_sensitive(true);
        headers.insert("Client-ID", client_id);
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://id.twitch.tv/oauth2/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://id.twitch.tv/oauth2/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.to_string()).unwrap());
        let web_client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("conrad")
            .default_headers(headers)
            .build()
            .unwrap();
        Self {
            client,
            scope: config.base.scope,
            web_client,
            force_verify: config.force_verify,
        }
    }

    fn get_authorization_url(&self) -> crate::RedirectInfo {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_extra_param("force_verify", self.force_verify.to_string());
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
        let tokens = utils::get_tokens_with_expiration(&self.client, code).await?;
        let provider_user = utils::get_provider_user::<RawUser>(
            &self.web_client,
            &tokens.access_token,
            "https://api.twitch.tv/helix/users",
        )
        .await?
        .data
        .first()
        .cloned()
        .unwrap();
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

#[derive(Deserialize)]
struct RawUser {
    data: Vec<TwitchUser>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TwitchUser {
    pub id: String,
    pub login: String,
    pub display_name: String,
    #[serde(rename = "type")]
    pub user_type: UserType,
    pub broadcaster_type: BroadcasterType,
    pub description: String,
    pub profile_image_url: String,
    pub offline_image_url: String,
    pub view_count: usize,
    pub email: Option<String>,
    pub created_at: String,
}

#[derive(Deserialize, Clone, Debug)]
pub enum UserType {
    #[serde(rename = "")]
    Others,
    #[serde(rename = "admin")]
    Admin,
    #[serde(rename = "staff")]
    Staff,
    #[serde(rename = "global_mod")]
    GlobalModerator,
}

#[derive(Deserialize, Clone, Debug)]
pub enum BroadcasterType {
    #[serde(rename = "")]
    Others,
    #[serde(rename = "affiliate")]
    Affiliate,
    #[serde(rename = "partner")]
    Partner,
}
