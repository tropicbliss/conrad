use crate::{
    errors::OAuthError, utils, AuthInfo, OAuthConfig, OAuthProvider, RedirectInfo, ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "patreon";

#[derive(Clone)]
pub struct PatreonConfig {
    base: OAuthConfig,
    redirect_uri: String,
}

impl PatreonConfig {
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

#[derive(Clone)]
pub struct PatreonProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for PatreonProvider {
    type Config = PatreonConfig;
    type UserInfo = PatreonUser;

    fn get_authorization_url(&self) -> RedirectInfo {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("identity".to_string()));
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
            AuthUrl::new("https://www.patreon.com/oauth2/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://www.patreon.com/api/oauth2/token".to_string()).unwrap()),
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
        let mut url = Url::parse("https://www.patreon.com/api/oauth2/v2/identity").unwrap();
        url.query_pairs_mut().append_pair(
            "fields[user]",
            "about,email,full_name,hide_pledges,image_url,is_email_verified,url",
        );
        let provider_user = utils::get_provider_user::<PatreonUser>(
            &self.web_client,
            &tokens.access_token,
            url.as_str(),
        )
        .await?;
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

#[derive(Deserialize, Debug, Clone)]
pub struct PatreonUser {
    pub id: String,
    pub attributes: Attributes,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Attributes {
    pub about: Option<String>,
    pub created: String,
    pub email: Option<String>,
    pub full_name: String,
    pub hide_pledges: Option<bool>,
    pub image_url: String,
    pub is_email_verified: bool,
    pub url: String,
}
