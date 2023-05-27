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

const PROVIDER_ID: &str = "facebook";

#[derive(Clone)]
pub struct FacebookConfig {
    base: OAuthConfig,
    redirect_uri: String,
}

impl FacebookConfig {
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
pub struct FacebookProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for FacebookProvider {
    type Config = FacebookConfig;
    type UserInfo = FacebookUser;

    fn new(config: Self::Config) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://www.facebook.com/v16.0/dialog/oauth".to_string()).unwrap(),
            Some(
                TokenUrl::new("https://graph.facebook.com/v16.0/oauth/access_token".to_string())
                    .unwrap(),
            ),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_uri.to_string()).unwrap());
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

    fn get_authorization_url(&self) -> crate::RedirectInfo {
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

    async fn validate_callback(
        &self,
        code: String,
    ) -> Result<ValidationResult<Self::UserInfo>, OAuthError> {
        let tokens = utils::get_tokens_with_expiration(&self.client, code).await?;
        let mut url = Url::parse("https://graph.facebook.com/me").unwrap();
        url.query_pairs_mut()
            .append_pair("access_token", &tokens.access_token)
            .append_pair("fields", &["id", "name", "picture"].join(","));
        let provider_user = utils::get_provider_user::<FacebookUser>(
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
pub struct FacebookUser {
    pub id: String,
    pub name: String,
    pub picture: String,
}
