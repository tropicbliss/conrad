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

const PROVIDER_ID: &str = "auth0";

pub struct Auth0Config {
    base: OAuthConfig,
    app_domain: String,
    redirect_uri: String,
    connection: Option<String>,
    organization: Option<String>,
    invitation: Option<String>,
    login_hint: Option<String>,
}

impl Auth0Config {
    pub fn new(
        client_id: String,
        client_secret: String,
        scope: Vec<String>,
        redirect_uri: String,
        app_domain: String,
    ) -> Self {
        let base = OAuthConfig {
            client_id,
            client_secret,
            scope,
        };
        Self {
            base,
            redirect_uri,
            app_domain,
            connection: None,
            organization: None,
            invitation: None,
            login_hint: None,
        }
    }

    pub fn set_connection(self, connection: String) -> Self {
        Self {
            connection: Some(connection),
            ..self
        }
    }

    pub fn set_organization(self, organization: String) -> Self {
        Self {
            organization: Some(organization),
            ..self
        }
    }

    pub fn set_invitation(self, invitation: String) -> Self {
        Self {
            invitation: Some(invitation),
            ..self
        }
    }

    pub fn set_login_hint(self, login_hint: String) -> Self {
        Self {
            login_hint: Some(login_hint),
            ..self
        }
    }
}

pub struct Auth0Provider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
    app_domain: String,
    connection: Option<String>,
    organization: Option<String>,
    invitation: Option<String>,
    login_hint: Option<String>,
}

#[async_trait]
impl OAuthProvider for Auth0Provider {
    type Config = Auth0Config;
    type UserInfo = Auth0User;

    fn new(config: Self::Config) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new(format!("{}{}", config.app_domain, "/authorize")).unwrap(),
            Some(TokenUrl::new(format!("{}{}", config.app_domain, "/oauth/token")).unwrap()),
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
            app_domain: config.app_domain,
            connection: config.connection,
            invitation: config.invitation,
            login_hint: config.login_hint,
            organization: config.organization,
        }
    }

    fn get_authorization_url(&self) -> crate::RedirectInfo {
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()));
        if let Some(connection) = &self.connection {
            req = req.add_extra_param("connection", connection);
        }
        if let Some(invitation) = &self.invitation {
            req = req.add_extra_param("invitation", invitation);
        }
        if let Some(login_hint) = &self.login_hint {
            req = req.add_extra_param("login_hint", login_hint);
        }
        if let Some(organization) = &self.organization {
            req = req.add_extra_param("organization", organization);
        }
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
        let mut provider_user = utils::get_provider_user::<Auth0User>(
            &self.web_client,
            &tokens.access_token,
            &format!("{}{}", self.app_domain, "/userinfo"),
        )
        .await?;
        provider_user.id = provider_user.id.split_once('|').unwrap().1.to_string();
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
pub struct Auth0User {
    #[serde(rename = "sub")]
    pub id: String,
    pub nickname: String,
    pub name: String,
    pub picture: String,
    pub updated_at: String,
}
