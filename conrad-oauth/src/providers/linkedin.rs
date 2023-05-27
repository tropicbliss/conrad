use crate::{
    errors::OAuthError, utils, AuthInfo, ExpirationInfo, OAuthConfig, OAuthProvider, RedirectInfo,
    Tokens, ValidationResult,
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::{Client, Url};
use serde::Deserialize;
use std::time::Duration;

const PROVIDER_ID: &str = "linkedin";

#[derive(Clone)]
pub struct LinkedinConfig {
    base: OAuthConfig,
    redirect_uri: String,
}

impl LinkedinConfig {
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
pub struct LinkedinProvider {
    client: BasicClient,
    scope: Vec<String>,
    web_client: Client,
}

#[async_trait]
impl OAuthProvider for LinkedinProvider {
    type Config = LinkedinConfig;
    type UserInfo = LinkedinUser;

    fn new(config: Self::Config) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.base.client_id),
            Some(ClientSecret::new(config.base.client_secret)),
            AuthUrl::new("https://www.linkedin.com/oauth/v2/authorization".to_string()).unwrap(),
            Some(
                TokenUrl::new("https://www.linkedin.com/oauth/v2/accessToken".to_string()).unwrap(),
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
        let mut req = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("r_liteprofile".to_string()));
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
        let mut url = Url::parse("https://api.linkedin.com/v2/me").unwrap();
        url.query_pairs_mut()
            .append_pair("projection", "(id,localizedFirstName,localizedLastName,profilePicture(displayImage~:playableStreams))");
        let provider_user = utils::get_provider_user::<RawUser>(
            &self.web_client,
            &tokens.access_token,
            url.as_str(),
        )
        .await?;
        let get_profile_picture = move || {
            provider_user
                .profile_picture
                .display_image?
                .elements?
                .last()
                .cloned()?
                .identifiers?
                .last()
                .cloned()?
                .identifier
        };
        let provider_user = LinkedinUser {
            first_name: provider_user.localized_first_name,
            last_name: provider_user.localized_last_name,
            id: provider_user.id,
            profile_picture: get_profile_picture(),
        };
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

impl LinkedinProvider {
    async fn get_tokens(&self, code: String) -> Result<Tokens, OAuthError> {
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
            scope: Some(
                token_result
                    .scopes()
                    .unwrap()
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUser {
    id: String,
    localized_first_name: String,
    localized_last_name: String,
    profile_picture: ProfilePicture,
}

#[derive(Deserialize)]
struct ProfilePicture {
    #[serde(rename = "displayImage~")]
    display_image: Option<DisplayImage>,
}

#[derive(Deserialize)]
struct DisplayImage {
    elements: Option<Vec<Element>>,
}

#[derive(Deserialize, Clone)]
struct Element {
    identifiers: Option<Vec<Identifier>>,
}

#[derive(Deserialize, Clone)]
struct Identifier {
    identifier: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinkedinUser {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub profile_picture: Option<String>,
}
