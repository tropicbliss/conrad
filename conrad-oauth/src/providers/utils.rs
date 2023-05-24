use crate::{errors::OAuthError, ExpirationInfo, Tokens};
use oauth2::{basic::BasicClient, reqwest::async_http_client, AuthorizationCode, TokenResponse};
use reqwest::Client;
use serde::de::DeserializeOwned;

pub(crate) async fn get_provider_user<T>(
    web_client: &Client,
    access_token: &str,
    url: &str,
) -> Result<T, OAuthError>
where
    T: DeserializeOwned,
{
    let res = web_client
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| OAuthError::RequestError(Box::new(err)))?
        .json::<T>()
        .await
        .map_err(|err| OAuthError::RequestError(Box::new(err)))?;
    Ok(res)
}

pub(crate) async fn get_tokens_with_expiration(
    client: &BasicClient,
    code: String,
) -> Result<Tokens, OAuthError> {
    let token_result = client
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
