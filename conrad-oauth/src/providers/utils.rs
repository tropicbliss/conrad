use crate::errors::OAuthError;
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
