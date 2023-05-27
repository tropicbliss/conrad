use crate::{errors::TokenError, Token};
use conrad_core::{
    auth::Authenticator, database::DatabaseAdapter, errors::AuthError, KeyType, NaiveKeyType,
    UserData, UserId,
};
use futures::{stream, StreamExt, TryStreamExt};
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

pub struct IdTokenBuilder<'a, D, U> {
    auth: &'a Authenticator<D, U>,
    name: String,
    expires_in: i64,
    generate_custom_token_id: fn() -> String,
}

impl<'a, D, U> IdTokenBuilder<'a, D, U> {
    pub fn new(auth: &'a Authenticator<D, U>, name: String, expires_in: i64) -> Self {
        Self {
            auth,
            name,
            expires_in,
            generate_custom_token_id: || Uuid::new_v4().to_string(),
        }
    }

    pub fn set_token_id_generator(self, function: fn() -> String) -> Self {
        Self {
            generate_custom_token_id: function,
            ..self
        }
    }

    pub fn build(self) -> IdToken<'a, D, U> {
        IdToken {
            auth: self.auth,
            name: self.name,
            expires_in: self.expires_in,
            generate_custom_token_id: self.generate_custom_token_id,
        }
    }
}

pub struct IdToken<'a, D, U> {
    auth: &'a Authenticator<D, U>,
    name: String,
    expires_in: i64,
    generate_custom_token_id: fn() -> String,
}

impl<'a, D, U> IdToken<'a, D, U>
where
    D: DatabaseAdapter<U>,
    U: Serialize + DeserializeOwned,
{
    pub async fn issue(&self, user_id: UserId) -> Result<Token, TokenError> {
        let token = (self.generate_custom_token_id)();
        let key_type = NaiveKeyType::SingleUse {
            expires_in: self.expires_in.into(),
        };
        let res = self
            .auth
            .create_key(
                user_id,
                UserData {
                    password: None,
                    provider_id: self.name.clone(),
                    provider_user_id: token.clone(),
                },
                &key_type,
            )
            .await;
        match res {
            Err(AuthError::InvalidUserId) => Err(TokenError::InvalidUserId),
            Err(AuthError::DuplicateKeyId) => Err(TokenError::DuplicateToken),
            Err(err) => Err(err.into()),
            Ok(key) => Ok(Token::new(token, key)),
        }
    }

    pub async fn validate(&self, token: String) -> Result<Token, TokenError> {
        let res = self.auth.use_key(&self.name, &token, None).await;
        match res {
            Ok(key) if matches!(key.key_type, KeyType::SingleUse { .. }) => {
                Ok(Token::new(token, key))
            }
            Err(AuthError::ExpiredKey) => Err(TokenError::ExpiredToken),
            Ok(_) | Err(AuthError::InvalidKeyId) => Err(TokenError::InvalidToken),
            Err(err) => Err(err.into()),
        }
    }

    pub async fn invalidate_token(&self, token: &str) -> Result<(), AuthError> {
        self.auth.delete_key(&self.name, token).await
    }

    pub async fn invalidate_all_user_tokens(&self, user_id: &UserId) -> Result<(), AuthError> {
        let res = self.auth.get_all_user_keys(user_id).await;
        let keys = match res {
            Err(AuthError::InvalidUserId) => return Ok(()),
            Err(e) => return Err(e),
            Ok(keys) => keys,
        };
        let target_keys = keys.into_iter().filter(|key| key.provider_id == self.name);
        let res: Result<(), AuthError> = stream::iter(target_keys)
            .map(|key| async move {
                self.auth
                    .delete_key(&key.provider_id, &key.provider_user_id)
                    .await
            })
            .buffer_unordered(10)
            .try_collect()
            .await;
        match res {
            Ok(()) | Err(AuthError::InvalidUserId) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn get_all_user_tokens(&self, user_id: &UserId) -> Result<Vec<Token>, AuthError> {
        let keys = self.auth.get_all_user_keys(user_id).await?;
        let target_keys = keys
            .into_iter()
            .filter_map(|key| {
                if matches!(key.key_type, KeyType::SingleUse { .. }) && key.provider_id == self.name
                {
                    Some(Token::new(key.provider_user_id.clone(), key))
                } else {
                    None
                }
            })
            .collect();
        Ok(target_keys)
    }
}
