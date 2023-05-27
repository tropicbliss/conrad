use crate::{errors::TokenError, Token};
use conrad_core::{
    auth::Authenticator, database::DatabaseAdapter, errors::AuthError, KeyType, NaiveKeyType,
    UserData, UserId,
};
use futures::{stream, StreamExt, TryStreamExt};
use rand::{distributions::Uniform, Rng};

pub struct PasswordTokenBuilder<'a, D>
where
    D: Clone,
{
    auth: &'a Authenticator<D>,
    name: String,
    expires_in: i64,
    generate_custom_token_id: fn(usize) -> String,
    password_len: usize,
}

impl<'a, D> PasswordTokenBuilder<'a, D>
where
    D: Clone,
{
    pub fn new(auth: &'a Authenticator<D>, name: String, expires_in: i64) -> Self {
        Self {
            auth,
            name,
            expires_in,
            generate_custom_token_id: |len: usize| {
                rand::thread_rng()
                    .sample_iter(Uniform::new_inclusive(0, 9))
                    .take(len)
                    .map(char::from)
                    .collect()
            },
            password_len: 8,
        }
    }

    pub fn set_password_generator(self, function: fn(usize) -> String) -> Self {
        Self {
            generate_custom_token_id: function,
            ..self
        }
    }

    pub fn set_password_length(self, len: usize) -> Self {
        Self {
            password_len: len,
            ..self
        }
    }

    pub fn build(self) -> PasswordToken<'a, D> {
        PasswordToken {
            auth: self.auth,
            name: self.name,
            expires_in: self.expires_in,
            generate_custom_token_id: self.generate_custom_token_id,
            password_len: self.password_len,
        }
    }
}

pub struct PasswordToken<'a, D>
where
    D: Clone,
{
    auth: &'a Authenticator<D>,
    name: String,
    expires_in: i64,
    generate_custom_token_id: fn(usize) -> String,
    password_len: usize,
}

impl<'a, D> PasswordToken<'a, D>
where
    D: Clone + DatabaseAdapter,
{
    pub async fn issue(&self, user_id: UserId) -> Result<Token, TokenError> {
        let token = (self.generate_custom_token_id)(self.password_len);
        let provider_user_id = format!("{}.{}", user_id.as_str(), token);
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
                    provider_user_id,
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

    pub async fn validate(&self, token: String, user_id: &UserId) -> Result<Token, TokenError> {
        let provider_user_id = format!("{}.{}", user_id.as_str(), token);
        let res = self.auth.use_key(&self.name, &provider_user_id, None).await;
        match res {
            Ok(key) if matches!(key.key_type, KeyType::SingleUse { .. }) => {
                Ok(Token::new(token, key))
            }
            Err(AuthError::ExpiredKey) => Err(TokenError::ExpiredToken),
            Ok(_) | Err(AuthError::InvalidKeyId) => Err(TokenError::InvalidToken),
            Err(err) => Err(err.into()),
        }
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
            .buffer_unordered(3)
            .try_collect()
            .await;
        match res {
            Ok(()) | Err(AuthError::InvalidUserId) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub async fn get_all_user_tokens(&self, user_id: &UserId) -> Result<Vec<Token>, TokenError> {
        let res = self.auth.get_all_user_keys(user_id).await;
        let keys = match res {
            Ok(keys) => keys,
            Err(AuthError::InvalidUserId) => return Err(TokenError::InvalidUserId),
            Err(err) => return Err(err.into()),
        };
        let target_keys = keys
            .into_iter()
            .filter_map(|key| {
                if key.provider_user_id.contains('.')
                    && matches!(key.key_type, KeyType::SingleUse { .. })
                    && key.provider_id == self.name
                {
                    let (_, token) = key.provider_user_id.split_once('.').unwrap();
                    Some(Token::new(token.to_string(), key))
                } else {
                    None
                }
            })
            .collect();
        Ok(target_keys)
    }
}
