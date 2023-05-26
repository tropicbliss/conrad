use crate::errors::TokenError;
use conrad_core::{
    auth::Authenticator,
    database::{DatabaseAdapter, Key, KeyTimestamp, KeyType, UserData, UserId},
    errors::AuthError,
};
use uuid::Uuid;

pub struct IdTokenBuilder<'a, D>
where
    D: Clone,
{
    auth: &'a Authenticator<D>,
    name: String,
    expires_in: i64,
    generate_custom_token_id: fn() -> String,
}

impl<'a, D> IdTokenBuilder<'a, D>
where
    D: Clone,
{
    pub fn new(auth: &'a Authenticator<D>, name: String, expires_in: i64) -> Self {
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

    pub fn build(self) -> IdToken<'a, D> {
        IdToken {
            auth: self.auth,
            name: self.name,
            expires_in: self.expires_in,
            generate_custom_token_id: self.generate_custom_token_id,
        }
    }
}

pub struct IdToken<'a, D>
where
    D: Clone,
{
    auth: &'a Authenticator<D>,
    name: String,
    expires_in: i64,
    generate_custom_token_id: fn() -> String,
}

impl<'a, D> IdToken<'a, D>
where
    D: Clone + DatabaseAdapter,
{
    pub async fn issue(&self, user_id: UserId) -> Result<Token, TokenError> {
        let token = (self.generate_custom_token_id)();
        let key_type = KeyType::SingleUse {
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
            Err(err) => Err(TokenError::AuthError(Box::new(err))),
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
            Err(err) => Err(TokenError::AuthError(Box::new(err))),
        }
    }
}

pub struct Token {
    value: String,
    pub user_id: UserId,
    pub expires_at: KeyTimestamp,
}

impl ToString for Token {
    fn to_string(&self) -> String {
        self.value.clone()
    }
}

impl Token {
    fn new(value: String, key: Key) -> Self {
        if let KeyType::SingleUse { expires_in } = key.key_type {
            Self {
                value,
                expires_at: expires_in,
                user_id: key.user_id,
            }
        } else {
            unreachable!()
        }
    }
}
