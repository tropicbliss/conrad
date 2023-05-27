use conrad_core::{Key, KeyTimestamp, KeyType, UserId};

pub mod errors;
pub mod id_tokens;
pub mod password_tokens;

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
