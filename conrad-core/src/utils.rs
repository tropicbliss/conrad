use cookie::time::OffsetDateTime;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};

/// Hash password using scrypt
pub async fn hash_password(password: String) -> String {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Scrypt
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string()
    })
    .await
    .unwrap()
}

pub async fn validate_password(password: String, hashed_password: String) -> bool {
    tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&hashed_password).unwrap();
        Scrypt
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .unwrap()
}

/// In milliseconds.
pub fn is_within_expiration(expires: i64) -> bool {
    OffsetDateTime::now_utc() <= OffsetDateTime::from_unix_timestamp(expires).unwrap()
}
