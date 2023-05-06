use cookie::time::OffsetDateTime;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Scrypt,
};

/// Hash password using scrypt
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Scrypt
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

/// In milliseconds.
pub fn is_within_expiration(expires: i64) -> bool {
    OffsetDateTime::now_utc() <= OffsetDateTime::from_unix_timestamp(expires).unwrap()
}
