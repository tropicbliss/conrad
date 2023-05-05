use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Scrypt,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// Hash password using scrypt
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Scrypt
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

/// In milliseconds.
pub fn is_within_expiration(expires: u64) -> bool {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    current_time <= expires
}
