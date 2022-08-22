use std::error::Error;
use argon2::{Algorithm, Version};
use argon2::{password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
}, Argon2, Params};
use lazy_static::lazy_static;


lazy_static! {
    /// # Config
    /// - Algorithm chosen: **Argon2id**
    /// - Version chosen: **19**
    /// - Memory cost chosen: **64 KiB**
    /// - Number of passes chosen: **3**
    /// - Number of lanes chosen: **4**
    /// - Output length chosen: **64 B**
    static ref ARGON2: Argon2<'static> = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 4, Some(64)).unwrap()
    );
}

/// Hash a password with Argon 2id based on the server config
///
/// # Error
/// If the hashing failed.
pub fn hash_password(password: &str) -> Result<String, Box<dyn Error>> {
    // Hash password
    match ARGON2.hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng)) {
        Ok(h) => Ok(h.to_string()),
        Err(_) => Err("Hashing password failed")?
    }
}

/// Verify a password and the corresponding hash
///
/// # Error
/// If the parsing of the hash failed
pub fn verify_password(password: &str, hash: &str) -> Result<bool, Box<dyn Error>> {
    match PasswordHash::new(hash) {
        Ok(pwd_hash) => Ok(ARGON2.verify_password(password.as_ref(), &pwd_hash).is_ok()),
        Err(_) => Err("Failed to parse hash")?
    }
}
