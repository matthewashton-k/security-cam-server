use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
const BUFFER_LEN: usize = 500;
/// passed to app_data and used by the login function to verify login attempts
pub struct AdminSessionInfo {
    pub username: String,
    pub hash: String,
}

impl AdminSessionInfo {
    pub fn from(username: String, hash: String) -> Self {
        Self {
            username,
            hash,
        }
    }
}

/// obsolete function after adopting actix-identity
// pub async fn validate_session(session: &Session, admin_session_info: &SessionInfo) -> actix_web::Result<(),actix_web::error::Error> {
//     return match session.get::<String>("session_id") {
//         Ok(Some(hash)) => {
//             // the hash of the authenticated user
//             info!("hash was read from cookie: {}", hash);
//             if let Ok(result) = verify_hash(
//                 &admin_session_info.username,
//                 &admin_session_info.password,
//                 &hash,
//             ) {
//                 info!("hash was verified: {}", result);
//                 if result {
//                     return Ok(());
//                 }
//             }
//
//             // if the stored hash wasnt the right format or the stored hash wasnt verified
//             Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
//         }
//         _ => {
//             info!("no hash was found in cookie");
//             Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
//         }
//     }
// }

/// creates a salted argon2 hash of the password and username concatenated together
pub fn create_hash(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(format!("{}{}", password, username).as_bytes(), &salt).expect("failed to hash passcode").to_string())
}

/// verifies that a hash created with create_hash is valid for the given username and password
pub fn verify_hash(username: &str, password: &str, hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(Argon2::default().verify_password(
        format!("{}{}", password, username,).as_bytes(),
        &PasswordHash::new(hash).map_err(|e| {e.to_string()})?
        ).is_ok()
    )
}





#[cfg(test)]
mod tests {
    use argon2::password_hash::rand_core::RngCore;
    use super::*;
    #[test]
    fn test_hash_and_verify() {
        let username = "test_user";
        let password = "test_password";

        // Test create_hash function
        let hash = create_hash(username, password).unwrap();
        assert!(!hash.is_empty(), "Hash should not be empty");

        // Test verify_hash function
        let is_valid = verify_hash(username, password, &hash).unwrap();
        assert!(is_valid, "Hash should be valid for the given username and password");

        // Test verify_hash function with wrong password
        let is_valid = verify_hash(username, "wrong_password", &hash).unwrap();
        assert!(!is_valid, "Hash should be invalid for the wrong password");
    }


}
