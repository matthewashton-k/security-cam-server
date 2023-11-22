use actix_session::Session;
use actix_web::error::InternalError;
use actix_web::HttpResponse;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use log::{info, log};
use shuttle_secrets::SecretStore;

pub struct AdminSessionInfo {
    pub username: String,
    pub password: String,
    pub hash: String,
}

impl AdminSessionInfo {
    pub fn new(username: String, password: String, ) -> Self {
        let hash = create_hash(&username, &password).unwrap();
        Self {
            username,
            password,
            hash,
        }
    }
}

/// Validates the session and returns the user id if valid.
/// taken f
pub fn validate_session(session: &Session, admin_session_info: &AdminSessionInfo) -> actix_web::Result<(),actix_web::error::Error> {
    return match session.get::<String>("session_id") {
        Ok(Some(hash)) => {
            // the hash of the authenticated user
            info!("hash was read from cookie: {}", hash);
            if let Ok(result) = verify_hash(
                &admin_session_info.username,
                &admin_session_info.password,
                &hash,
            ) {
                info!("hash was verified: {}", result);
                if result {
                    return Ok(());
                }
            }

            // if the stored hash wasnt the right format or the stored hash wasnt verified
            Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
        }
        _ => {
            info!("no hash was found in cookie");
            Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
        }
    }
}


pub fn create_hash(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(format!("{}{}", password, username).as_bytes(), &salt).expect("failed to hash passcode").to_string())
}

pub fn verify_hash(username: &str, password: &str, hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(Argon2::default().verify_password(
        format!("{}{}", password, username,).as_bytes(),
        &PasswordHash::new(hash).map_err(|e| {e.to_string()})?
        ).is_ok()
    )
}