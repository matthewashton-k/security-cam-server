use actix_session::Session;
use actix_web::error::InternalError;
use actix_web::HttpResponse;

/// Validates the session and returns the user id if valid.
/// taken f
pub fn validate_session(session: &Session) -> actix_web::Result<(),actix_web::error::Error> {
    if session.get::<bool>("authenticated").unwrap().is_none() {
        return Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
    if !(session.get::<bool>("authenticated").unwrap().unwrap()) {
        // return Err(InternalError::from_response("", HttpResponse::Unauthorized().finish()).into());
        return Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    } else {
        return Ok(());
    }
}