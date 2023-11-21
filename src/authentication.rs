use actix_session::Session;
use actix_web::HttpResponse;

/// Validates the session and returns the user id if valid.
/// taken f
pub fn validate_session(session: &Session) -> Result<i64, HttpResponse> {
    let user_id: Option<i64> = session.get("id").unwrap_or(None);

    match user_id {
        Some(id) => {
            session.renew(); // renew session
            Ok(id)
        }
        None => Err(HttpResponse::Unauthorized().json("Unauthorized")),
    }
}