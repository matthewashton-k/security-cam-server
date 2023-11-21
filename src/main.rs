mod authentication;

use std::collections::HashMap;
use actix_web::{get, HttpResponse, post, Responder, ResponseError, web, web::ServiceConfig};
use actix_web::http::header::{ContentType, LOCATION};
use shuttle_actix_web::ShuttleActixWeb;
use actix_web::{cookie::Key, App, HttpServer, Error};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{CookieContentSecurity, PersistentSession, SessionMiddlewareBuilder};
use actix_web::cookie::time::Duration;
use actix_web::http::StatusCode;
use actix_web::middleware::{ErrorHandlerResponse, ErrorHandlers};
use log::log;
use security_cam_viewer::errors;
use crate::authentication::validate_session;


#[post("/new_video")]
async fn new_video(session: Session) -> actix_web::Result<impl Responder> {
    validate_session(&session)?; // will return error if the user isnt authenticated

    Ok(
        HttpResponse::Ok().body("Hello World!")
    )}

#[get("/")]
async fn index(session: Session) -> actix_web::Result<impl Responder> {
    validate_session(&session)?; // will return error if the user isnt authenticated
    Ok(
        HttpResponse::Ok().body("Hello World!")
    )
}
#[get("/login")]
pub async fn login_form() -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(include_str!("../login.html"))
}
#[shuttle_runtime::main]
async fn actix_web(
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let key_map: HashMap<String,String> = toml::from_str(include_str!("../Secrets.toml")).unwrap();
    let secret_key = Key::from(key_map.get("KEY").expect("KEY not found in Secrets.toml").as_bytes());

    // (user,pass)
    let admin_creds = (key_map.get("ADMIN_USER").expect("ADMIN_USER not found in Secrets.toml").to_string(),key_map.get("ADMIN_PASS").expect("ADMIN_PASS not found in Secrets.toml").to_string());
    let config = move |cfg: &mut ServiceConfig| {
        //(user,pass)
        cfg.app_data(web::Data::new(admin_creds));

        cfg.service(
            web::scope("")
                .service(index)
                .service(login_form)
                // cookie middleware
                .wrap(
                    ErrorHandlers::new()
                        .default_handler_client(errors::add_error_header)
                        .handler(StatusCode::NOT_FOUND, errors::handle_404)
                )
                .wrap(SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    secret_key.clone(),
                    ).cookie_content_security(CookieContentSecurity::Private)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::weeks(1)))
                    .cookie_name("authenticated".to_owned()).build()
                )
                // on login form submit
                .route("/login",web::post().to(login))
        );

    };
    Ok(config.into())
}



#[derive(serde::Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// data is (user,pass)
/// updates session if the user and pass in the form match data
pub async fn login(session: Session,data: web::Data<(String,String)>, form: web::Form<LoginForm>) -> HttpResponse {
    if form.username == data.0&& form.password == data.1 {
        session.insert("authenticated",true);
        HttpResponse::SeeOther().insert_header((LOCATION,"/")).finish()
    } else {
        session.insert("authenticated",false);
        HttpResponse::SeeOther().insert_header((LOCATION,"/login")).finish()
    }
}

