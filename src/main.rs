mod authentication;

use std::collections::HashMap;
use actix_web::{get, HttpResponse, Responder, web, web::ServiceConfig};
use actix_web::http::header::{ContentType, LOCATION};
use shuttle_actix_web::ShuttleActixWeb;
use actix_web::{cookie::Key, App, HttpServer, Error};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{CookieContentSecurity, PersistentSession, SessionMiddlewareBuilder};
use actix_web::cookie::time::Duration;
use log::log;


#[get("/")]
async fn hello_world() -> &'static str {
    "Hello World!"
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
    log::info!("Starting server");
    // (user,pass)
    let admin_creds = (key_map.get("ADMIN_USER").expect("ADMIN_USER not found in Secrets.toml").to_string(),key_map.get("ADMIN_PASS").expect("ADMIN_PASS not found in Secrets.toml").to_string());
    log::info!("read admin creds");
    let config = move |cfg: &mut ServiceConfig| {
        //(user,pass)
        cfg.app_data(web::Data::new(admin_creds));
        cfg.service(
            web::scope("")
                .service(hello_world)
                .service(login_form)
                .wrap(SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    secret_key.clone(),
                    ).cookie_content_security(CookieContentSecurity::Private)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::minutes(5)))
                    .cookie_name("authenticated".to_owned()).build()
                )
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

