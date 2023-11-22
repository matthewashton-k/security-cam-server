mod authentication;

use std::io::Bytes;
use actix_web::{get, HttpResponse, post, Responder, ResponseError, web, web::ServiceConfig};
use actix_web::http::header::{ContentType, LOCATION};
use shuttle_actix_web::ShuttleActixWeb;
use actix_web::{cookie::Key, App, HttpServer, Error};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{CookieContentSecurity, PersistentSession, SessionMiddlewareBuilder};
use actix_web::cookie::time::Duration;
use shuttle_secrets::SecretStore;
use security_cam_viewer::video::save_video;
use crate::authentication::validate_session;

#[post("/new_video")]
async fn new_video(session: Session, bytes: web::Bytes) -> actix_web::Result<impl Responder> {
    validate_session(&session)?; // will return error if the user isnt authenticated
    save_video(&bytes).await?;
    Ok(
        HttpResponse::Ok().body("SUCCESS")
    )
}

#[get("/")]
async fn index(session: Session) -> actix_web::Result<impl Responder> {
    validate_session(&session)?; // will return error if the user isnt authenticated
    Ok(
        HttpResponse::Ok().body(include_str!("../index.html"))
    )
}
#[get("/login")]
pub async fn login_form() -> impl Responder {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(include_str!("../login.html"))
}
#[get("/logout")]
pub async fn logout(session: Session) -> impl Responder {
    session.remove("authenticated").unwrap();
    log::info!("session: {:?}", session.get::<bool>("authenticated"));
    HttpResponse::SeeOther().insert_header((LOCATION,"/login")).finish()
}
#[shuttle_runtime::main]
async fn actix_web(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let config = move |cfg: &mut ServiceConfig| {
        //(user,pass)
        cfg.app_data(web::Data::new((secret_store.get("ADMIN_USER").expect("no ADMIN_USER in Secrets.toml"), secret_store.get("ADMIN_PASS").expect("no ADMIN_PASS in Secrets.toml"))));
        cfg.default_service(web::to(|| HttpResponse::NotFound()));
        cfg.service(
            web::scope("")
                .service(index)
                .service(login_form)
                .service(logout)
                // cookie middleware
                .wrap(SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    Key::from(secret_store.get("KEY").unwrap().as_bytes().clone()),
                    ).cookie_content_security(CookieContentSecurity::Private)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::weeks(1)))
                          .build()// .cookie_name("authenticated".to_owned()).build()
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

