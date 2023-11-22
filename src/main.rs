mod authentication;

use std::io::Bytes;
use std::path::PathBuf;
use actix_web::{get, HttpRequest, HttpResponse, post, Responder, ResponseError, web, web::ServiceConfig};
use actix_web::http::header::{ContentDisposition, ContentType, DispositionType, LOCATION};
use shuttle_actix_web::ShuttleActixWeb;
use actix_web::{cookie::Key, App, HttpServer, Error};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{CookieContentSecurity, PersistentSession, SessionMiddlewareBuilder};
use actix_web::cookie::time::Duration;
use actix_web::error::ErrorInternalServerError;
use actix_web::web::to;
use handlebars::Handlebars;
use log::{info, log};
use serde_json::json;
use shuttle_secrets::SecretStore;
use tokio::fs;
use security_cam_viewer::authentication::verify_hash;
use security_cam_viewer::video::{get_video_paths, save_video};
use uuid::uuid;
use crate::authentication::{AdminSessionInfo, create_hash, validate_session};
pub type AppState<'a> = (AdminSessionInfo,Handlebars<'a>);



#[post("/new_video")]
async fn new_video(data: web::Data<AppState<'_>>, session: Session, bytes: web::Bytes) -> actix_web::Result<impl Responder> {
    validate_session(&session,&data.0).await?; // will return error if the user isnt authenticated
    save_video(&bytes).await?;
    Ok(
        HttpResponse::Ok().body("SUCCESS")
    )
}

#[get("/assets/{filename}")]
async fn assets(req: HttpRequest,data: web::Data<AppState<'_>>, session: Session, filename: web::Path<String>) -> actix_web::Result<impl Responder> {
    validate_session(&session,&data.0).await?; // will return error if the user isnt authenticated
    let path: std::path::PathBuf = req.match_info().query("filename").parse::<PathBuf>().unwrap().canonicalize()?;
    let file = actix_files::NamedFile::open(PathBuf::from("assets").join(&path))?;
    info!("the path: {}",PathBuf::from("assets").join(&path).to_str().unwrap());
    Ok(file)
}

#[get("/")]
async fn index(data: web::Data<AppState<'_>>, session: Session) -> actix_web::Result<impl Responder> {
    validate_session(&session,&data.0).await?; // will return error if the user isnt authenticated
    let video_paths = get_video_paths().await?;
    let video_paths_json = json!({"files" : video_paths});
    info!("{}",video_paths_json);
    let body = data.1.render("index",&video_paths_json).unwrap();
    info!("{}",body);
    Ok(
        HttpResponse::Ok().body(data.1.render("index",&video_paths_json).unwrap())
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
    session.remove("session_id").unwrap();
    HttpResponse::SeeOther().insert_header((LOCATION,"/login")).finish()
}

#[shuttle_runtime::main]
async fn actix_web(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let config = move |cfg: &mut ServiceConfig| {

        let admin_user = secret_store.get("ADMIN_USER").expect("no ADMIN_USER in Secrets.toml");
        let admin_pass = secret_store.get("ADMIN_PASS").expect("no ADMIN_PASS in Secrets.toml");
        // generate valid hash
        let admin_hash = create_hash(
            &admin_user,
            &admin_pass,
        ).expect("failed to create hash for admin credentials");

        // admin session info
        let admin_session_info = AdminSessionInfo::new(admin_user,admin_pass);

        // create static site builder
        let mut hbars = Handlebars::new();
        hbars.register_template_file("index","index.html").unwrap();
        cfg.app_data(web::Data::new((admin_session_info, hbars)));
        cfg.service(
            web::scope("")
                .service(index)
                .service(login_form)
                .service(logout)
                .service(new_video)
                .service(assets)
                .route("/login",web::post().to(login))
        // cookie middleware
                .wrap(SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    Key::from(secret_store.get("KEY").unwrap().as_bytes().clone()),
                    ).cookie_content_security(CookieContentSecurity::Private)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::weeks(1)))
                          .build()// .cookie_name("authenticated".to_owned()).build()
                )
                .default_service(web::to(|| HttpResponse::NotFound()))
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
pub async fn login(session: Session,data: web::Data<AppState<'_>>, form: web::Form<LoginForm>) -> actix_web::Result<impl Responder> {
    if verify_hash(&form.username, &form.password, &data.0.hash)? {
        log::info!("verified hash");
        session.insert("session_id", create_hash(&form.username,&form.password)?)?;
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, "/"))
            .finish());
    } else {
        info!("couldnt verify hash");
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, "/login"))
            .finish());
    }
}

