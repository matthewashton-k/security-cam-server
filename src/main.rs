mod authentication;

use std::io::Bytes;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use actix_identity::IdentityMiddleware;
use actix_web::{get, HttpMessage, HttpRequest, HttpResponse, post, Responder, ResponseError, web, web::ServiceConfig};
use actix_web::http::header::{CONNECTION, CONTENT_DISPOSITION, ContentDisposition, ContentType, DispositionType, LOCATION, TRANSFER_ENCODING};
use shuttle_actix_web::ShuttleActixWeb;
use actix_web::{cookie::Key, App, HttpServer, Error};
use actix_session::{Session, SessionMiddleware, storage::CookieSessionStore};
use actix_session::config::{CookieContentSecurity, PersistentSession, SessionMiddlewareBuilder};
use actix_web::cookie::time::Duration;
use actix_identity::Identity;
use actix_web::body::BodyStream;
use handlebars::Handlebars;
use log::{info, log};
use serde_json::json;
use shuttle_runtime::tokio;
use shuttle_runtime::tokio::fs::File;
use shuttle_runtime::tokio::sync::Mutex;
use shuttle_secrets::SecretStore;
use security_cam_viewer::authentication::{verify_hash};
use security_cam_viewer::video::{get_video_paths, save_video};
use crate::authentication::{AdminSessionInfo};
use security_cam_viewer::encryption::*;
use actix_web::http::header::CONTENT_LENGTH;
pub type AppState<'a> = (AdminSessionInfo, Handlebars<'a>);

/// data is (user,pass)
/// updates session if the user and pass in the form match data
pub async fn login(session: Session,data: web::Data<AppState<'_>>, form: web::Form<LoginForm>,request: HttpRequest) -> actix_web::Result<impl Responder> {
    if verify_hash(&form.username, &form.password, &data.0.hash)? {
        log::info!("verified hash");
        Identity::login(&request.extensions(),form.username.clone())?; // log the user in
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

#[get("/login")]
pub async fn login_form() -> impl Responder {
    // returns the login form
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(include_str!("../login.html"))
}
#[get("/logout")]
pub async fn logout(user: Identity) -> impl Responder {
    user.logout();
    HttpResponse::SeeOther().insert_header((LOCATION,"/login")).finish()
}


#[post("/new_video/")]
async fn new_video(bytes: web::Bytes, identity: Option<Identity>) -> actix_web::Result<impl Responder> {
    if let Some(identity) = identity { // if the user is logged in
        save_video(&bytes).await?;
        Ok(
            HttpResponse::Ok().body("SUCCESS")
        )
    } else {
        Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
}

#[get("/assets/{filename}/{password}")]
async fn assets(
    data: web::Data<AppState<'_>>,
    session: Session,
    path: web::Path<(String,String)>,
    identity: Option<Identity>) -> actix_web::Result<impl Responder> {
    let (filename,password) = path.into_inner();
    info!("the password is: {}",password);
    if let Some(identity) = Some(1) {
        info!("the identity was found");
        // let plaintext = decrypt_bytes(&key, salt, &tokio::fs::read(PathBuf::from("assets").join(&path)).await?)?; // decrypt the file?;
        let file = File::open(PathBuf::from("assets").join(&filename)).await?;
        let mut decryptor = EncryptDecrypt {
            key:None,
            salt:None,
            file: file,
        };
        info!("returning stream");
        //Ok::<_, Box<dyn std::error::Error>>(
        Ok(HttpResponse::Ok()
            .content_type("video/mp4")
            .streaming(
                Box::pin(decryptor.decrypt_stream(password.clone()))
            ))

    } else {
        Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
}

#[get("/")]
async fn index(data: web::Data<AppState<'_>>, session: Session, identity: Option<Identity>) -> actix_web::Result<impl Responder> {
    if let Some(identity) = identity {
        let video_paths = get_video_paths().await?;
        let video_paths_json = json!({"files" : video_paths});
        info!("{}",video_paths_json);
        Ok(
            HttpResponse::Ok().body(data.1.render("index",&video_paths_json).unwrap())
        )
    } else {
        Ok(
            HttpResponse::SeeOther().insert_header((LOCATION,"/login")).finish()
        )
    }
}



#[shuttle_runtime::main]
async fn actix_web(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let admin_hash = secret_store.get("ADMIN_HASH").expect("ADMIN_HASH not found");
    let admin_user = secret_store.get("ADMIN_USER").expect("ADMIN_USER not found");
    let key = Key::from(secret_store.get("KEY").unwrap().as_bytes().clone());
    let config = move |cfg: &mut ServiceConfig| {
        // create static site builder

        let mut hbars = Handlebars::new();
        hbars.register_template_file("index","index.html").expect("index.html not found");
        cfg.app_data(web::Data::new((AdminSessionInfo::from(admin_user.clone(), admin_hash.clone()), hbars)));
        cfg.service(
            web::scope("")
                .wrap(IdentityMiddleware::default())
                .service(index)
                .service(login_form)
                .service(logout)
                .service(new_video)
                .service(assets)
                .route("/login",web::post().to(login))
        // cookie middleware
                .wrap(SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    key,
                    ).cookie_content_security(CookieContentSecurity::Private)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::days(1)))
                          .build()
                )
                .default_service(web::to(|| HttpResponse::NotFound()))
        );

    };
    Ok(config.into())
}


/// deserializable struct representing the login form
#[derive(serde::Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}



#[cfg(test)]
mod tests {
    // use aes_gcm::Key;
    // use argon2::password_hash::rand_core::{OsRng, RngCore};
    // use argon2::password_hash::SaltString;
    // use shuttle_runtime::tokio::io::AsyncReadExt;
    // use shuttle_runtime::tokio::runtime::Builder;
    // use crate::encryption::{decrypt_bytes, encrypt_bytes, generate_key};
    //
    // #[test]
    // fn test_generate_key() {
    //     let password = "password123";
    //     let result = generate_key(password);
    //     assert!(result.is_ok());
    // }
    //
    // #[test]
    // fn testt_encrypt_decrypt() {
    //     let password = "password123";
    //     let (key, salt) = generate_key(password).unwrap();
    //
    //     let mut plaintext: Vec<u8> = vec![0;50];
    //     OsRng.fill_bytes(&mut plaintext);
    //
    //     let encrypted = encrypt_bytes(&key, salt.clone(), &plaintext).unwrap();
    //     assert_ne!(encrypted, plaintext);
    //
    //     let decrypted = decrypt_bytes(&key, salt, &encrypted).unwrap();
    //     println!("{:?}", decrypted);
    //     println!("{:?}", plaintext);
    //     assert_eq!(decrypted, plaintext);
    // }

    use actix_web::App;
    use actix_web::cookie::Key;
    use actix_web::web::ServiceConfig;
    use handlebars::Handlebars;
    use actix_web::web::Data;
    use actix_web::web;
    use crate::AdminSessionInfo;
    use actix_identity::IdentityMiddleware;
    use actix_web::HttpResponse;
    use actix_web::cookie::time::Duration;
    use actix_session::config::PersistentSession;
    use actix_session::storage::CookieSessionStore;
    use actix_session::*;
    use crate::*;

    ///to be used for future integration testing
    #[actix_web::test]
    async fn test_encrypt() {
        // the hash of admin and pass
        let admin_hash = "$argon2id$v=19$m=19456,t=2,p=1$7STshatCtAHy3vGgxpFiUQ$QU/EbkQel7B7lIdOeejR2uz6jOTpMWztlruaPkzmjLM".to_string();
        let admin_user = "admin".to_string();
        let key = Key::generate();
        let config = move |cfg: &mut ServiceConfig| {
            // create static site builder

            let mut hbars = Handlebars::new();
            hbars.register_template_file("index","index.html").expect("index.html not found");
            cfg.app_data(web::Data::new((AdminSessionInfo::from(admin_user.clone(), admin_hash.clone()), hbars)));
            cfg.service(
                web::scope("")
                    .wrap(IdentityMiddleware::default())
                    .service(index)
                    .service(login_form)
                    .service(logout)
                    .service(new_video)
                    .service(assets)
                    .route("/login",web::post().to(login))
                    // cookie middleware
                    .wrap(SessionMiddleware::builder(
                        CookieSessionStore::default(),
                        key,
                    ).cookie_content_security(CookieContentSecurity::Private)
                        .session_lifecycle(PersistentSession::default().session_ttl(Duration::days(1)))
                        .build()
                    )
                    .default_service(web::to(|| HttpResponse::NotFound()))
            );

        };
        actix_web::test::init_service(App::new().configure(config));
    }

}

