mod authentication;

use actix_identity::Identity;
use actix_identity::IdentityMiddleware;
use actix_session::config::{CookieContentSecurity, PersistentSession};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::cookie::time::Duration;
use actix_web::cookie::Key;
use actix_web::http::header::{ContentType, CONTENT_DISPOSITION, LOCATION};
use actix_web::rt;
use actix_web::web::Bytes;
use actix_web::web::Form;
use actix_web::{
    get, post, web, web::ServiceConfig, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use actix_ws::AggregatedMessage;
use handlebars::template::Parameter::Path;
use handlebars::Handlebars;
use log::{info, warn};
use security_cam_common::futures::StreamExt;
use security_cam_common::futures::TryStreamExt;
use serde_json::json;
use shuttle_actix_web::ShuttleActixWeb;
use shuttle_runtime::tokio::fs::remove_file;
use shuttle_runtime::tokio::sync::mpsc::channel;
use shuttle_runtime::SecretStore;
use shuttle_runtime::Secrets;
use std::io::Cursor;
use std::io::{Error, ErrorKind, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;

use shuttle_runtime::tokio::fs::File;

use crate::authentication::AdminSessionInfo;
use security_cam_common::encryption::*;
use security_cam_viewer::authentication::verify_hash;
use security_cam_viewer::video::{
    append_chunk_to_file, delete_video_file, get_video_paths, make_new_video_file,
};
use shuttle_runtime::tokio::io::AsyncWriteExt;

use security_cam_viewer::ffmpeg::execute_ffmpeg;

pub type AppState<'a> = (Mutex<AdminSessionInfo>, Handlebars<'a>);

/// data is (AdminSessionInfo, hbars)
/// updates session if the user and pass in the form match data
pub async fn login(
    _session: Session,
    data: web::Data<AppState<'_>>,
    form: web::Form<LoginForm>,
    request: HttpRequest,
) -> actix_web::Result<impl Responder> {
    if verify_hash(&form.username, &form.password, &data.0.lock().unwrap().hash)? {
        Identity::login(&request.extensions(), form.username.clone())?; // log the user in
        data.0.lock().unwrap().password = Some(form.password.clone()); // TODO: for whatever reason this doesnt work
        _session.insert("password", form.password.clone())?; // but this does
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

#[post("/delete_video")]
pub async fn delete_video(
    form: web::Form<DeleteForm>,
    identity: Option<Identity>,
) -> actix_web::Result<impl Responder> {
    info!("Deleting video.");
    let path = sanitize_video_path(&form.delete)?;
    if let Some(_) = identity {
        delete_video_file(&path).await?;
        return Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, "/"))
            .finish());
    } else {
        warn!("Unauthorized");
        return Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"));
    }
}

fn sanitize_video_path(path: &String) -> Result<String, std::io::Error> {
    let path = std::path::Path::new(path);
    let filename = path
        .file_name()
        .ok_or(Error::new(ErrorKind::NotFound, "file name invalid"))?
        .to_str()
        .ok_or(Error::new(ErrorKind::NotFound, "file name invalid"))?
        .to_string();
    let path = PathBuf::from("assets").join(filename);
    Ok(path.to_string_lossy().to_string())
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
    HttpResponse::SeeOther()
        .insert_header((LOCATION, "/login"))
        .finish()
}

#[post("/upload/{video_num}/{fps}/{frame_size}")]
async fn upload(
    _session: Session,
    mut body: web::Payload,
    data: web::Data<AppState<'_>>,
    path: web::Path<(usize, usize, usize)>,
    identity: Option<Identity>,
    request: HttpRequest,
) -> actix_web::Result<impl Responder> {
    info!("got a new upload");
    if identity.is_none() {
        warn!("unauthorized");
        return Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"));
    }
    let (video_num, fps, frame_size) = path.into_inner();
    let password = match _session.get::<String>("password")? {
        Some(pass) => pass,
        None => {
            log::error!("Password not found in session");
            return Err(actix_web::error::ErrorInternalServerError(
                "Password not set",
            ));
        }
    };

    // convert the stream Item to be sendable
    let (tx, rx) = channel::<Result<Bytes, std::io::Error>>(2000);
    actix_web::rt::spawn(async move {
        let mut stream = body
            .into_stream()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        while let Some(chunk_result) = stream.next().await {
            info!("decrypted frame getting converted to sendable stream");
            let result = chunk_result
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            info!(
                "the frame: {:?}",
                result.as_ref().and_then(|val| {
                    println!("frame length: {}", val.len());
                    Ok(val)
                })
            );
            if tx.send(result).await.is_err() {
                warn!("error sending frame over");
                break;
            } else {
                info!("sent the frame over");
            }
        }
        info!("done converting frames to sendables");
    });

    // Convert the receiver into a Send + 'static stream
    let send_stream = ReceiverStream::new(rx);

    // Now we can create the FrameReader with our Send stream
    let frame_reader = FrameReader::new(send_stream);
    info!("created frame reader");
    let mut decrypted_frames = Box::pin(decrypt_frame_reader(frame_reader, frame_size, password));
    info!("started decryption stream");
    let mut frame_num = 0;
    while let Some(frame) = decrypted_frames.next().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[DECRYPTION ERROR]: {e}");
                break;
            }
        };
        info!("decrypted frame here");
        let mut file_handle =
            File::create(format!("video_frames/{}.{}.jpg", video_num, frame_num)).await?;
        file_handle.write_all(frame.as_ref()).await?;
        frame_num += 1;
    }
    // spawn a task for executing ffmpeg
    // actix_web::rt::spawn(async move {
        execute_ffmpeg(video_num, frame_num, fps).unwrap();
    // });
    Ok(HttpResponse::Ok().body("SUCCESS"))
}

#[get("/new_video_stream/{video_num}/{fps}")]
async fn new_video_stream(
    _session: Session,
    mut body: web::Payload,
    data: web::Data<AppState<'_>>,
    path: web::Path<(usize, usize)>,
    identity: Option<Identity>,
    request: HttpRequest,
) -> actix_web::Result<impl Responder> {
    info!("saving new video from video stream");
    if identity.is_some() {
        // set up the websocket
        let (res, _, stream) = actix_ws::handle(&request, body)?;
        let mut stream = Box::pin(
            stream
                .aggregate_continuations()
                .max_continuation_size(1024 * 1024 * 1024),
        );

        let password = match _session.get::<String>("password")? {
            Some(pass) => pass,
            None => {
                log::error!("Password not found in session");
                return Err(actix_web::error::ErrorInternalServerError(
                    "Password not set",
                ));
            }
        };
        // spawn a task to handle the stream of frames
        rt::spawn(async move {
            println!("got here in the sasdfa");
            let mut video_num = path.0;
            let fps = path.1;
            let mut frame_num = 0;
            // while the websocket still has messages in it
            while let Some(Ok(msg)) = stream.next().await {
                match msg {
                    // each message is a frame encrypted with different salt
                    AggregatedMessage::Binary(encrypted_frame) => {
                        println!("got an encrypted frame");
                        let mut file_handle =
                            File::create(format!("video_frames/{}.{}.jpg", video_num, frame_num))
                                .await
                                .expect("failed to create file");
                        let mut decrypted_frame = Box::pin(decrypt_stream_frame(
                            Cursor::new(encrypted_frame),
                            password.clone(),
                        ));
                        while let Some(Ok(chunk)) = decrypted_frame.next().await {
                            file_handle
                                .write_all(&chunk)
                                .await
                                .expect("failed to write to file");
                        }
                        frame_num += 1;
                    }
                    // on close, generate a new key and salt, encrypt the video, and delete the unencrypted video
                    AggregatedMessage::Close(reason) => {
                        println!("closing stream: {:?}", reason);
                        match execute_ffmpeg(video_num, frame_num, fps) {
                            Ok(filepath) => {
                                info!("ffmpeg executed successfully: {}", filepath);
                                let (key, salt) =
                                    generate_key(&password).expect("failed to generate key");

                                // encrypt the mp4 file
                                let mut enc_stream = Box::pin(encrypt_stream(
                                    key,
                                    salt,
                                    File::create(&filepath).await.expect("couldn't make file"),
                                ));

                                let mut encrypted_file_handle =
                                    File::create(filepath.replace(".unencrypted", ""))
                                        .await
                                        .expect("couldn't make file");

                                while let Some(Ok(chunk)) = enc_stream.next().await {
                                    encrypted_file_handle
                                        .write_all(&chunk)
                                        .await
                                        .expect("failed to write to file");
                                }
                                remove_file(filepath)
                                    .await
                                    .expect("failed to delete the old unencrypted file");
                            }
                            Err(e) => warn!("failed to execute ffmpeg: {}", e),
                        }
                    }
                    AggregatedMessage::Text(text) => {
                        println!("got : {text}")
                    }
                    AggregatedMessage::Ping(_) => todo!(),
                    AggregatedMessage::Pong(_) => todo!(),
                }
            }
        });
        Ok(res)
    } else {
        warn!("unauthorized");
        Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
}

#[post("/new_video_ffmpeg/{video_num}/{current}/{count}/{fps}")]
#[deprecated]
async fn new_video_ffmpeg(
    mut body: web::Payload,
    path: web::Path<(usize, u64, u64, usize)>,
    identity: Option<Identity>,
) -> actix_web::Result<impl Responder> {
    info!("saving new video");
    let mut frame = vec![];
    let path = path.into_inner();
    let fps = path.3;
    let frame_count = path.2;
    let frame_num = path.1;
    let video_num = path.0;
    if let Some(_identity) = identity {
        // if the user is logged in
        let mut file_handle =
            File::create(format!("video_frames/{}.{}.jpg", video_num, frame_num)).await?;
        while let Some(Ok(chunk)) = body.next().await {
            <dyn std::io::Write>::write_all(&mut frame, chunk.as_ref())?;
        }
        file_handle.write_all(&frame).await?;
        if frame_num == frame_count {
            drop(file_handle);
            execute_ffmpeg(video_num, frame_count + 1, fps)?;
        }
        Ok(HttpResponse::Ok().body("SUCCESS"))
    } else {
        warn!("unauthorized");
        Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
}

#[post("/new_video")]
#[deprecated]
async fn new_video(
    mut body: web::Payload,
    identity: Option<Identity>,
) -> actix_web::Result<impl Responder> {
    info!("saving new video");
    if let Some(_identity) = identity {
        // if the user is logged in
        let mut file_handle = make_new_video_file().await?;
        while let Some(Ok(chunk)) = body.next().await {
            append_chunk_to_file(&chunk, &mut file_handle).await?;
        }
        Ok(HttpResponse::Ok().body("SUCCESS"))
    } else {
        warn!("unauthorized");
        Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
}

#[get("/assets/{filename}/{password}")]
async fn assets(
    _data: web::Data<AppState<'_>>,
    _session: Session,
    path: web::Path<(String, String)>,
    _identity: Option<Identity>,
) -> actix_web::Result<impl Responder> {
    let (filename, password) = path.into_inner();
    info!("the password is: {}", password);
    if let Some(_identity) = Some(1) {
        info!("the identity was found");
        let sanitized_filename = sanitize_video_path(&filename)?;
        // let plaintext = decrypt_bytes(&key, salt, &tokio::fs::read(PathBuf::from("assets").join(&path)).await?)?; // decrypt the file?;
        let file = File::open(sanitized_filename).await?;
        info!("returning stream");
        //Ok::<_, Box<dyn std::error::Error>>(
        Ok(HttpResponse::Ok()
            .content_type("video/mp4")
            .streaming(Box::pin(decrypt_stream(file, password.clone()))))
    } else {
        Err(actix_web::error::ErrorForbidden("UNAUTHORIZED"))
    }
}

#[get("/")]
async fn index(
    data: web::Data<AppState<'_>>,
    _session: Session,
    identity: Option<Identity>,
) -> actix_web::Result<impl Responder> {
    if let Some(_identity) = identity {
        let video_paths = get_video_paths().await?;
        let video_paths_json = json!({"files" : video_paths});
        info!("{}", video_paths_json);
        Ok(HttpResponse::Ok().body(data.1.render("index", &video_paths_json).unwrap()))
    } else {
        Ok(HttpResponse::SeeOther()
            .insert_header((LOCATION, "/login"))
            .finish())
    }
}

#[shuttle_runtime::main]
async fn actix_web(
    #[Secrets] secret_store: SecretStore,
) -> ShuttleActixWeb<impl FnOnce(&mut ServiceConfig) + Send + Clone + 'static> {
    let admin_hash = secret_store
        .get("ADMIN_HASH")
        .expect("ADMIN_HASH not found");
    let admin_user = secret_store
        .get("ADMIN_USER")
        .expect("ADMIN_USER not found");
    let key = Key::from(secret_store.get("KEY").unwrap().as_bytes());
    let config = move |cfg: &mut ServiceConfig| {
        // create static site builder

        let mut hbars = Handlebars::new();
        hbars
            .register_template_file("index", "index.html")
            .expect("index.html not found");

        // store the admin session info (username and hash)
        // store the handlebars static site generation information in the shuttle state
        cfg.app_data(web::Data::new((
            Mutex::new(AdminSessionInfo::from(
                admin_user.clone(),
                admin_hash.clone(),
            )),
            hbars,
        )));
        cfg.service(
            web::scope("")
                .wrap(IdentityMiddleware::default())
                .service(index)
                .service(login_form)
                .service(logout)
                .service(new_video)
                .service(assets)
                .service(new_video_ffmpeg)
                .service(delete_video)
                .service(new_video_stream)
                .service(upload)
                .route("/login", web::post().to(login))
                // cookie middleware
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), key)
                        .cookie_content_security(CookieContentSecurity::Private)
                        .session_lifecycle(
                            PersistentSession::default().session_ttl(Duration::days(1)),
                        )
                        .build(),
                )
                .default_service(web::to(HttpResponse::NotFound)),
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

#[derive(serde::Deserialize)]
pub struct DeleteForm {
    delete: String,
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

    use actix_web::cookie::Key;
    use actix_web::web::ServiceConfig;
    use actix_web::App;
    use handlebars::Handlebars;

    use crate::AdminSessionInfo;
    use crate::*;
    use actix_identity::IdentityMiddleware;
    use actix_session::config::PersistentSession;
    use actix_session::storage::CookieSessionStore;
    use actix_session::*;
    use actix_web::cookie::time::Duration;
    use actix_web::web;
    use actix_web::HttpResponse;

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
            hbars
                .register_template_file("index", "index.html")
                .expect("index.html not found");
            cfg.app_data(web::Data::new((
                AdminSessionInfo::from(admin_user.clone(), admin_hash.clone()),
                hbars,
            )));
            cfg.service(
                web::scope("")
                    .wrap(IdentityMiddleware::default())
                    .service(index)
                    .service(login_form)
                    .service(logout)
                    .service(new_video)
                    .service(assets)
                    .service(delete_video)
                    .route("/login", web::post().to(login))
                    // cookie middleware
                    .wrap(
                        SessionMiddleware::builder(CookieSessionStore::default(), key)
                            .cookie_content_security(CookieContentSecurity::Private)
                            .session_lifecycle(
                                PersistentSession::default().session_ttl(Duration::days(1)),
                            )
                            .build(),
                    )
                    .default_service(web::to(HttpResponse::NotFound)),
            );
        };
        actix_web::test::init_service(App::new().configure(config));
    }
}
