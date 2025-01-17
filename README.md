# Encrypted Security Camera Server and Viewer
## Features
* Deployment on shuttle.rs using actix web.
* Argon2 hash creating helper tool in the examples folder.
* Password protected mp4 file hosting.
* Session based login system.
* Tokio Stream based asynchronous decryption and encryption.

## Crates:
Common (encrypted streams, FrameReader): https://github.com/matthewashton-k/security-cam-common
<br> Client (motion detection, v4l, frame processing): https://github.com/matthewashton-k/security-cam-client

## Security Features
DISCLAIMER: this tool has not been audited, use at your own risk.
* An argon2 hash of the admin username||password is stored in Secrets.toml, and on login the username and password in the form are validated with the hash.
* After hash validation, actix-identity middleware is used to generate a uuid and store it in a cookie that is associated with the logged in user.
* A key is stored in Secrets.toml and used to encrypt the session cookie.
* Cookies expire after some time.
* Files sent to the server by a client should be encrypted using the key generation and encryption functions in the security-cam-common crate (authored by me). There is one function for generating a random key and salt pair, and another function that takes in a salt string, and a password, and uses Argon2 to derive a 32 byte key from it.
* When decrypting a file, it is expected that the salt should be the first 16 bytes of the file.
* AES 256 bit stream encryption is handled by my common crate at https://github.com/matthewashton-k/security-cam-common

## Usage
**SERVER SETUP**:
* Install shuttle, instructions on shuttle.rs.
* Clone this repo.
* Use ```cargo run --example generate_password_hash <user> <pass>``` to generate an argon2 hash that will be used for authentication.
* In the crate root create a file called Secrets.toml with this format:
```
ADMIN_USER = "<admin user>"
ADMIN_HASH = "<argon2 hash>"
```
* Run locally with ```cargo shuttle run``` or deploy with ```cargo shuttle deploy```

**ROUTES**\
GET /login\
GET /assets/video.mp4/password (click on a link shown in the index page)\
GET /logout \
GET / (shows all the videos stored on the server)
POST /upload (for uploading encrypted videos)
<br> POST /delete video

TODOS:
1. Test a route for deleting files, or auto-deleting files after a certain amount of time.
2. Delete deprecated endpoints after thouroughly testing the upload endpoint.
