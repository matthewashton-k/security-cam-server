# Encrypted Security Camera Server and Viewer
## Features
* deployment on shuttle.rs using actix web
* argon2 hash creating helper tool in the examples folder
* password protected mp4 file hosting
* session based login system
* tokio Stream based asynchronous decryption and encryption


## Security Features
DISCLAIMER: this tool has not been audited, use at your own risk
* An argon2 hash of the admin username||password is stored in Secrets.toml, and on login the username and password in the form are validated with the hash
* after hash validation, actix-identity middleware is used to generate a uuid and store it in a cookie that is associated with the logged in user
* A key is stored in Secrets.toml and used to encrypt the session cookie
* cookies expire after some time
* files sent to the server by a client should be encrypted using the key generation functions in the security-cam-common crate (authored by me). There is one function for generating a random key and salt pair, and another function that takes in a salt string, and a password, and uses Argon2 to derive a 32 byte key from it.
* decrypted mp4s should never touch the file disk, as all files are decrypted and send in chunks to the user.
* When decrypting a file, it is expected that the salt should be the first 16 bytes of the file
* AES 256 bit stream encryption is handled by my common crate at https://crates.io/crates/security-cam-common ( https://github.com/matthewashton_k/security-cam-common)

## Usage
Note: This server is meant to be for my future motion detection security camera project.\
Note: the motion camera should authenticate, and send encrypted videos of when motion was captured to POST /new_video\
**SERVER SETUP**:
* install shuttle, instructions on shuttle.rs
* clone this repo
* use ```cargo run --example generate_password_hash <user> <pass>``` to generate an argon2 hash that will be used for authentication
* use ```openssl rand -base64 64``` to generate a key to be used for encrypting session id cookies
* in the crate root create a file called Secrets.toml with this format:
```
KEY = "<cookie key>"
ADMIN_USER = "<admin user>"
ADMIN_HASH = "<argon2 hash>"
```
* run locally with ```cargo shuttle run``` or deploy with ```cargo shuttle deploy```

**ROUTES**\
GET /login\
POST /new_video\
GET /assets/video.mp4/password (click on a link shown in the index page)\
GET /logout \
GET / (shows all the videos stored on the server)
POST /upload (for uploading encrypted videos)

## Motion Detecting Client
* Client code and usage instructions hosted at https://github.com/matthewashton_k/security-cam-client

TODOS:
1. test a route for deleting files, or auto-deleting files after a certain amount of time
2. Delete deprecated endpoints after thouroughly testing the upload endpoint
