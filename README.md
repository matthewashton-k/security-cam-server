# Encrypted .mp4 Hosting Tool

## Features 
* deployment on shuttle.rs using actix web
* argon2 hash creating helper tool in the examples folder
* password protected mp4 file hosting
* session based login system


## Security Features
DISCLAIMER: this tool has not been audited, use at your own risk
* An argon2 hash of the admin username||password is stored in Secrets.toml, and on login the username and password in the form are validated with the hash
* after hash validation, actix-identity middleware is used to generate a uuid and store it in a cookie that is associated with the logged in user
* A key is stored in Secrets.toml and used to encrypt the session cookie
* cookies expire after some time
* files sent to the server by a client should be encrypted using the key generation functions in encryption.rs. There is one function for generating a random key and salt pair, and another function that takes in a salt string, and a password, and uses Argon2 to derive a 32 byte key from it.
* When decrypting a file, it is expected that the salt should be the first 22 bytes of the file

## Usage
Note: This server is meant to be for a future motion detection security camera project.\
Note: the motion camera should authenticate, and send encrypted videos of when motion was captured to POST /new_video\
**SERVER SETUP**:
* install shuttle, instructions on shuttle.rs
* clone repo
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

*I included a test encrypted mp4 (and its decrypted counterpart) in /assets encrypted with the password "pass" so feel free to test out the capabilities of the server using that if you don't want to bother with encrypting files your self since I have not written the client yet*

TODOS:
1. make the website look nice
2. make a route for deleting files, or auto-deleting files after a certain amount of time

