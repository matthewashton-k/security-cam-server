use argon2::Argon2;
use argon2::password_hash::SaltString;
use security_cam_viewer::authentication::create_hash;

fn main() {
    println!("---USAGE---");
    println!("cargo run --examples generate_password_hash <username> <password>");
    let args = std::env::args().collect::<Vec<String>>();

    let hash = create_hash(&args[1], &args[2], ).expect("Error creating hash");
    println!("Hash: {}", hash);
}