use std::env;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use zxcvbn::zxcvbn;

pub fn send_mail(email : &String, subject : String, body : String) -> Result<(), String> {
    let splited_email = email.split('@').collect::<Vec<&str>>();

    if splited_email.len() < 2 {
        return Err(String::from("Wrong mail"));
    }

    let host = env::var("SMTP_HOST").expect("Could not get SMTP_HOST from ENV");
    let port = env::var("SMTP_PORT").expect("Could not get SMTP_PORT from ENV").parse::<u16>().expect("SMTP_PORT in ENV should be a u16");

    let username = env::var("SMTP_USERNAME").expect("Could not get SMTP_USERNAME from ENV");
    let password = env::var("SMTP_PASSWORD").expect("Could not get SMTP_PASSWORD from ENV");

    let email = Message::builder()
        .from("labo3 <labo3@gmail.com>".parse().unwrap())
        .to(format!("{} <{}>", splited_email[0], email).parse().unwrap())
        .subject(subject)
        .body(body).unwrap();

    let creds = Credentials::new(username, password);

    let mailer = SmtpTransport::builder_dangerous(host)
        .credentials(creds)
        .port(port)
        .build();


    mailer.send(&email).map(|_| ()).or(Err(String::from("Error when sending mail")))
}

pub fn hash_default(password : &str) {
    const DEFAULT_HASH : &str = "$argon2id$v=19$m=4096,t=3,p=1$4umFzAYSVZkYYA7cPfe4Tg$uJnyCkJuG2s+QOyQfn43YYMWZMmFlJV2QUEULfO0UiA";
    let parsed_hash = PasswordHash::new(DEFAULT_HASH).expect("Error when created PasswordHash object");
    Argon2::default().verify_password(password.as_ref(), &parsed_hash);
}

pub fn password_strong_enough(password : &str, user_inputs : &[&str]) -> bool {
    const MIN_PASSWORD_LENGTH: i32 = 8;
    const MAX_PASSWORD_LENGTH : i32 = 64;
    if password.chars().count() < MIN_PASSWORD_LENGTH as usize || password.chars().count() > MAX_PASSWORD_LENGTH as usize {
        return false;
    }

   match zxcvbn(password, user_inputs) {
         Ok(result) => result.score() >= 3,
         Err(_) => false
   }
}

pub fn hash_password(password : &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_ref(), &salt).expect("Error while hashing password").to_string()
}