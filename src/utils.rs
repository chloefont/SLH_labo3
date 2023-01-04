use std::env;
use axum::http::Response;
use dotenv::Error;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

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