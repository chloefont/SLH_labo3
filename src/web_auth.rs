use std::env;
use crate::db::DbConn;
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::UserDTO;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::MemoryStore;
use serde_json::json;
use std::error::Error;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
        .route("/oauth/google", get(google_oauth))
        .route("/_oauth", get(oauth_redirect))
        .route("/password_update", post(password_update))
        .route("/logout", get(logout))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    // TODO: Implement the login function. You can use the functions inside db.rs to check if
    //       the user exists and get the user info.
    let _email = login.login_email;
    let _password = login.login_password;

    // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
    // let jar = add_auth_cookie(jar, &user_dto)
    //     .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;
    return Ok((jar, AuthResult::Success));
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the register function. The email must be verified by sending a link.
    //       You can use the functions inside db.rs to add a new user to the DB.

    let _email = register.register_email;
    let _password = register.register_password;

    println!("{}", _email);
    println!("{}", _password);

    let splited_email = _email.split('@').collect::<Vec<&str>>();

    if splited_email.len() < 2 {
        return Err(AuthResult::WrongCreds.into_response())
    }

    let host = env::var("SMTP_HOST").expect("Could not get SMTP_HOST from ENV");
    let port = env::var("SMTP_PORT").expect("Could not get SMTP_PORT from ENV").parse::<u16>();
    match port {
        Result::Ok(_) => (),
        Result::Err(e) => panic!("SMTP_PORT in ENV should be a u16")
    }
    let username = env::var("SMTP_USERNAME").expect("Could not get SMTP_USERNAME from ENV");
    let password = env::var("SMTP_PASSWORD").expect("Could not get SMTP_PASSWORD from ENV");

    let email = Message::builder()
        .from("labo3 <labo3@gmail.com>".parse().unwrap())
        .to(format!("{} <{}>", splited_email[0], _email).parse().unwrap())
        .subject("Email verification")
        .body(String::from("Hello, world!")).unwrap();

    let creds = Credentials::new(username, password);

    let mailer = SmtpTransport::builder_dangerous(host)
        .credentials(creds)
        .port(port.unwrap())
        .build();

    match mailer.send(&email) {
        Ok(_) => (),
        Err(e) => return Err(AuthResult::WrongCreds.into_response())
    }

    // Once the user has been created, send a verification link by email
    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.

    Ok(AuthResult::Success)
}

// TODO: Create the endpoint for the email verification function.

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: This function is used to authenticate a user with Google's OAuth2 service.
    //       We want to use a PKCE authentication flow, you will have to generate a
    //       random challenge and a CSRF token. In order to get the email address of
    //       the user, use the following scope: https://www.googleapis.com/auth/userinfo.email
    //       Use Redirect::to(url) to redirect the user to Google's authentication form.

    // let client = crate::oauth::OAUTH_CLIENT.todo();

    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.
    Ok((jar, Redirect::to("myurl")))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // TODO: The user should be redirected to this page automatically after a successful login.
    //       You will need to verify the CSRF token and ensure the authorization code is valid
    //       by interacting with Google's OAuth2 API (use an async request!). Once everything
    //       was verified, get the email address with the provided function (get_oauth_email)
    //       and create a JWT for the user.

    // If you need to recover data between requests, you may use the session_store to load a session
    // based on a session_id.

    // Once the OAuth user is authenticated, create the user in the DB and add a JWT cookie
    // let jar = add_auth_cookie(jar, &user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the password update function.
    Ok(AuthResult::Success)
}

/// Endpoint handling the logout logic
/// GET /logout
async fn logout(jar: CookieJar) -> impl IntoResponse {
    let new_jar = jar.remove(Cookie::named("auth"));
    (new_jar, Redirect::to("/home"))
}

#[allow(dead_code)]
fn add_auth_cookie(jar: CookieJar, _user: &UserDTO) -> Result<CookieJar, Box<dyn Error>> {
    // TODO: You have to create a new signed JWT and store it in the auth cookie.
    //       Careful with the cookie options.
    let jwt = "JWT";
    Ok(jar.add(Cookie::build("auth", jwt).finish()))
}

enum AuthResult {
    Success,
    WrongCreds,
    IncorrectEmail
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::WrongCreds => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            Self::IncorrectEmail => (StatusCode::UNAUTHORIZED, "Incorrect email")
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}
