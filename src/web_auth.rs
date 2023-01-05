use std::env;
use crate::db::{DbConn, get_user, save_user, user_exists, validate_email};
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::{User, UserDTO};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use axum_sessions::async_session::{MemoryStore, SessionStore, Session};
use serde_json::json;
use std::error::Error;
use std::fmt::format;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use jsonwebtoken::{encode, EncodingKey, Header};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use serde::de::Unexpected::Str;
use crate::user::AuthenticationMethod::Password;
use crate::utils::*;
use time::{Duration, OffsetDateTime};

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
        .route("/email-verification/:token", get(email_verification))
        .with_state(state)
}

/// Endpoint handling login
/// POST /login
/// BODY { "login_email": "email", "login_password": "password" }
async fn login(
    mut _conn: DbConn,
    jar: CookieJar,
    Json(login): Json<LoginRequest>,
) -> Result<(CookieJar, AuthResult), Response> {
    // TODO: Implement the login function. You can use the functions inside db.rs to check if
    //       the user exists and get the user info.
    let _email = login.login_email;
    let _password = login.login_password;

    if let Ok(user) = get_user(&mut _conn, _email.as_str()){
        if !user.email_verified || user.get_auth_method() != Password {
            hash_default(_password.as_str());
            return Err(AuthResult::WrongCreds.into_response());
        }

        let parsed_hash = PasswordHash::new(&user.password).expect("Error when created PasswordHash object");
        Argon2::default().verify_password(_password.as_str().as_ref(), &parsed_hash).or(Err(AuthResult::WrongCreds.into_response()))?;

        // Once the user has been created, authenticate the user by adding a JWT cookie in the cookie jar
        let jar = add_auth_cookie(jar, &user.to_dto())
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()))?;

        return Ok((jar, AuthResult::Success));
    } else {
        hash_default(_password.as_str());
        return Err(AuthResult::WrongCreds.into_response());
    }
}

/// Endpoint used to register a new account
/// POST /register
/// BODY { "register_email": "email", "register_password": "password", "register_password2": "password" }
async fn register(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Json(register): Json<RegisterRequest>,
) -> Result<AuthResult, Response> {
    // TODO: Implement the register function. The email must be verified by sending a link.
    //       You can use the functions inside db.rs to add a new user to the DB.

    let _email = register.register_email;
    let _password = register.register_password;

    match user_exists(&mut _conn, _email.as_str()) {
        Ok(_) => return Err(AuthResult::UserExists.into_response()),
        _ => ()
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(_password.as_ref(), &salt).expect("Error while hashing password").to_string();
    println!("{}", password_hash);

    let user = User::new(_email.as_str(), password_hash.as_str(), Password, false);

    save_user(&mut _conn, user).expect("Error when tried to save user");

    let mut session = Session::new();
    session.insert("email", _email.clone()).or(Err(AuthResult::Error.into_response()))?;

    let session_id = _session_store.store_session(session).await.expect("Error when storing session");

    if session_id == None {
        return Err(AuthResult::Error.into_response())
    }

    let mut url = String::from("http://localhost:8000/email-verification/");
    url_escape::encode_component_to_string(session_id.unwrap(), &mut url);

    let _body = format!("Please click on the following link to validate your email address : {}", url);

    send_mail(&_email, "Email validation".to_string(), _body).or(Err(AuthResult::WrongCreds.into_response()))?;

    // Once the user has been created, send a verification link by email
    // If you need to store data between requests, you may use the session_store. You need to first
    // create a new Session and store the variables. Then, you add the session to the session_store
    // to get a session_id. You then store the session_id in a cookie.

    Ok(AuthResult::Success)
}

// TODO: Create the endpoint for the email verification function.
/// Endpoint used to register a new account
/// GET /email-verification/:token
async fn email_verification(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Path(session_id_encoded) : Path<String>
) -> Result<AuthResult, Response> {
    let session_id = url_escape::decode(session_id_encoded.as_str()).to_string();
    println!("Email verification {}", session_id);

    let session_option = _session_store.load_session(session_id).await.expect("Error when loading session");

    if session_option == None {
        return Err(AuthResult::Error.into_response());
    }

    let session = session_option.unwrap();
    let email : String = session.get("email").unwrap();
    validate_email(&mut _conn, email.as_str()).or(Err(AuthResult::Error.into_response()))?;
    _session_store.destroy_session(session);

    println!("Email {} validated", email.as_str());
    Ok(AuthResult::Success)
}

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
    let secret = env::var("JWT_SECRET").expect("Could not get JWT_SECRET from ENV");
    let expireds_in = env::var("JWT_EXPIRES_IN_DAYS").expect("Could not get JWT_EXPIRES_IN_DAYS from ENV").parse::<i64>().expect("JWT_EXPIRES_IN_DAYS from ENV should be a i64");

    let jwt = encode(&Header::default(), _user, &EncodingKey::from_secret(secret.as_ref()))?;
    Ok(jar.add(Cookie::build("auth", jwt)
        .expires(OffsetDateTime::now_utc() + Duration::days(expireds_in))
        .secure(true)
        .http_only(true)
        .finish())
    )
}

enum AuthResult {
    Success,
    WrongCreds,
    IncorrectEmail,
    UserExists,
    Error
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::WrongCreds => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            Self::IncorrectEmail => (StatusCode::UNAUTHORIZED, "Incorrect email"),
            Self::UserExists => (StatusCode::UNAUTHORIZED, "This email is already used"),
            Self::Error => (StatusCode::UNAUTHORIZED, "Error")
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}
