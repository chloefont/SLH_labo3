use std::env;
use crate::db::{DbConn, get_user, save_user, update_password, user_exists, validate_email};
use crate::models::{
    AppState, LoginRequest, OAuthRedirect, PasswordUpdateRequest, RegisterRequest,
};
use crate::user::{AuthenticationMethod, User, UserDTO};
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
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use jsonwebtoken::{encode, EncodingKey, Header};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope};
use oauth2::reqwest::{async_http_client};
use crate::user::AuthenticationMethod::Password;
use crate::utils::*;
use time::{Duration, OffsetDateTime};
use crate::oauth::get_google_oauth_email;

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
    let _email = login.login_email.to_lowercase();
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

    let _email = register.register_email.to_lowercase();
    let _password = register.register_password;

    if !password_strong_enough(_password.as_str(),&[_email.as_str()]) {
        return Err(AuthResult::WrongPasswordFormat.into_response());
    }

    match user_exists(&mut _conn, _email.as_str()) {
        Ok(_) => return Err(AuthResult::UserExists.into_response()),
        _ => ()
    }

    let password_hash = hash_password(_password.as_str());

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

    Ok(AuthResult::Success)
}

/// Endpoint used to register a new account
/// GET /email-verification/:token
async fn email_verification(
    mut _conn: DbConn,
    State(_session_store): State<MemoryStore>,
    Path(session_id_encoded) : Path<String>
) -> Result<Redirect, Response> {
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
    Ok(Redirect::to("/login"))
}

/// Endpoint used for the first OAuth step
/// GET /oauth/google
async fn google_oauth(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let client = &crate::oauth::OAUTH_CLIENT;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("email".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    let mut session = Session::new();
    session.insert("csrf_token", csrf_token.clone()).or(Err(StatusCode::UNAUTHORIZED))?;
    session.insert("pkce_verifier", pkce_verifier).or(Err(StatusCode::UNAUTHORIZED))?;

    //let session_id = _session_store.store_session(session).await.expect("Error when storing session").ok_or(Err::<>(StatusCode::UNAUTHORIZED)).unwrap();
    let session_id =  _session_store.store_session(session).await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let expireds_in = env::var("COOKIE_EXPIRES_IN_DAYS").expect("Could not get COOKIE_EXPIRES_IN_DAYS from ENV").parse::<i64>().expect("COOKIE_EXPIRES_IN_DAYS from ENV should be a i64");

    // Add csrf cookie
    let jar = jar.add(Cookie::build("csrf_token", csrf_token.secret().clone())
        .path("/")
        .expires(OffsetDateTime::now_utc() + Duration::days(expireds_in))
        .secure(true)
        .http_only(true)
        .finish());

    // Add session id cookie
    let jar = jar.add(Cookie::build("session_id", session_id)
        .path("/")
        .expires(OffsetDateTime::now_utc() + Duration::days(expireds_in))
        .secure(true)
        .http_only(true)
        .finish());

    Ok((jar, Redirect::to(auth_url.as_str())))
}

/// Endpoint called after a successful OAuth login.
/// GET /_oauth?state=x&code=y
async fn oauth_redirect(
    jar: CookieJar,
    State(_session_store): State<MemoryStore>,
    mut _conn: DbConn,
    _params: Query<OAuthRedirect>,
) -> Result<(CookieJar, Redirect), StatusCode> {

    let session_id_cookie = jar.get("session_id").ok_or(StatusCode::BAD_REQUEST)?;
    let csrf_token_cookie = jar.get("csrf_token").ok_or(StatusCode::BAD_REQUEST)?.clone();

    let session =
        _session_store.load_session(session_id_cookie.value().to_string())
        .await.or(Err(StatusCode::UNAUTHORIZED))?.ok_or(StatusCode::UNAUTHORIZED).unwrap();

    let stored_csrf_token : CsrfToken = session.get("csrf_token").ok_or(StatusCode::UNAUTHORIZED)?;
    let pkce_verifier = session.get("pkce_verifier").ok_or(StatusCode::UNAUTHORIZED)?;

    // verify the csrf tokens
    if csrf_token_cookie.value().to_string() != (stored_csrf_token.secret()).to_string() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token_result =
        crate::oauth::OAUTH_CLIENT
            .exchange_code(AuthorizationCode::new(_params.code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client).await.or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let email = get_google_oauth_email(&token_result).await.or(Err(StatusCode::UNAUTHORIZED))?;

    let jar = if let Ok(user) = get_user(&mut _conn, email.as_str()) {
        if user.get_auth_method() != AuthenticationMethod::OAuth {
            return Err(StatusCode::UNAUTHORIZED);
        }

        add_auth_cookie(jar, &user.to_dto()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
    } else {
        let new_user = User::new(email.as_str(), "", AuthenticationMethod::OAuth, true);
        let new_user_dto = &new_user.to_dto();
        save_user(&mut _conn, new_user).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

        add_auth_cookie(jar, new_user_dto).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
    }.remove(csrf_token_cookie.clone());

    Ok((jar, Redirect::to("/home")))
}

/// Endpoint handling login
/// POST /password_update
/// BODY { "old_password": "pass", "new_password": "pass" }
async fn password_update(
    mut _conn: DbConn,
    _user: UserDTO,
    Json(_update): Json<PasswordUpdateRequest>,
) -> Result<AuthResult, Response> {

    let user = get_user(&mut _conn, _user.email.as_str()).or(Err(AuthResult::Error.into_response()))?;

    if user.get_auth_method() != Password {
        return Err(AuthResult::Error.into_response());
    }

    // Verify old password
    let parsed_hash = PasswordHash::new(&user.password).expect("Error when created PasswordHash object");
    Argon2::default().verify_password(_update.old_password.as_str().as_ref(), &parsed_hash).or(Err(AuthResult::WrongCreds.into_response()))?;

    if !password_strong_enough(_update.new_password.as_str(), &[user.email.as_str()]) {
        return Err(AuthResult::WrongPasswordFormat.into_response());
    }

    let password_hash = hash_password(_update.new_password.as_str());
    update_password(&mut _conn, user.email.as_str(), password_hash.as_str()).or(Err(AuthResult::InternalError.into_response()))?;

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
    let secret = env::var("JWT_SECRET").expect("Could not get JWT_SECRET from ENV");
    let expireds_in = env::var("COOKIE_EXPIRES_IN_DAYS").expect("Could not get COOKIE_EXPIRES_IN_DAYS from ENV").parse::<i64>().expect("COOKIE_EXPIRES_IN_DAYS from ENV should be a i64");

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
    Error,
    InternalError,
    WrongPasswordFormat
}

/// Returns a status code and a JSON payload based on the value of the enum
impl IntoResponse for AuthResult {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Success => (StatusCode::OK, "Success"),
            Self::WrongCreds => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            Self::IncorrectEmail => (StatusCode::UNAUTHORIZED, "Incorrect email"),
            Self::UserExists => (StatusCode::UNAUTHORIZED, "This email is already used"),
            Self::Error => (StatusCode::BAD_REQUEST, "Error"),
            Self::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            Self::WrongPasswordFormat => (StatusCode::UNAUTHORIZED, "The password must be between 8 and 64 characters and should be strong enough")
        };
        (status, Json(json!({ "res": message }))).into_response()
    }
}
