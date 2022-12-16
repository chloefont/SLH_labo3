use crate::db::Pool;
use axum::extract::FromRef;
use axum_sessions::async_session::MemoryStore;
use handlebars::Handlebars;
use serde::Deserialize;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub session_store: MemoryStore,
    pub hbs: Handlebars<'static>,
}

/// Returns a Pool from an AppState reference
impl FromRef<AppState> for Pool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

/// Returns a MemoryStore from an AppState reference
impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.session_store.clone()
    }
}

/// Returns a Handlebars instance from an AppState reference
impl FromRef<AppState> for Handlebars<'_> {
    fn from_ref(state: &AppState) -> Self {
        state.hbs.clone()
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub login_email: String,
    pub login_password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub register_email: String,
    pub register_password: String,
    pub register_password2: String,
}

#[derive(Deserialize)]
pub struct PasswordUpdateRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct OAuthRedirect {
    pub state: String,
    pub code: String,
}
