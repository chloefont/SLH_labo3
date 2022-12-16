use crate::models::*;
use crate::user::UserDTO;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;
use handlebars::Handlebars;

/// Declares the different endpoints
/// state is used to pass common structs to the endpoints
pub fn stage(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/home", get(get_home))
        .route("/password_update", get(password_update_page))
        .route("/login", get(login_page))
        .with_state(state)
}

/// Redirects to the home page
async fn index() -> impl IntoResponse {
    Redirect::to("/home")
}

/// Home page for authenticated users
async fn get_home(State(hbs): State<Handlebars<'_>>, user: Option<UserDTO>) -> impl IntoResponse {
    Html(hbs.render("home", &user).unwrap())
}

/// Password update page
async fn password_update_page(
    State(hbs): State<Handlebars<'_>>,
    user: UserDTO,
) -> impl IntoResponse {
    Html(hbs.render("password_update", &user).unwrap())
}

/// Login page
async fn login_page(State(hbs): State<Handlebars<'_>>) -> impl IntoResponse {
    Html(hbs.render("login", &"".to_string()).unwrap())
}
