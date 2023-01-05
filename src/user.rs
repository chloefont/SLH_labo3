use std::env;
use std::ops::Add;
use crate::schema::*;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use axum_sessions::async_session::chrono::{Duration, Utc};
use strum_macros::{Display, EnumString};

#[derive(Display, EnumString, Serialize, Deserialize, PartialEq)]
pub enum AuthenticationMethod {
    Password,
    OAuth,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
pub struct User {
    pub email: String,
    auth_method: String,
    pub password: String,
    pub email_verified: bool,
}

#[derive(Deserialize, Serialize)]
pub struct UserDTO {
    pub email: String,
    pub auth_method: AuthenticationMethod,
    pub exp: usize
}

impl User {
    pub fn new(
        email: &str,
        password: &str,
        auth_method: AuthenticationMethod,
        verified: bool,
    ) -> Self {
        Self {
            email: email.to_string(),
            auth_method: auth_method.to_string(),
            password: password.to_string(),
            email_verified: verified,
        }
    }

    pub fn get_auth_method(&self) -> AuthenticationMethod {
        AuthenticationMethod::from_str(&self.auth_method)
            .expect("Different auth method in enum and DB")
    }

    pub fn to_dto(&self) -> UserDTO {
        let expireds_in = env::var("JWT_EXPIRES_IN_DAYS").expect("Could not get JWT_EXPIRES_IN_DAYS from ENV").parse::<i64>().expect("JWT_EXPIRES_IN_DAYS from ENV should be a i64");
        let exp_time = Utc::now().add(Duration::days(expireds_in)).timestamp();

        UserDTO {
            email: self.email.clone(),
            auth_method: self.get_auth_method(),
            exp: exp_time as usize
        }
    }
}
