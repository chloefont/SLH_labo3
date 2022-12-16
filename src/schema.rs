// @generated automatically by Diesel CLI.

diesel::table! {
    users (email) {
        email -> Varchar,
        auth_method -> Varchar,
        password -> Varchar,
        email_verified -> Bool,
    }
}
