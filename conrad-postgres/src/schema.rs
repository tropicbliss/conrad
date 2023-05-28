// @generated automatically by Diesel CLI.

diesel::table! {
    auth_key (id) {
        id -> Text,
        user_id -> Text,
        primary_key -> Bool,
        hashed_password -> Nullable<Text>,
        expires -> Nullable<Int8>,
    }
}

diesel::table! {
    auth_session (id) {
        id -> Text,
        user_id -> Text,
        active_expires -> Int8,
        idle_expires -> Int8,
    }
}

diesel::table! {
    auth_user (id) {
        id -> Text,
        attributes -> Text,
    }
}

diesel::joinable!(auth_key -> auth_user (user_id));
diesel::joinable!(auth_session -> auth_user (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    auth_key,
    auth_session,
    auth_user,
);
