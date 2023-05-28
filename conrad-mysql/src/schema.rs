// @generated automatically by Diesel CLI.

diesel::table! {
    auth_key (id) {
        #[max_length = 255]
        id -> Varchar,
        #[max_length = 15]
        user_id -> Varchar,
        primary_key -> Unsigned<Tinyint>,
        #[max_length = 255]
        hashed_password -> Nullable<Varchar>,
        expires -> Nullable<Unsigned<Bigint>>,
    }
}

diesel::table! {
    auth_session (id) {
        #[max_length = 127]
        id -> Varchar,
        #[max_length = 15]
        user_id -> Varchar,
        active_expires -> Unsigned<Bigint>,
        idle_expires -> Unsigned<Bigint>,
    }
}

diesel::table! {
    auth_user (id) {
        #[max_length = 15]
        id -> Varchar,
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
