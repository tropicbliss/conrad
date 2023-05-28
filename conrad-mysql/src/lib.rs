use crate::errors::DatabaseError;
use diesel::{Connection, PgConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use dotenvy::dotenv;

pub mod errors;
mod models;
mod schema;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub struct PostgresAdapter {
    conn: PgConnection,
}

impl PostgresAdapter {
    pub fn new() -> Result<Self, DatabaseError> {
        dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let mut conn: PgConnection = PgConnection::establish(&database_url)
            .map_err(|_| DatabaseError::ConnectionError(database_url))?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|_| DatabaseError::MigrationError)?;
        Ok(Self { conn })
    }
}
