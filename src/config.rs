// THIS FILE INTENTIONALLY CONTAINS A FAKE SECRET FOR TESTING
// In a real codebase, this is exactly the kind of mistake TruffleHog catches.

/// Database configuration
pub struct Config {
    pub database_url: String,
    pub private_key: String,
}

impl Config {
    pub fn load() -> Self {
        Config {
            database_url: "postgres://admin:SuperSecret123!@db.production.internal:5432/myapp".to_string(),

            private_key: "removed",
            // Another hardcoded secret to test custom TruffleHog detector
            staging_db: "mysql://deploy:P@ssw0rd2026!@db.staging.internal:3306/appdb".to_string(),
        }
    }
}
