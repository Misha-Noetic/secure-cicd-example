// THIS FILE INTENTIONALLY CONTAINS A FAKE SECRET FOR TESTING
// In a real codebase, this is exactly the kind of mistake TruffleHog catches.

/// Database configuration
pub struct Config {
    pub database_url: String,
    pub api_key: String,
}

impl Config {
    pub fn load() -> Self {
        Config {
            // Oops! Someone hardcoded credentials instead of using env vars
            database_url: "postgres://admin:SuperSecret123!@db.production.internal:5432/myapp".to_string(),
            api_key: "AKIAIOSFODNN7EXAMPLE2".to_string(),
        }
    }
}
