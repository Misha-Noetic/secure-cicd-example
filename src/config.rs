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
        }
    }
}
