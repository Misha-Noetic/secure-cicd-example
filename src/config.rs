// THIS FILE EXISTS SOLELY FOR TRUFFLEHOG TESTING
//
// In the original git history, this file contained hardcoded secrets (database
// URLs with passwords, private keys, etc.) that were committed intentionally to
// verify TruffleHog's custom detectors. The secrets have since been removed from
// the file content, but TruffleHog scans git history so they are still detected.
//
// In a real codebase, this is exactly the kind of mistake TruffleHog catches:
// secrets committed to source control, even if later deleted.

/// Database configuration — load from environment variables, never hardcode.
pub struct Config {
    pub database_url: String,
    pub private_key: String,
}

impl Config {
    pub fn load() -> Self {
        Config {
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/dev".to_string()),
            private_key: std::env::var("PRIVATE_KEY")
                .unwrap_or_else(|_| String::new()),
        }
    }
}
