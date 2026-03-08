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
            database_url: "removed",

            private_key: "removed",
            // Another hardcoded secret to test custom TruffleHog detector
            staging_db: "removed",
            // New test: should trigger TruffleHog custom detector + Slack alert
            reporting_db: "removed",
            // Junior dev copy-pasted from prod wiki
            cache_url: "removed",
        }
    }
}
