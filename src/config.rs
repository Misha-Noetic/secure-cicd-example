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
            // Oops! Someone hardcoded credentials instead of using env vars
            database_url: "postgres://admin:SuperSecret123!@db.production.internal:5432/myapp".to_string(),

            // Oops! Someone pasted a private key directly in code
            private_key: "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/yGaXxw9MBH+FKEWCCkCpOBFPRaF2r3Jj
c6WnGqergPmGFsTAqdFqJXsPmE0fDH2CnM3gKmFPMSj4JJYmm4Xf5AvBdEecBTH
nRZ4sOQbNi5KLHRZwqrI8h9VToqpnPBMWYCnMOJdKETvILkpJ7nJPsVaiRELuG7v
Y0K3YxFvhS2MN9MtN4CZPh0Gk9kHOMFiJBMEYXHUHKtLG0bNzMEF4eNMRKlMBEB
rIGqpFDBNPO0bHB3StORJBhb0F3MZjA9JOhGBwMT5QGEMbNPb1VGpUtOL1s2i8NG
y1JUhUeg8ILHP5VhPFJ7dkPRN1FWLzr5dQIDAQABAKCAQEAhchGvXuMEH3sNTIbY
-----END RSA PRIVATE KEY-----".to_string(),
        }
    }
}
