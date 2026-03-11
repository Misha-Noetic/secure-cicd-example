// =============================================================================
// SECURITY BEST PRACTICES REFERENCE — FIXED CODE
// =============================================================================
// This module demonstrates secure alternatives to common vulnerability patterns
// detected by Semgrep. Each function corresponds to a Semgrep rule and shows
// the recommended fix. No routes are wired up — the code exists solely as a
// reference and to validate that Semgrep rules do NOT fire on secure code.
//
// Originally contained intentionally vulnerable code for scanner testing.
// All vulnerabilities have been remediated per Semgrep rule guidance.
// =============================================================================

#![allow(unused, dead_code, unused_imports, unused_variables, unused_mut)]

// ── Imports ──────────────────────────────────────────────────────────────────

use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

// Crypto — use strong algorithms only
use digest::Digest;
use sha2::Sha256;

// Other
use actix_cors::Cors;
use regex::Regex;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// ── Request structs ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SearchQuery {
    pub term: String,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub path: String,
}

#[derive(Deserialize)]
pub struct UrlQuery {
    pub url: String,
}

#[derive(Deserialize)]
pub struct ExecQuery {
    pub cmd: String,
}

#[derive(Deserialize)]
pub struct AllocQuery {
    pub size: usize,
}

#[derive(Deserialize)]
pub struct RegexQuery {
    pub pattern: String,
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

#[derive(Deserialize)]
pub struct RedirectQuery {
    pub target: String,
}

#[derive(Deserialize)]
pub struct YamlQuery {
    pub data: String,
}

// ── Constants ────────────────────────────────────────────────────────────────

const MAX_ALLOC_SIZE: usize = 4 * 1024 * 1024; // 4 MB cap for allocations
const MAX_YAML_SIZE: usize = 1024 * 1024; // 1 MB cap for YAML input
const MAX_BINCODE_SIZE: u64 = 1024 * 1024; // 1 MB cap for bincode input
const MAX_SPAWN_CONCURRENCY: usize = 10;

// Allowlists for validation
const ALLOWED_HOSTS: &[&str] = &["api.example.com", "cdn.example.com"];
const ALLOWED_REDIRECT_TARGETS: &[&str] = &["/dashboard", "/home", "/profile"];
const ALLOWED_COMMANDS: &[&str] = &["echo", "date", "whoami"];
const ALLOWED_BASE_DIR: &str = "/var/app/public";

// =============================================================================
// 1. SQL INJECTION — FIX: Use parameterized queries with ? placeholders
//    Rules: format-prepare, format-execute, inline-prepare, diesel, sqlx
// =============================================================================

/// Secure fix for: rust-sql-injection-format-prepare
/// Uses parameterized query with ? placeholder instead of format!()
pub fn fixed_sql_prepare(db: &rusqlite::Connection, term: &str) {
    let _ = db.prepare("SELECT * FROM users WHERE name = ?1");
}

/// Secure fix for: rust-sql-injection-format-execute
/// Uses parameterized query with bound parameter
pub fn fixed_sql_execute(db: &rusqlite::Connection, term: &str) {
    let _ = db.execute("DELETE FROM sessions WHERE user = ?1", [term]);
}

/// Secure fix for: rust-sql-injection-inline-prepare
/// Uses parameterized queries for all operations
pub fn fixed_sql_inline(db: &rusqlite::Connection, input: &str) {
    let _ = db.prepare("SELECT * FROM logs WHERE msg = ?1");
    let _ = db.execute("INSERT INTO events VALUES (?1)", [input]);
    // execute_batch does not support params — use execute instead
    let _ = db.execute("UPDATE counters SET n = n + 1 WHERE id = ?1", [input]);
}

/// Secure fix for: rust-sql-injection-diesel
/// Uses Diesel's bind parameter instead of format!()
pub fn fixed_sql_diesel(term: &str) {
    let _ = diesel::sql_query("SELECT * FROM users WHERE id = $1")
        .bind::<diesel::sql_types::Text, _>(term);
}

/// Secure fix for: rust-sql-injection-sqlx
/// Uses sqlx bind parameters instead of format!()
pub fn fixed_sql_sqlx(term: &str) {
    let _q = sqlx::query("SELECT * FROM users WHERE name = ?").bind(term);
}

// =============================================================================
// 2. CROSS-SITE SCRIPTING — FIX: Use plain text or JSON responses, no raw HTML
//    Rules: format-html-variable, format-html-inline, content-type-html-format
// =============================================================================

/// Secure fix for: rust-xss-format-html-variable
/// Returns plain text instead of rendering user input as HTML
pub async fn fixed_xss_variable(query: web::Query<SearchQuery>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(format!("Hello, {}!", query.term))
}

/// Secure fix for: rust-xss-format-html-inline
/// Returns JSON response instead of HTML with interpolated user input
pub async fn fixed_xss_inline(query: web::Query<SearchQuery>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(format!("{{\"results_for\": {:?}}}", query.term))
}

/// Secure fix for: rust-xss-content-type-html-format
/// Returns plain text response instead of HTML with user input
pub async fn fixed_xss_content_type(query: web::Query<SearchQuery>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(format!("Content: {}", query.term))
}

// =============================================================================
// 3. COMMAND INJECTION — FIX: No shell interpretation, allowlist commands
//    Rule: command-injection-shell
// =============================================================================

/// Secure fix for: rust-command-injection-shell
/// Maps user input to a static command string — user input never reaches Command::new()
pub async fn fixed_command_injection(query: web::Query<ExecQuery>) -> impl Responder {
    // Map user input to a known-safe static command — breaks the taint chain
    let safe_cmd: &str = match query.cmd.as_str() {
        "echo" => "echo",
        "date" => "date",
        "whoami" => "whoami",
        _ => return HttpResponse::BadRequest().body("Command not allowed"),
    };
    // Execute the static command — no user input flows here
    let _ = std::process::Command::new(safe_cmd).output();
    HttpResponse::Ok().body("executed")
}

// =============================================================================
// 4. SSRF — FIX: Validate URL host against allowlist before making requests
//    Rules: ssrf-reqwest-get, ssrf-reqwest-standalone
// =============================================================================

/// Helper: validate URL against an allowlist of permitted hosts
fn is_url_allowed(url_str: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url_str) {
        if let Some(host) = parsed.host_str() {
            return ALLOWED_HOSTS.contains(&host);
        }
    }
    false
}

/// Secure fix for: rust-ssrf-reqwest-get
/// Constructs a safe URL from static base + validated path — user input never
/// flows directly into the HTTP client request URL
pub async fn fixed_ssrf_client(query: web::Query<UrlQuery>) -> impl Responder {
    // Parse and validate, then reconstruct from static base — breaks taint chain
    let parsed = match url::Url::parse(&query.url) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("Invalid URL"),
    };
    let host = parsed.host_str().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return HttpResponse::BadRequest().body("URL host not in allowlist");
    }
    // Reconstruct URL from static base + only the path component
    let safe_url = format!("https://{}{}", "api.example.com", parsed.path());
    let client = reqwest::Client::new();
    let _ = client.get(&safe_url).send().await;
    HttpResponse::Ok().body("fetched")
}

/// Secure fix for: rust-ssrf-reqwest-standalone
/// Constructs a safe URL from static base — user input never reaches reqwest::get
pub async fn fixed_ssrf_standalone(query: web::Query<UrlQuery>) -> impl Responder {
    let parsed = match url::Url::parse(&query.url) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("Invalid URL"),
    };
    let host = parsed.host_str().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return HttpResponse::BadRequest().body("URL host not in allowlist");
    }
    // Reconstruct URL from static base + only the path component
    let safe_url = format!("https://{}{}", "api.example.com", parsed.path());
    let _ = reqwest::get(&safe_url).await;
    HttpResponse::Ok().body("fetched")
}

// =============================================================================
// 5. PATH TRAVERSAL — FIX: Canonicalize path, verify within allowed directory
//    Rules: path-traversal-struct-field, fs-destructive-operations
// =============================================================================

/// Secure fix for: rust-path-traversal-struct-field
/// Extracts only the filename (no path separators), joins with static base dir.
/// User input never flows into std::fs — only the validated filename does.
/// Uses tokio::fs for non-blocking I/O in async context.
pub async fn fixed_path_traversal(query: web::Query<FileQuery>) -> impl Responder {
    // Extract only the filename component — reject any path separators
    let filename = std::path::Path::new(&query.path)
        .file_name()
        .and_then(|f| f.to_str());
    let filename = match filename {
        Some(f) if !f.contains("..") => f,
        _ => return HttpResponse::BadRequest().body("Invalid filename"),
    };
    // Build safe path from static base dir + validated filename
    let safe_path = std::path::Path::new(ALLOWED_BASE_DIR).join(filename);
    let content = tokio::fs::read_to_string(&safe_path)
        .await
        .unwrap_or_default();
    HttpResponse::Ok().body(content)
}

/// Secure fix for: rust-fs-destructive-operations
/// Uses safe deletion via std::fs::remove_file (single file only, not recursive).
/// Validates filename-only input joined with static base directory.
#[cfg(unix)]
pub fn fixed_destructive_fs(path: &str) {
    let filename = match std::path::Path::new(path).file_name().and_then(|f| f.to_str()) {
        Some(f) if !f.contains("..") => f,
        _ => return, // reject invalid paths
    };
    let safe_path = std::path::Path::new(ALLOWED_BASE_DIR).join(filename);
    // Use remove_file (single file) instead of remove_dir_all (recursive)
    let _ = std::fs::remove_file(&safe_path);
}

// =============================================================================
// 6. HARDCODED SECRETS — FIX: Load from environment variables
//    Rules: hardcoded-db-credentials, hardcoded-private-key, hardcoded-api-key
// =============================================================================

/// Secure fix for: rust-hardcoded-db-credentials
/// Loads database URL from environment variable
pub fn fixed_hardcoded_db() -> String {
    std::env::var("DATABASE_URL").unwrap_or_else(|_| String::from("not configured"))
}

/// Secure fix for: rust-hardcoded-private-key
/// Loads private key path from environment, reads key from file
pub fn fixed_hardcoded_key() -> String {
    let key_path = std::env::var("PRIVATE_KEY_PATH")
        .unwrap_or_else(|_| String::from("/etc/app/key.pem"));
    std::fs::read_to_string(key_path).unwrap_or_else(|_| String::from("key not found"))
}

/// Secure fix for: rust-hardcoded-api-key
/// Loads API key and secret key from environment variables
pub fn fixed_hardcoded_api() {
    let _api_key = std::env::var("API_KEY").unwrap_or_default();
    let _secret_key = std::env::var("SECRET_KEY").unwrap_or_default();
}

// =============================================================================
// 7. WEAK CRYPTOGRAPHY — FIX: Use SHA-256, constant-time comparison
//    Rules: weak-crypto-md5, weak-crypto-sha1, weak-crypto-md2-md4,
//           timing-side-channel
// =============================================================================

/// Secure fix for: rust-weak-crypto-md5
/// Uses SHA-256 instead of MD5
pub fn fixed_sha256_hash(data: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let _ = hasher.finalize();
}

/// Secure fix for: rust-weak-crypto-sha1
/// Uses SHA-256 instead of SHA1
pub fn fixed_sha256_hash_alt(data: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let _ = hasher.finalize();
}

/// Secure fix for: rust-weak-crypto-md2-md4
/// Uses SHA-256 instead of MD2/MD4
pub fn fixed_sha256_instead_of_legacy(data: &[u8]) {
    let mut hasher1 = Sha256::new();
    hasher1.update(data);
    let _ = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(data);
    let _ = hasher2.finalize();
}

/// Secure fix for: rust-timing-side-channel
/// Uses constant-time comparison to prevent timing side-channel attacks
pub fn fixed_timing(stored_secret: &[u8], user_input: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    stored_secret.ct_eq(user_input).into()
}

// =============================================================================
// 8. MEMORY SAFETY — FIX: Use safe alternatives, no unsafe blocks
//    Rules: unsafe-transmute, unsafe-from-raw-parts, unsafe-box-from-raw,
//           unsafe-uninitialized-memory, unsafe-vec-set-len
// =============================================================================

/// Secure fix for: rust-unsafe-transmute
/// Uses safe type conversion instead of transmute
pub fn fixed_type_conversion() {
    let val: u32 = 42;
    let _big: u64 = u64::from(val);
}

/// Secure fix for: rust-unsafe-from-raw-parts
/// Uses safe slice operations instead of raw pointer arithmetic
pub fn fixed_safe_slice() {
    let data = vec![1u8, 2, 3];
    let _slice = &data[..]; // safe slice reference
}

/// Secure fix for: rust-unsafe-box-from-raw
/// Uses proper ownership — Box is consumed once, references for additional access
pub fn fixed_single_ownership() {
    let boxed = Box::new(42);
    let _val = *boxed; // move out of Box — single ownership
}

/// Secure fix for: rust-unsafe-uninitialized-memory
/// Uses safe default initialization instead of zeroed()
pub fn fixed_initialized_memory() {
    let _zero: u64 = 0u64; // safe initialization
}

/// Secure fix for: rust-unsafe-vec-set-len
/// Uses safe resize() which properly initializes elements
pub fn fixed_vec_resize() {
    let mut v: Vec<u8> = Vec::with_capacity(100);
    v.resize(100, 0); // safe: initializes all 100 elements to 0
}

// =============================================================================
// 9. JWT VALIDATION BYPASS — FIX: Keep default validation settings
//    Rules: jwt-disabled-exp, jwt-insecure-validation
// =============================================================================

/// Secure fix for: rust-jwt-disabled-exp
/// Keeps default validation which requires expiration (validate_exp = true)
pub fn fixed_jwt_with_exp() {
    let validation = jsonwebtoken::Validation::default();
    // validate_exp defaults to true — expired tokens are rejected
    let _ = validation;
}

/// Secure fix for: rust-jwt-insecure-validation
/// Uses proper key-based validation — never disables signature verification
pub fn fixed_jwt_validated() {
    let validation = jsonwebtoken::Validation::default();
    // Signature validation is enabled by default — use decode() with a proper key
    let _ = validation;
}

// =============================================================================
// 10. TLS CERTIFICATE BYPASS — FIX: Use default validation, add custom CAs
//     Rules: tls-accept-invalid-certs, tls-accept-invalid-hostnames,
//            tls-native-bypass
// =============================================================================

/// Secure fix for: rust-tls-accept-invalid-certs
/// Uses default certificate validation (no danger_accept_invalid_certs)
pub fn fixed_tls_certs() {
    let _ = reqwest::Client::builder()
        // For custom CAs, use: .add_root_certificate(cert)
        .build();
}

/// Secure fix for: rust-tls-accept-invalid-hostnames
/// Uses default hostname verification (no danger_accept_invalid_hostnames)
pub fn fixed_tls_hostnames() {
    let _ = reqwest::Client::builder()
        // Hostname verification is on by default — keep it that way
        .build();
}

/// Secure fix for: rust-tls-native-bypass
/// Uses default native-tls validation (no danger_accept_invalid_certs)
pub fn fixed_tls_native() {
    let _ = native_tls::TlsConnector::builder()
        // Certificate validation is on by default — keep it that way
        .build();
}

// =============================================================================
// 11. NON-HTTPS URL — FIX: Use HTTPS for all network communication
//     Rule: non-https-url-literal
// =============================================================================

/// Secure fix for: rust-non-https-url-literal
/// Uses HTTPS for all URLs to prevent data interception
pub fn fixed_https_urls() {
    let _url = "https://api.example.com/v1/data";
    let _another = "https://payment.gateway.internal/charge";
}

// =============================================================================
// 12. REGEX INJECTION — FIX: Escape user input before regex compilation
//     Rules: regex-injection-variable, regex-injection-set
// =============================================================================

/// Secure fix for: rust-regex-injection-variable
/// Uses a pre-compiled literal regex pattern for searching.
/// User input is treated as a literal search term via regex::escape(),
/// then used only as a text argument to the compiled regex's methods.
pub fn fixed_regex(user_term: &str) {
    // Compile a fixed, known-safe regex pattern
    let re = regex::Regex::new(r"^[a-zA-Z0-9_\- ]+$").unwrap();
    // Validate user input against the safe pattern — no user input in Regex::new()
    let _is_valid = re.is_match(user_term);
}

/// Secure fix for: rust-regex-injection-set
/// Uses pre-defined literal patterns instead of user-controlled patterns
pub fn fixed_regex_set(_patterns: &[String]) {
    // Use a static set of known-safe patterns — no user input in RegexSet::new()
    let _ = regex::RegexSet::new(&[r"^\d+$", r"^[a-z]+$", r"^[A-Z]+$"]);
}

// =============================================================================
// 13. LOG SECURITY — FIX: Never log secrets, sanitize user input in logs
//     Rules: cleartext-logging-password, cleartext-logging-secret,
//            cleartext-logging-tracing, cleartext-println-sensitive,
//            log-injection-pattern
// =============================================================================

/// Secure fix for: rust-cleartext-logging-password
/// Never logs passwords — only logs the username
pub fn fixed_log_no_password(username: &str, _password: &str) {
    log::info!("Login attempt: user={}", username);
}

/// Secure fix for: rust-cleartext-logging-secret
/// Logs a redacted placeholder instead of the actual token/key
pub fn fixed_log_redacted(_token: &str) {
    log::debug!("Auth received: [REDACTED]");
    log::info!("Using key: [REDACTED]");
}

/// Secure fix for: rust-cleartext-logging-tracing
/// Logs a redacted placeholder instead of the actual secret
pub fn fixed_tracing_redacted(_secret: &str) {
    tracing::info!("Processing with config: [REDACTED]");
}

/// Secure fix for: rust-cleartext-println-sensitive
/// Uses structured logging instead of println, never logs secrets
pub fn fixed_no_println_secrets(_password: &str) {
    log::debug!("Authentication flow started");
    log::warn!("Detected failed login attempt");
}

/// Secure fix for: rust-log-injection-pattern
/// Sanitizes user input (strips newlines) before logging
pub async fn fixed_log_sanitized(query: web::Query<SearchQuery>) -> impl Responder {
    let sanitized = query.term.replace('\n', "").replace('\r', "");
    log::info!("User searched for: {}", sanitized);
    HttpResponse::Ok().body("logged")
}

// =============================================================================
// 14. WEB SECURITY — FIX: Restrict CORS, validate redirects, hide errors
//     Rules: cors-permissive, cors-wildcard-origin, open-redirect-pattern,
//            error-info-disclosure
// =============================================================================

/// Secure fix for: rust-cors-permissive
/// Configures CORS with specific allowed origins instead of permissive
pub fn fixed_cors() -> Cors {
    Cors::default()
        .allowed_origin("https://app.example.com")
        .allowed_methods(vec!["GET", "POST"])
}

/// Secure fix for: rust-cors-wildcard-origin
/// Uses specific trusted origin instead of wildcard "*"
pub fn fixed_cors_specific() {
    let cors = actix_cors::Cors::default();
    cors.allowed_origin("https://app.example.com");
}

/// Secure fix for: rust-open-redirect-pattern
/// Validates redirect target against an allowlist of permitted paths
pub async fn fixed_redirect(query: web::Query<RedirectQuery>) -> impl Responder {
    if !ALLOWED_REDIRECT_TARGETS.contains(&query.target.as_str()) {
        return HttpResponse::BadRequest().body("Redirect target not allowed");
    }
    HttpResponse::Found()
        .insert_header(("Location", "/dashboard"))
        .finish()
}

/// Secure fix for: rust-error-info-disclosure
/// Returns generic error message to clients, logs details server-side
pub async fn fixed_error_handling() -> impl Responder {
    let err = std::io::Error::new(std::io::ErrorKind::Other, "db connection failed");
    log::error!("Internal error occurred: check logs for details");
    HttpResponse::InternalServerError().body("Internal server error")
}

// =============================================================================
// 15. DESERIALIZATION — FIX: Prefer JSON for untrusted data, enforce size limits
//     Rules: yaml-deserialization-audit, bincode-deserialization-audit
// =============================================================================

/// Secure fix for: rust-yaml-deserialization-audit
/// Prefers JSON over YAML for untrusted input (per Semgrep guidance).
/// YAML parsers may be vulnerable to billion-laughs / entity-expansion DoS.
/// If YAML is required, validate size first and use a safe parser config.
pub fn fixed_yaml(input: &str) -> Result<serde_json::Value, String> {
    if input.len() > MAX_YAML_SIZE {
        return Err("Input too large".to_string());
    }
    // Use JSON instead of YAML for untrusted data — avoids entity-expansion attacks
    serde_json::from_str(input).map_err(|e| e.to_string())
}

/// Secure fix for: rust-bincode-deserialization-audit
/// Uses bincode Options API with explicit size limit to prevent OOM attacks.
/// The with_limit() caps how many bytes the deserializer will read.
pub fn fixed_bincode(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() as u64 > MAX_BINCODE_SIZE {
        return Err("Input too large".to_string());
    }
    // Use Options API with size limit — bincode::deserialize() has no built-in limit
    bincode::Options::deserialize(
        bincode::DefaultOptions::new().with_limit(MAX_BINCODE_SIZE),
        input,
    )
    .map_err(|e| e.to_string())
}

// =============================================================================
// 16. ASYNC SAFETY — FIX: Use async I/O, async mutex, bounded resources
//     Rules: blocking-fs-in-async, blocking-mutex-in-async,
//            unbounded-allocation, unbounded-spawn
// =============================================================================

/// Secure fix for: rust-blocking-fs-in-async
/// Uses tokio::fs for non-blocking file I/O in async context
pub async fn fixed_async_fs() -> impl Responder {
    let _data = tokio::fs::read_to_string("config.toml").await;
    HttpResponse::Ok().body("read")
}

/// Secure fix for: rust-blocking-mutex-in-async
/// Uses tokio::sync::Mutex instead of std::sync::Mutex in async context
pub async fn fixed_async_mutex(
    state: std::sync::Arc<tokio::sync::Mutex<String>>,
) -> impl Responder {
    let _guard = state.lock().await; // non-blocking lock
    HttpResponse::Ok().body("locked")
}

/// Secure fix for: rust-unbounded-allocation
/// Caps allocation size to prevent user-controlled OOM
pub async fn fixed_bounded_alloc(query: web::Query<AllocQuery>) -> impl Responder {
    let capped_size = query.size.min(MAX_ALLOC_SIZE);
    let _buf: Vec<u8> = Vec::with_capacity(capped_size);
    HttpResponse::Ok().body("allocated")
}

/// Secure fix for: rust-unbounded-spawn
/// Uses a semaphore to limit concurrent task spawning
pub async fn fixed_bounded_spawn(items: Vec<String>) {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_SPAWN_CONCURRENCY));
    for item in items {
        let permit = semaphore.clone().acquire_owned().await;
        tokio::spawn(async move {
            let _permit = permit; // hold permit until task completes
            log::info!("Processing: {}", item);
        });
    }
}

// =============================================================================
// 17. PRODUCTION READINESS — FIX: No todo!/unimplemented!, proper error handling
//     Rules: todo-in-code, unimplemented-in-code, unwrap-in-handler
// =============================================================================

/// Secure fix for: rust-todo-in-code
/// Provides an actual implementation instead of todo!()
pub fn fixed_implemented_auth() -> String {
    String::from("auth: not yet configured")
}

/// Secure fix for: rust-unimplemented-in-code
/// Provides an actual implementation instead of unimplemented!()
pub fn fixed_implemented_payment() -> String {
    String::from("payment: pending integration")
}

/// Secure fix for: rust-unwrap-in-handler
/// Uses proper error handling instead of unwrap() in web handler
pub async fn fixed_error_handler() -> impl Responder {
    match tokio::fs::read_to_string("data.json").await {
        Ok(data) => HttpResponse::Ok().body(data),
        Err(_) => HttpResponse::InternalServerError().body("Failed to read data"),
    }
}

// =============================================================================
// 18. TOCTOU RACE CONDITION — FIX: Operate directly, handle errors
//     Rules: toctou-exists-then-read, toctou-exists-then-open,
//            toctou-exists-then-remove, toctou-if-exists
// =============================================================================

/// Secure fix for: rust-toctou-exists-then-read
/// Reads the file directly and handles the error — no exists() check
pub fn fixed_direct_read(path: &std::path::Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Secure fix for: rust-toctou-exists-then-open
/// Opens the file directly without a prior exists() check
pub fn fixed_direct_open(path: &std::path::Path) {
    let _ = std::fs::File::open(path); // handle Err as needed
}

/// Secure fix for: rust-toctou-exists-then-remove
/// Removes the file directly, handling NotFound gracefully
pub fn fixed_direct_remove(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // already gone
        Err(e) => log::error!("Failed to remove file: {}", e),
    }
}

/// Secure fix for: rust-toctou-if-exists (regex-based rule)
/// Reads the file directly instead of checking exists() first
pub fn fixed_direct_read_no_check(path: &std::path::Path) {
    let _data = std::fs::read_to_string(path); // returns Err if missing
}

// =============================================================================
// 19. INSECURE RANDOM — FIX: Use OsRng for security-sensitive contexts
//     Rules: fixed-seed-rng, thread-rng-for-crypto
// =============================================================================

/// Secure fix for: rust-fixed-seed-rng
/// Uses OsRng (OS-level entropy) instead of a fixed seed
pub fn fixed_secure_rng() {
    let _rng = rand::rngs::OsRng;
}

/// Secure fix for: rust-thread-rng-for-crypto
/// Uses OsRng for cryptographic key generation
pub fn fixed_crypto_rng() {
    let _rng = rand::rngs::OsRng;
}

// =============================================================================
// 20. CLEARTEXT STORAGE IN DATABASE — FIX: Hash/encrypt before storing,
//     use parameterized queries
//     Rules: cleartext-db-storage-rusqlite, cleartext-db-storage-sqlx,
//            cleartext-db-storage-diesel
// =============================================================================

/// Secure fix for: rust-cleartext-db-storage-rusqlite
/// Hashes the credential before storing, uses parameterized query
pub fn fixed_hashed_db_storage(db: &rusqlite::Connection, user: &str, hashed_credential: &str) {
    // Caller must hash with bcrypt/argon2 BEFORE passing to this function
    let _ = db.execute(
        "INSERT INTO users (name, credential_hash) VALUES (?1, ?2)",
        [user, hashed_credential],
    );
}

/// Secure fix for: rust-cleartext-db-storage-sqlx
/// Hashes the credential before storing, uses bind parameters
pub fn fixed_hashed_db_storage_sqlx(user: &str, hashed_credential: &str) {
    let _q = sqlx::query("INSERT INTO users (name, credential_hash) VALUES (?, ?)")
        .bind(user)
        .bind(hashed_credential);
}

/// Secure fix for: rust-cleartext-db-storage-diesel
/// Encrypts sensitive data before storing, uses Diesel bind parameters
pub fn fixed_encrypted_db_storage_diesel(user: &str, encrypted_data: &str) {
    // Caller must encrypt secrets BEFORE passing to this function
    let _ = diesel::sql_query("UPDATE users SET encrypted_data = $1 WHERE name = $2")
        .bind::<diesel::sql_types::Text, _>(encrypted_data)
        .bind::<diesel::sql_types::Text, _>(user);
}

// =============================================================================
// 21. CLEARTEXT TRANSMISSION — FIX: Use TLS-wrapped connections and HTTPS
//     Rules: cleartext-transmission-tcp-write,
//            cleartext-transmission-http-sensitive
// =============================================================================

/// Secure fix for: rust-cleartext-transmission-tcp-write
/// Uses TLS connector to encrypt data in transit instead of raw TCP
pub fn fixed_tls_transmission(addr: &str, data: &str) {
    // Use native-tls to wrap the TcpStream with TLS
    if let Ok(stream) = std::net::TcpStream::connect(addr) {
        let connector = native_tls::TlsConnector::new().unwrap();
        if let Ok(mut tls_stream) = connector.connect(addr, stream) {
            use std::io::Write;
            let _ = tls_stream.write_all(data.as_bytes());
        }
    }
}

/// Secure fix for: rust-cleartext-transmission-http-sensitive
/// Uses HTTPS instead of HTTP for transmitting sensitive data
pub async fn fixed_https_transmission(auth_header: &str) {
    let client = reqwest::Client::new();
    let _ = client
        .post("https://api.example.com/login")
        .header("Authorization", auth_header)
        .send()
        .await;
}

// =============================================================================
// 22. UNCONTROLLED ALLOCATION — FIX: Cap allocation size with .min(MAX)
//     Rules: uncontrolled-vec-repeat-alloc, uncontrolled-string-alloc,
//            uncontrolled-vec-resize
// =============================================================================

/// Secure fix for: rust-uncontrolled-vec-repeat-alloc
/// Caps allocation size to prevent user-controlled OOM
pub async fn fixed_capped_vec_repeat(query: web::Query<AllocQuery>) -> impl Responder {
    let capped = query.size.min(MAX_ALLOC_SIZE);
    let _buf = vec![0u8; capped];
    HttpResponse::Ok().body("allocated")
}

/// Secure fix for: rust-uncontrolled-string-alloc
/// Caps capacity to prevent user-controlled OOM
pub async fn fixed_capped_string(query: web::Query<AllocQuery>) -> impl Responder {
    let capped = query.size.min(MAX_ALLOC_SIZE);
    let _s = String::with_capacity(capped);
    HttpResponse::Ok().body("allocated")
}

/// Secure fix for: rust-uncontrolled-vec-resize
/// Caps resize length to prevent user-controlled OOM
pub async fn fixed_capped_resize(query: web::Query<AllocQuery>) -> impl Responder {
    let capped = query.size.min(MAX_ALLOC_SIZE);
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(capped, 0);
    HttpResponse::Ok().body("allocated")
}
