// =============================================================================
// INTENTIONALLY VULNERABLE RUST CODE — FOR SECURITY SCANNER TESTING
// =============================================================================
// This module is compiled (registered via `mod vulnerable;` in main.rs) so
// that BOTH Semgrep AND CodeQL can analyze it. No routes are wired up — the
// code exists solely to produce scanner findings.
//
// Compare results: Semgrep (custom rules) vs CodeQL (built-in Rust queries)
// =============================================================================

#![allow(
    unused,
    dead_code,
    deprecated,
    unreachable_code,
    clippy::all,
    unused_imports,
    unused_variables,
    unused_mut,
    unused_must_use,
    invalid_value
)]

// ── Imports ──────────────────────────────────────────────────────────────────

use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

// Crypto
use digest::Digest;
use md5::Md5; // from md-5 crate (RustCrypto)
use sha1::Sha1;
use md2::Md2;
use md4::Md4;

// Other
use actix_cors::Cors;
use rand::SeedableRng;
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

// =============================================================================
// 1. SQL INJECTION (rust-sql-injection.yml)
//    Rules: format-prepare, format-execute, inline-prepare, diesel, sqlx
// =============================================================================

/// Triggers: rust-sql-injection-format-prepare
pub fn vuln_sql_prepare(db: &rusqlite::Connection, term: &str) {
    let sql = format!("SELECT * FROM users WHERE name = '{}'", term);
    let _ = db.prepare(&sql);
}

/// Triggers: rust-sql-injection-format-execute
pub fn vuln_sql_execute(db: &rusqlite::Connection, term: &str) {
    let sql = format!("DELETE FROM sessions WHERE user = '{}'", term);
    let _ = db.execute(&sql, []);
}

/// Triggers: rust-sql-injection-inline-prepare
pub fn vuln_sql_inline(db: &rusqlite::Connection, input: &str) {
    let _ = db.prepare(&format!("SELECT * FROM logs WHERE msg = '{}'", input));
    let _ = db.execute(&format!("INSERT INTO events VALUES ('{}')", input), []);
    let _ = db.execute_batch(&format!(
        "UPDATE counters SET n = n + 1 WHERE id = '{}'",
        input
    ));
}

/// Triggers: rust-sql-injection-diesel
pub fn vuln_sql_diesel(term: &str) {
    let _ = diesel::sql_query(format!(
        "SELECT * FROM users WHERE id = {}",
        term
    ));
}

/// Triggers: rust-sql-injection-sqlx
pub fn vuln_sql_sqlx(term: &str) {
    sqlx::query(&format!(
        "SELECT * FROM users WHERE name = '{}'",
        term
    ));
}

// =============================================================================
// 2. CROSS-SITE SCRIPTING (rust-xss.yml)
//    Rules: format-html-variable, format-html-inline, content-type-html-format
// =============================================================================

/// Triggers: rust-xss-format-html-variable
pub async fn vuln_xss_variable(query: web::Query<SearchQuery>) -> impl Responder {
    let html = format!("<h1>Hello, {}!</h1>", query.term);
    HttpResponse::Ok().content_type("text/html").body(html)
}

/// Triggers: rust-xss-format-html-inline
pub async fn vuln_xss_inline(query: web::Query<SearchQuery>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(format!("<p>Search results for: {}</p>", query.term))
}

/// Triggers: rust-xss-content-type-html-format
pub async fn vuln_xss_content_type(query: web::Query<SearchQuery>) -> impl Responder {
    let body = format!("<div>{}</div>", query.term);
    let mut resp = HttpResponse::Ok();
    resp.content_type("text/html").body(body)
}

// =============================================================================
// 3. COMMAND INJECTION (rust-command-injection.yml)
// =============================================================================

/// Triggers: rust-command-injection-shell
pub async fn vuln_command_injection(query: web::Query<ExecQuery>) -> impl Responder {
    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(&query.cmd)
        .output();
    HttpResponse::Ok().body("executed")
}

// =============================================================================
// 4. SSRF (rust-ssrf.yml)
//    Rules: ssrf-reqwest-get, ssrf-reqwest-standalone
// =============================================================================

/// Triggers: rust-ssrf-reqwest-get
pub async fn vuln_ssrf_client(query: web::Query<UrlQuery>) -> impl Responder {
    let client = reqwest::Client::new();
    let _ = client.get(&query.url).send().await;
    HttpResponse::Ok().body("fetched")
}

/// Triggers: rust-ssrf-reqwest-standalone
pub async fn vuln_ssrf_standalone(query: web::Query<UrlQuery>) -> impl Responder {
    let _ = reqwest::get(&query.url).await;
    HttpResponse::Ok().body("fetched")
}

// =============================================================================
// 5. PATH TRAVERSAL (rust-path-traversal.yml)
//    Rules: path-traversal-struct-field, fs-destructive-operations
// =============================================================================

/// Triggers: rust-path-traversal-struct-field
pub async fn vuln_path_traversal(query: web::Query<FileQuery>) -> impl Responder {
    let content = std::fs::read_to_string(&query.path).unwrap_or_default();
    HttpResponse::Ok().body(content)
}

/// Triggers: rust-fs-destructive-operations
#[cfg(unix)]
pub fn vuln_destructive_fs(path: &str) {
    let _ = std::fs::remove_dir_all(path);
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777));
}

// =============================================================================
// 6. HARDCODED SECRETS (rust-hardcoded-secrets.yml)
//    Rules: hardcoded-db-credentials, hardcoded-private-key, hardcoded-api-key
//    NOTE: TruffleHog excludes this file via .trufflehog-exclude.txt
// =============================================================================

/// Triggers: rust-hardcoded-db-credentials
pub fn vuln_hardcoded_db() -> &'static str {
    "postgres://admin:hunter2@db.internal:5432/myapp"
}

/// Triggers: rust-hardcoded-private-key
pub fn vuln_hardcoded_key() -> &'static str {
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ..."
}

/// Triggers: rust-hardcoded-api-key
pub fn vuln_hardcoded_api() {
    let api_key = "abcdefghijklmnopqrstuvwxyz123456";
    let secret_key = "AAAAAAAAAAAAAAAA";
}

// =============================================================================
// 7. WEAK CRYPTOGRAPHY (rust-weak-crypto.yml)
//    Rules: weak-crypto-md5, weak-crypto-sha1, weak-crypto-md2-md4,
//           timing-side-channel
// =============================================================================

/// Triggers: rust-weak-crypto-md5 (Md5::new pattern)
pub fn vuln_md5(data: &[u8]) {
    let mut hasher = Md5::new();
    hasher.update(data);
    let _ = hasher.finalize();
}

/// Triggers: rust-weak-crypto-sha1
pub fn vuln_sha1(data: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let _ = hasher.finalize();
}

/// Triggers: rust-weak-crypto-md2-md4
pub fn vuln_md2_md4(data: &[u8]) {
    let _ = Md2::new();
    let _ = Md4::new();
}

/// Triggers: rust-timing-side-channel
pub fn vuln_timing(stored_secret: &str, user_input: &str) -> bool {
    stored_secret == user_input
}

// =============================================================================
// 8. MEMORY SAFETY (rust-memory-safety.yml)
//    Rules: unsafe-transmute, unsafe-from-raw-parts, unsafe-box-from-raw,
//           unsafe-uninitialized-memory, unsafe-vec-set-len
// =============================================================================

/// Triggers: rust-unsafe-transmute
pub fn vuln_transmute() {
    unsafe {
        let val: u32 = 42;
        let _big: u64 = std::mem::transmute::<[u32; 2], u64>([val, 0]);
    }
}

/// Triggers: rust-unsafe-from-raw-parts
pub fn vuln_from_raw_parts() {
    unsafe {
        let data = vec![1u8, 2, 3];
        let _slice = std::slice::from_raw_parts(data.as_ptr(), 100);
    }
}

/// Triggers: rust-unsafe-box-from-raw
pub fn vuln_box_from_raw() {
    unsafe {
        let ptr = Box::into_raw(Box::new(42));
        let _a = Box::from_raw(ptr);
        let _b = Box::from_raw(ptr);
    }
}

/// Triggers: rust-unsafe-uninitialized-memory
pub fn vuln_uninitialized() {
    unsafe {
        let _zero: u64 = std::mem::zeroed();
    }
}

/// Triggers: rust-unsafe-vec-set-len
pub fn vuln_set_len() {
    unsafe {
        let mut v: Vec<u8> = Vec::with_capacity(3);
        v.set_len(100);
    }
}

// =============================================================================
// 9. JWT VALIDATION BYPASS (rust-jwt-validation.yml)
//    Rules: jwt-disabled-exp, jwt-insecure-validation
//    NOTE: dangerous_insecure_decode was removed in jsonwebtoken v8+.
//    We pin to v9.x so we test the 2 current-API rules.
// =============================================================================

/// Triggers: rust-jwt-disabled-exp
pub fn vuln_jwt_no_exp() {
    let mut validation = jsonwebtoken::Validation::default();
    validation.validate_exp = false;
}

/// Triggers: rust-jwt-insecure-validation
pub fn vuln_jwt_insecure() {
    let mut validation = jsonwebtoken::Validation::default();
    validation.insecure_disable_signature_validation();
}

// =============================================================================
// 10. TLS CERTIFICATE BYPASS (rust-tls-bypass.yml)
//     Rules: tls-accept-invalid-certs, tls-accept-invalid-hostnames,
//            tls-native-bypass
// =============================================================================

/// Triggers: rust-tls-accept-invalid-certs
pub fn vuln_tls_certs() {
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
}

/// Triggers: rust-tls-accept-invalid-hostnames
pub fn vuln_tls_hostnames() {
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_hostnames(true)
        .build();
}

/// Triggers: rust-tls-native-bypass
pub fn vuln_tls_native() {
    let _ = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build();
}

// =============================================================================
// 11. NON-HTTPS URL (rust-non-https.yml)
// =============================================================================

/// Triggers: rust-non-https-url-literal
pub fn vuln_http_url() {
    let _url = "http://api.example.com/v1/data";
    let _another = "http://payment.gateway.internal/charge";
}

// =============================================================================
// 12. REGEX INJECTION (rust-regex-injection.yml)
//     Rules: regex-injection-variable, regex-injection-set
// =============================================================================

/// Triggers: rust-regex-injection-variable
pub fn vuln_regex(pattern: &str) {
    let _ = regex::Regex::new(pattern);
    let _ = Regex::new(pattern);
}

/// Triggers: rust-regex-injection-set
pub fn vuln_regex_set(patterns: &[String]) {
    let _ = regex::RegexSet::new(patterns);
}

// =============================================================================
// 13. LOG SECURITY (rust-log-security.yml)
//     Rules: cleartext-logging-password, cleartext-logging-secret,
//            cleartext-logging-tracing, cleartext-println-sensitive,
//            log-injection-pattern
// =============================================================================

/// Triggers: rust-cleartext-logging-password
pub fn vuln_log_password(username: &str, password: &str) {
    log::info!("Login attempt: user={} password={}", username, password);
}

/// Triggers: rust-cleartext-logging-secret
pub fn vuln_log_secret(token: &str) {
    log::debug!("Auth token received: {}", token);
    log::info!("Using api_key: {}", "some-key");
}

/// Triggers: rust-cleartext-logging-tracing
pub fn vuln_tracing_secret(secret: &str) {
    tracing::info!("Processing with secret: {}", secret);
}

/// Triggers: rust-cleartext-println-sensitive
pub fn vuln_println_secret(password: &str) {
    println!("Debug password: {}", password);
    eprintln!("Lost credential: {}", "oops");
}

/// Triggers: rust-log-injection-pattern
pub async fn vuln_log_injection(query: web::Query<SearchQuery>) -> impl Responder {
    log::info!("User searched for: {}", query.term);
    HttpResponse::Ok().body("logged")
}

// =============================================================================
// 14. WEB SECURITY (rust-web-security.yml)
//     Rules: cors-permissive, cors-wildcard-origin, open-redirect-pattern,
//            error-info-disclosure
// =============================================================================

/// Triggers: rust-cors-permissive
pub fn vuln_cors() -> Cors {
    Cors::permissive()
}

/// Triggers: rust-cors-wildcard-origin
pub fn vuln_cors_wildcard() {
    let cors = actix_cors::Cors::default();
    cors.allowed_origin("*");
}

/// Triggers: rust-open-redirect-pattern
pub async fn vuln_redirect(query: web::Query<RedirectQuery>) -> impl Responder {
    HttpResponse::Found()
        .insert_header(("Location", query.target.as_str()))
        .finish()
}

/// Triggers: rust-error-info-disclosure
pub async fn vuln_error_disclosure() -> impl Responder {
    let err = std::io::Error::new(std::io::ErrorKind::Other, "db connection failed");
    HttpResponse::InternalServerError().body(format!("Error: {:?}", err))
}

// =============================================================================
// 15. DESERIALIZATION (rust-deserialization.yml)
//     Rules: yaml-deserialization-audit, bincode-deserialization-audit
// =============================================================================

/// Triggers: rust-yaml-deserialization-audit
pub fn vuln_yaml(input: &str) {
    let _val: serde_json::Value = serde_yaml::from_str(input).unwrap();
}

/// Triggers: rust-bincode-deserialization-audit
pub fn vuln_bincode(input: &[u8]) {
    let _data: Vec<u8> = bincode::deserialize(input).unwrap();
}

// =============================================================================
// 16. ASYNC SAFETY (rust-async-safety.yml)
//     Rules: blocking-fs-in-async, blocking-mutex-in-async,
//            unbounded-allocation, unbounded-spawn
// =============================================================================

/// Triggers: rust-blocking-fs-in-async
pub async fn vuln_blocking_fs() -> impl Responder {
    let _data = std::fs::read_to_string("config.toml");
    HttpResponse::Ok().body("read")
}

/// Triggers: rust-blocking-mutex-in-async
pub async fn vuln_blocking_mutex(
    state: std::sync::Arc<std::sync::Mutex<String>>,
) -> impl Responder {
    let _guard = state.lock().unwrap();
    HttpResponse::Ok().body("locked")
}

/// Triggers: rust-unbounded-allocation
pub async fn vuln_unbounded_alloc(query: web::Query<AllocQuery>) -> impl Responder {
    let _buf: Vec<u8> = Vec::with_capacity(query.size);
    HttpResponse::Ok().body("allocated")
}

/// Triggers: rust-unbounded-spawn
pub async fn vuln_unbounded_spawn(items: Vec<String>) {
    for item in items {
        tokio::spawn(async move {
            println!("Processing: {}", item);
        });
    }
}

// =============================================================================
// 17. PRODUCTION READINESS (rust-production-readiness.yml)
//     Rules: todo-in-code, unimplemented-in-code, unwrap-in-handler
// =============================================================================

/// Triggers: rust-todo-in-code
pub fn vuln_todo() -> String {
    todo!("implement proper auth")
}

/// Triggers: rust-unimplemented-in-code
pub fn vuln_unimplemented() -> String {
    unimplemented!("payment processing")
}

/// Triggers: rust-unwrap-in-handler
pub async fn vuln_unwrap_handler() -> impl Responder {
    let data = std::fs::read_to_string("data.json").unwrap();
    HttpResponse::Ok().body(data)
}

// =============================================================================
// 18. TOCTOU RACE CONDITION (rust-toctou.yml)
//     Rules: toctou-exists-then-read, toctou-exists-then-open,
//            toctou-exists-then-remove, toctou-if-exists
// =============================================================================

/// Triggers: rust-toctou-exists-then-read
pub fn vuln_toctou_read(path: &std::path::Path) -> String {
    path.exists();
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Triggers: rust-toctou-exists-then-open
pub fn vuln_toctou_open(path: &std::path::Path) {
    path.exists();
    let _ = std::fs::File::open(path);
}

/// Triggers: rust-toctou-exists-then-remove
pub fn vuln_toctou_remove(path: &std::path::Path) {
    path.exists();
    let _ = std::fs::remove_file(path);
}

/// Triggers: rust-toctou-if-exists (regex-based rule)
pub fn vuln_toctou_if_block(path: &std::path::Path) {
    if path.exists() {
        let _data = std::fs::read_to_string(path);
    }
}

// =============================================================================
// 19. INSECURE RANDOM (rust-insecure-random.yml)
//     Rules: fixed-seed-rng, thread-rng-for-crypto
// =============================================================================

/// Triggers: rust-fixed-seed-rng
pub fn vuln_fixed_seed() {
    let _rng = rand::rngs::SmallRng::seed_from_u64(12345);
}

/// Triggers: rust-thread-rng-for-crypto
pub fn vuln_thread_rng_crypto() {
    let _rng = rand::thread_rng();
}
