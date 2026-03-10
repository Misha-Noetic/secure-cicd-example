# Rust Application Attack Surface — Comprehensive Reference

A deep-dive catalog of every known attack vector in Rust applications. Organized by category, with dangerous API signatures, real-world examples, and safe alternatives.

---

## A. Injection Attacks

### A1. SQL Injection

User input interpolated into SQL queries via `format!()` or string concatenation.

**Dangerous patterns:**
```rust
// rusqlite — format! into prepare/execute
let sql = format!("SELECT * FROM users WHERE name = '{}'", user_input);
db.prepare(&sql).unwrap();
db.execute(&sql, []).unwrap();
db.execute_batch(&format!("INSERT INTO logs VALUES ('{}')", input)).unwrap();

// diesel — format! into sql_query
diesel::sql_query(format!("SELECT * FROM users WHERE id = {}", id));

// sqlx — format! into query
sqlx::query(&format!("DELETE FROM sessions WHERE token = '{}'", token));
```

**Safe alternative:**
```rust
// Parameterized queries with ? placeholders
db.prepare("SELECT * FROM users WHERE name = ?")?.query_row([&user_input], |row| ...)?;
```

### A2. Cross-Site Scripting (XSS)

User input rendered in HTML responses without escaping.

**Dangerous patterns:**
```rust
// format! into text/html body
let html = format!("<h1>Hello, {}!</h1>", user_input);
HttpResponse::Ok().content_type("text/html").body(html);

// Direct body with content type
HttpResponse::Ok().content_type("text/html").body(format!("..{}..", input));

// Template engines with raw/unescaped blocks
// Tera: {{ value | safe }} or {% raw %}{{ value }}{% endraw %}
// Askama: {{{ value }}} (triple brace = unescaped)
```

**Safe alternative:**
```rust
// Use HTML escaping crate
let escaped = html_escape::encode_text(&user_input);
// Or use template engines with auto-escaping (Tera, Askama default to escaped)
// Or return text/plain instead of text/html
```

### A3. Command Injection

User input passed to OS command execution.

**Dangerous patterns:**
```rust
// Direct command with user input
std::process::Command::new(&user_input).output();
std::process::Command::new("sh").arg("-c").arg(&user_input).output();
std::process::Command::new("bash").args(["-c", &user_input]).spawn();

// Argument injection
Command::new("git").arg("clone").arg(&user_url).output(); // url could be --upload-pack=...
```

**Safe alternative:**
```rust
// Validate input against allowlist
// Never pass user input as the command itself
// Use typed arguments, not shell interpretation
Command::new("ls").arg("--").arg(&validated_path).output();
```

### A4. Server-Side Request Forgery (SSRF)

User-controlled URLs passed to HTTP clients.

**Dangerous patterns:**
```rust
// reqwest
reqwest::Client::new().get(&user_url).send().await;
reqwest::Client::new().post(&user_url).body(data).send().await;

// hyper
hyper::Client::new().request(req_with_user_uri).await;

// std
std::net::TcpStream::connect(&user_addr);
```

**Attack targets:** `http://169.254.169.254/latest/meta-data/` (AWS metadata), `http://localhost:6379` (Redis), internal services.

**Safe alternative:**
```rust
// URL allowlist + block private IP ranges
fn is_safe_url(url: &str) -> bool {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    // Block private IPs: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8
    // Block non-HTTPS
    // Block internal hostnames
}
```

### A5. Log Injection

Unsanitized user input containing newlines injected into log output.

**Dangerous patterns:**
```rust
log::info!("User searched for: {}", user_input);
// user_input = "foo\n[ERROR] Admin password reset for user admin"
// Produces fake log entry that looks legitimate

tracing::info!(query = %user_input, "Search performed");
println!("Request from: {}", user_input);
eprintln!("Error processing: {}", user_input);
```

**Safe alternative:**
```rust
// Sanitize newlines
let sanitized = user_input.replace('\n', "\\n").replace('\r', "\\r");
log::info!("User searched for: {}", sanitized);
// Or use structured logging (slog, tracing with structured fields)
```

### A6. Regex Injection / ReDoS

User input compiled as a regex pattern.

**Dangerous patterns:**
```rust
regex::Regex::new(&user_input);         // User controls the pattern
Regex::new(&user_input);                // After `use regex::Regex`
regex::RegexSet::new(&user_patterns);   // User controls pattern set
```

**Historical CVE:** CVE-2022-24713 — regex crate ≤ 1.5.4 had exponential compilation time on crafted patterns with empty subexpressions and large repetitions. Fixed in 1.5.5+ (Pike NFA, linear time).

**Safe alternative:**
```rust
// Escape user input if using it as a literal match
let escaped = regex::escape(&user_input);
let re = Regex::new(&escaped)?;

// Or validate pattern complexity before compilation
// Or use simple string matching (str::contains) when regex isn't needed
```

### A7. Header Injection

User input placed in HTTP response headers.

**Dangerous patterns:**
```rust
HttpResponse::Ok()
    .insert_header(("X-Custom", &user_input))  // Newlines → header injection
    .finish();

HttpResponse::Ok()
    .insert_header(("Set-Cookie", format!("session={}", user_input)))
    .finish();
```

**Safe alternative:**
```rust
// Validate header values — reject if contains \r or \n
// Use typed header APIs when available
```

### A8. Open Redirect

User input controls redirect destination.

**Dangerous patterns:**
```rust
HttpResponse::Found()
    .insert_header(("Location", &user_url))
    .finish();

HttpResponse::TemporaryRedirect()
    .insert_header(("Location", format!("/redirect?to={}", user_input)))
    .finish();

web::Redirect::to(&user_url);
```

**Safe alternative:**
```rust
// Validate URL against allowlist of internal paths
// Reject absolute URLs or URLs starting with //
fn is_safe_redirect(url: &str) -> bool {
    url.starts_with('/') && !url.starts_with("//")
}
```

---

## B. Cryptography Failures

### B1. Weak Hashing Algorithms

MD5, SHA1, MD2, MD4 are broken for security purposes.

**Dangerous patterns:**
```rust
// md-5 crate
use md5::Md5;
use md5::digest::Digest;
let mut hasher = Md5::new();
hasher.update(password.as_bytes());
let result = hasher.finalize();

// Shorthand
let digest = md5::compute(password.as_bytes());

// sha1 crate
use sha1::Sha1;
let mut hasher = Sha1::new();
hasher.update(data);

// Also: Md2::new(), Md4::new()
```

**Safe alternative:**
```rust
// For password hashing
use argon2::{Argon2, PasswordHasher};
let salt = SaltString::generate(&mut OsRng);
let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;

// For general hashing (integrity, not passwords)
use sha2::Sha256;
let mut hasher = Sha256::new();
```

### B2. AES-GCM Nonce Reuse

Reusing a nonce with AES-GCM is catastrophic — attacker recovers the authentication key and can forge ciphertexts.

**Dangerous patterns:**
```rust
let nonce = GenericArray::from_slice(b"fixed_nonce!"); // FIXED nonce
let ct1 = cipher.encrypt(nonce, plaintext1.as_ref())?;
let ct2 = cipher.encrypt(nonce, plaintext2.as_ref())?; // REUSED — catastrophic

// Also: counter that wraps around, or counter reset after restart
```

**Safe alternative:**
```rust
// Random nonce per encryption
let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

// Or use AES-GCM-SIV for nonce-misuse resistance
use aes_gcm_siv::Aes256GcmSiv;
```

### B3. Timing Side-Channels

Non-constant-time comparison of secrets leaks information through timing.

**Dangerous patterns:**
```rust
if stored_token == user_provided_token { /* grant access */ }
// Rust's == on strings short-circuits — time reveals matching prefix length

if api_key == expected_key { /* authorize */ }
```

**Safe alternative:**
```rust
use subtle::ConstantTimeEq;
if stored_token.as_bytes().ct_eq(user_token.as_bytes()).into() {
    // grant access
}
```

### B4. Insecure PRNG for Cryptographic Purposes

`thread_rng()` uses a fast PRNG (ChaCha) seeded from OS entropy. While cryptographically strong for most uses, `OsRng` is preferred for key generation.

**Dangerous patterns:**
```rust
// Definitely insecure: using SmallRng or StdRng with fixed seed
use rand::SeedableRng;
let mut rng = rand::rngs::SmallRng::seed_from_u64(12345); // Predictable!
let token: u64 = rng.gen();

// Marginal: thread_rng for long-lived tokens
let token: [u8; 32] = rand::random(); // Uses thread_rng internally
```

**Safe alternative:**
```rust
use rand::rngs::OsRng;
let mut key = [0u8; 32];
OsRng.fill_bytes(&mut key);
```

### B5. TLS Certificate Verification Bypass

Disabling certificate verification allows MITM attacks.

**Dangerous patterns:**
```rust
reqwest::Client::builder()
    .danger_accept_invalid_certs(true)    // Accepts self-signed, expired, wrong CN
    .build()?;

reqwest::Client::builder()
    .danger_accept_invalid_hostnames(true) // Accepts cert for wrong domain
    .build()?;

// Native TLS
native_tls::TlsConnector::builder()
    .danger_accept_invalid_certs(true)
    .build()?;
```

**Safe alternative:**
```rust
// Use default reqwest client (TLS verification enabled by default)
reqwest::Client::new();
// For custom CA: add_root_certificate() instead of disabling verification
```

### B6. Non-HTTPS URLs

Sending sensitive data over HTTP instead of HTTPS.

**Dangerous patterns:**
```rust
client.post("http://api.example.com/auth").body(credentials);
const API_URL: &str = "http://internal.service/data";
let response = reqwest::get("http://payment.gateway/charge").await?;
```

### B7. JWT Validation Bypass

**Dangerous patterns:**
```rust
// Skip signature verification entirely
jsonwebtoken::dangerous_insecure_decode::<Claims>(&token);

// Disable expiration check
let mut validation = Validation::default();
validation.validate_exp = false;  // Accepts expired tokens
jsonwebtoken::decode::<Claims>(&token, &key, &validation);

// Algorithm confusion: using HS256 with a public RSA key
// Attacker signs token with public key using HS256
```

**Safe alternative:**
```rust
let mut validation = Validation::new(Algorithm::RS256);
// validation.validate_exp defaults to true
jsonwebtoken::decode::<Claims>(&token, &DecodingKey::from_rsa_pem(public_key)?, &validation)?;
```

### B8. Hardcoded Secrets

Credentials committed to source code.

**Dangerous patterns:** Embedding connection strings, API keys, JWT signing
keys, or PEM-encoded private keys directly in source code.

**Safe alternative:**
```rust
let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
// Or use a secrets manager (AWS Secrets Manager, HashiCorp Vault)
```

---

## C. Memory Safety (Unsafe Code)

All patterns in this section require `unsafe` blocks. Rust's borrow checker prevents them in safe code.

### C1. Use-After-Free

```rust
unsafe {
    let ptr = Box::into_raw(Box::new(42));
    drop(Box::from_raw(ptr));  // Frees the memory
    println!("{}", *ptr);       // USE-AFTER-FREE
}

// Also: dangling pointer from as_ptr() after drop
let ptr = {
    let v = vec![1, 2, 3];
    v.as_ptr()  // ptr dangles after v is dropped
};
unsafe { *ptr }  // USE-AFTER-FREE
```

### C2. Double Free

```rust
unsafe {
    let ptr = Box::into_raw(Box::new(42));
    let _a = Box::from_raw(ptr);  // First owner
    let _b = Box::from_raw(ptr);  // Second owner — DOUBLE FREE when both drop
}
```

### C3. Buffer Overflow via from_raw_parts

```rust
unsafe {
    let data = vec![1u8, 2, 3];
    // Claiming length 100 when only 3 bytes exist
    let slice = std::slice::from_raw_parts(data.as_ptr(), 100);  // OUT-OF-BOUNDS READ
    let slice_mut = std::slice::from_raw_parts_mut(ptr, 100);    // OUT-OF-BOUNDS WRITE
}

// Also: Vec::set_len beyond capacity
unsafe {
    let mut v: Vec<u8> = Vec::with_capacity(3);
    v.set_len(100);  // Reading uninitialized memory
}
```

### C4. Type Confusion via transmute

```rust
unsafe {
    // Size mismatch
    let val: u32 = 42;
    let big: u64 = std::mem::transmute(val);  // READS ADJACENT MEMORY

    // Aliasing violation: &T to &mut T
    let immutable = &42;
    let mutable: &mut i32 = std::mem::transmute(immutable);  // UNDEFINED BEHAVIOR

    // Invalid enum discriminant
    let invalid: bool = std::mem::transmute(2u8);  // bool can only be 0 or 1
}
```

### C5. Uninitialized Memory

```rust
unsafe {
    // Deprecated, always UB for types with invalid bit patterns
    let val: String = std::mem::uninitialized();  // UB

    // Zeroed memory — safe for primitives, UB for types with invariants
    let val: &str = std::mem::zeroed();  // UB (null reference)

    // MaybeUninit misuse
    let val = std::mem::MaybeUninit::<String>::uninit();
    val.assume_init()  // UB — String not initialized
}
```

### C6. Data Races via Incorrect Send/Sync

```rust
// UNSOUND: T is not bounded by Send
struct Wrapper<T>(T);
unsafe impl<T> Send for Wrapper<T> {}  // Allows sending non-Send T across threads

// UNSOUND: T is not bounded by Sync
struct SharedWrapper<T>(T);
unsafe impl<T> Sync for SharedWrapper<T> {}  // Allows sharing non-Sync T across threads

// RUDRA found 264 bugs of this pattern in 145 crates
```

**Safe pattern:**
```rust
unsafe impl<T: Send> Send for Wrapper<T> {}
unsafe impl<T: Send + Sync> Sync for SharedWrapper<T> {}
```

### C7. Panic Across FFI Boundary

```rust
#[no_mangle]
pub extern "C" fn rust_callback() {
    panic!("oops");  // Unwinds into C code → UNDEFINED BEHAVIOR
}
```

**Safe alternative:**
```rust
#[no_mangle]
pub extern "C" fn rust_callback() -> i32 {
    match std::panic::catch_unwind(|| {
        // Rust code that might panic
    }) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
```

### C8. Null Terminator Missing in FFI

```rust
let rust_str = String::from("hello");
let c_ptr = rust_str.as_ptr() as *const c_char;
// C code reads past "hello" — no null terminator!

unsafe { some_c_function(c_ptr); }
```

**Safe alternative:**
```rust
let c_string = std::ffi::CString::new("hello").unwrap();
unsafe { some_c_function(c_string.as_ptr()); }
```

### C9. Aliasing Violations

```rust
unsafe {
    let mut data = 42;
    let ptr1 = &mut data as *mut i32;
    let ptr2 = &mut *ptr1;  // Creates second &mut — UNDEFINED BEHAVIOR
    *ptr1 = 10;
    *ptr2 = 20;  // Compiler assumes ptr2 is unique
}
```

### C10. Lifetime Violations in FFI

```rust
#[no_mangle]
pub extern "C" fn get_data() -> *const u8 {
    let data = vec![1, 2, 3, 4];
    data.as_ptr()  // DANGLING — data dropped at end of function
}
```

**Safe alternative:**
```rust
#[no_mangle]
pub extern "C" fn get_data() -> *mut u8 {
    let data = vec![1, 2, 3, 4];
    let ptr = data.as_mut_ptr();
    std::mem::forget(data);  // Leak — C code must call rust_free()
    ptr
}
```

---

## D. Denial of Service

### D1. Stack Overflow via Recursion

Rust has no tail-call optimization guarantee.

```rust
fn process(depth: usize) {
    if depth > 0 {
        process(depth - 1);  // Stack grows with each call
    }
}
// Attacker sets depth to 1_000_000 → stack overflow
```

### D2. OOM via Unbounded Allocation

```rust
let user_size: usize = query.size.parse()?;
let buffer: Vec<u8> = Vec::with_capacity(user_size);  // user_size = 10GB → OOM
let map: HashMap<String, String> = HashMap::with_capacity(user_size);

// Also: collecting unbounded iterators
let items: Vec<Item> = stream.collect().await;  // No size limit
```

**Safe alternative:**
```rust
const MAX_SIZE: usize = 10 * 1024 * 1024; // 10MB
let size = user_size.min(MAX_SIZE);
let buffer: Vec<u8> = Vec::with_capacity(size);
```

### D3. Hash Flooding

`std::collections::HashMap` uses SipHash (cryptographically sound, DoS-resistant). But custom `Hasher` implementations may not be.

```rust
// DANGEROUS: Using a non-crypto hasher for untrusted keys
use std::hash::BuildHasherDefault;
use ahash::AHasher; // Fast but may be vulnerable to targeted attacks
let map: HashMap<String, String, BuildHasherDefault<AHasher>> = HashMap::default();
```

### D4. Async Task Explosion

```rust
for item in user_provided_items {
    tokio::spawn(async move {
        process(item).await;  // Unbounded spawns — OOM if millions of items
    });
}
```

**Safe alternative:**
```rust
use tokio::sync::Semaphore;
let sem = Arc::new(Semaphore::new(100)); // Max 100 concurrent tasks
for item in items {
    let permit = sem.clone().acquire_owned().await?;
    tokio::spawn(async move {
        process(item).await;
        drop(permit);
    });
}
```

### D5. Blocking in Async Context

Blocking operations on Tokio runtime starve ALL other tasks on that thread.

```rust
// DANGEROUS: blocking file I/O in async function
async fn handler() -> impl Responder {
    let data = std::fs::read_to_string("large_file.bin");  // BLOCKS entire thread
    let guard = std::sync::Mutex::lock(&mutex);             // BLOCKS entire thread
}
```

**Safe alternative:**
```rust
async fn handler() -> impl Responder {
    let data = tokio::fs::read_to_string("large_file.bin").await;  // Non-blocking
    let guard = tokio::sync::Mutex::lock(&mutex).await;            // Async-aware
    // Or: tokio::task::spawn_blocking(|| std::fs::read(...)).await
}
```

### D6. Deadlock via Mutex Held Across Await

```rust
async fn handler(state: Arc<Mutex<AppState>>) {
    let guard = state.lock().unwrap();  // std::sync::Mutex
    some_async_op().await;               // DEADLOCK — holds lock across await
    drop(guard);
}
```

### D7. HTTP/2 Stream Reset Flooding

Real-world CVEs in the h2 crate:
- **RUSTSEC-2024-0003** — Unbounded reset frame queuing → OOM + high CPU
- **RUSTSEC-2023-0034** — Pending accept queue grows unbounded from HEADERS/RST_STREAM flood
- **CVE-2025-8671** — Resource exhaustion via stream reset handling

**Mitigation:** Keep h2 crate updated; configure connection-level reset limits.

### D8. Deserialization Bombs

```rust
// Deeply nested JSON → stack overflow
let data: Value = serde_json::from_str(&user_input)?;  // {"a":{"a":{"a":...}}} 10k deep

// YAML billion laughs
let config: Config = serde_yaml::from_str(&user_input)?;
// a: &anchor [*anchor, *anchor, *anchor, ...] — exponential expansion

// Bincode/CBOR size claims
let data: Vec<u8> = bincode::deserialize(&user_input)?;  // Claims 10GB allocation
```

**Safe alternative:**
```rust
// Limit input size before deserialization
if user_input.len() > MAX_INPUT_SIZE { return Err("too large"); }
// Use serde limits where available
// Avoid deserializing YAML from untrusted sources
```

### D9. Regex Compilation DoS

CVE-2022-24713: regex ≤ 1.5.4 had exponential compilation time on crafted patterns.

```rust
// User provides: "(a+)+$" or "a{0,10000}{0,10000}{0,10000}"
regex::Regex::new(&user_pattern)?;  // Compilation takes minutes/hours
```

**Fixed in regex 1.5.5+** (Pike NFA, linear-time compilation). But user-controlled patterns can still have high constant factors.

---

## E. Supply Chain Attacks

### E1. Typosquatting on crates.io

Real incidents:
- **`rustdecimal`** (2022) — Typosquats `rust_decimal`. Injected into GitLab CI pipelines, attempted persistence.
- **`faster_log` + `async_println`** (May 2025) — 8,424 combined downloads. Embedded code scanned source files for Solana/Ethereum private keys, exfiltrated via HTTP POST.

**Attack pattern:** Create crate with similar name (1 char swap, underscore/hyphen confusion, plural form). Copy legitimate source + add malicious payload.

### E2. Malicious build.rs

Build scripts execute arbitrary code during `cargo build`. A malicious `build.rs`
can read CI environment variables (tokens, credentials) and exfiltrate them via
HTTP POST to an attacker-controlled server.

**Mitigation:** Audit `build.rs` in dependencies. Run builds in sandboxed environments. Use `cargo-crev` for community code reviews.

### E3. Proc Macro Injection

Proc macros execute during compilation and can generate arbitrary code:
```rust
// Malicious derive macro
#[derive(MaliciousDerive)]  // Generates backdoor code at compile time
struct MyStruct { ... }
```

**Mitigation:** Audit macro crate sources. Use `cargo expand` to inspect macro output.

### E4. Dependency Confusion

High-version crate on crates.io shadows internal registry package. Cargo resolves to the higher version from the public registry.

### E5. Compromised Maintainer Accounts

Attacker gains access to maintainer's crates.io account, publishes malicious version. Pin dependencies to specific versions, use Cargo.lock, monitor advisories.

---

## F. File System & OS-Level

### F1. Path Traversal

User input into filesystem operations without validation.

**Dangerous sinks (complete list):**
```rust
std::fs::read_to_string(&user_path)
std::fs::read(&user_path)
std::fs::write(&user_path, data)
std::fs::remove_file(&user_path)
std::fs::remove_dir_all(&user_path)
std::fs::copy(&user_src, &user_dst)
std::fs::rename(&user_src, &user_dst)
std::fs::create_dir_all(&user_path)
std::fs::set_permissions(&user_path, perms)
std::fs::File::open(&user_path)
std::fs::File::create(&user_path)
std::fs::metadata(&user_path)
std::fs::symlink_metadata(&user_path)
tokio::fs::read_to_string(&user_path)
tokio::fs::read(&user_path)
tokio::fs::write(&user_path, data)
tokio::fs::remove_file(&user_path)
```

**Safe alternative:**
```rust
use std::path::{Path, PathBuf};
let base = Path::new("/allowed/directory");
let requested = base.join(&user_path);
let canonical = requested.canonicalize()?;
if !canonical.starts_with(base) {
    return Err("path traversal attempt");
}
```

### F2. Symlink Following / TOCTOU

```rust
// Race condition: attacker replaces file with symlink between check and use
if path.exists() {                          // Check
    let data = std::fs::read(&path)?;       // Use — may now be a symlink!
}

// Historical: GHSA-r9cc-f5pr-p3j2
// std::fs::remove_dir_all followed symlinks in Rust < 1.58.1
```

### F3. Temp File Races

```rust
// DANGEROUS: Predictable temp path
let tmp = format!("{}/myapp-{}", std::env::temp_dir().display(), user_id);
std::fs::write(&tmp, data)?;  // Attacker pre-creates this path as symlink
```

**Safe alternative:**
```rust
use tempfile::NamedTempFile;
let file = NamedTempFile::new()?;  // Secure, random name, proper permissions
```

### F4. File Permission Bits

```rust
// Created with default umask (often 0o644 — world-readable)
std::fs::write("secret.key", key_material)?;
```

**Safe alternative (Unix):**
```rust
use std::os::unix::fs::OpenOptionsExt;
std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .mode(0o600)  // Owner read/write only
    .open("secret.key")?;
```

### F5. Windows Path Canonicalization

`std::fs::canonicalize()` on Windows returns UNC paths (`\\?\C:\...`) that many tools don't support, potentially bypassing path validation.

### F6. NTFS Alternate Data Streams

On Windows, `file.txt:hidden` creates a hidden data stream. Scanners may miss malicious content stored in ADS.

---

## G. Web Framework Patterns

### G1. CORS Misconfiguration

```rust
// Allows any origin — effectively disables same-origin policy
App::new().wrap(Cors::permissive());
App::new().wrap(Cors::default().allowed_origin("*"));
```

### G2. Missing Security Headers

Absence of:
- `Content-Security-Policy` — prevents XSS
- `Strict-Transport-Security` — enforces HTTPS
- `X-Frame-Options` — prevents clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing

### G3. Cookie Security Flags

```rust
// Missing Secure, HttpOnly, SameSite
Cookie::new("session", token);

// Should be:
Cookie::build("session", token)
    .secure(true)
    .http_only(true)
    .same_site(SameSite::Strict)
    .finish();
```

### G4. Error Information Disclosure

```rust
// Exposes internal error details to users
HttpResponse::InternalServerError()
    .body(format!("Error: {:?}", err));  // Debug format leaks stack traces, file paths

HttpResponse::BadGateway()
    .body(format!("Database error: {}", sql_err));  // Leaks DB schema info
```

**Safe alternative:**
```rust
log::error!("Internal error: {:?}", err);  // Log internally
HttpResponse::InternalServerError()
    .body("An internal error occurred");   // Generic message to user
```

### G5. Request Smuggling

Mismatched `Content-Length` vs `Transfer-Encoding` interpretation between proxy and backend.

Historical: RUSTSEC-2021-0081 in actix-http. Patched in recent versions.

### G6. Multipart Upload Attacks

```rust
// No file size limit, no filename validation, no type checking
while let Ok(Some(field)) = payload.try_next().await {
    let filename = field.name().to_string();
    std::fs::File::create(&filename)?;  // Path traversal in filename!
}
```

### G7. WebSocket Origin Bypass

```rust
// No Origin header check — any website can connect
ws::start(MyWebSocket, &req, stream);
```

### G8. Missing Rate Limiting / Body Size Limits

No per-IP throttling allows brute force. No body size limit allows OOM via large requests.

### G9. Host Header Injection

```rust
// Trusting Host header for URL generation
let host = req.headers().get("Host").unwrap();
let reset_url = format!("https://{}/reset-password?token={}", host, token);
// Attacker sets Host: evil.com → phishing link
```

---

## H. Cleartext / Information Disclosure

### H1. Cleartext Logging of Secrets

```rust
log::info!("Login: user={} password={}", username, password);
log::debug!("API key: {}", api_key);
tracing::info!(token = %auth_token, "Request received");
println!("Secret: {}", secret);
```

**Sensitive keywords to watch for:** password, secret, token, key, credential, api_key, authorization, bearer, private_key, ssn, credit_card

### H2. Debug Endpoints in Production

```rust
// Guard that might be accidentally removed or misconfigured
#[cfg(debug_assertions)]
#[get("/debug/state")]
async fn debug_state(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok().json(&*state.lock().unwrap())
}
```

### H3. Environment Variable Leakage

```rust
// Dumping all env vars — may include secrets
for (key, value) in std::env::vars() {
    log::info!("{}: {}", key, value);
}
```

---

## I. Concurrency Issues

### I1. Data Races via Incorrect Send/Sync

See Section C6. RUDRA found 264 bugs across 145 crates from this pattern.

### I2. Deadlock via Lock Ordering

```rust
// Thread 1: lock A then B
let _a = lock_a.lock();
let _b = lock_b.lock();  // Waits for B

// Thread 2: lock B then A
let _b = lock_b.lock();
let _a = lock_a.lock();  // Waits for A → DEADLOCK
```

### I3. Tokio Runtime Starvation

CPU-bound work without yielding starves all other tasks on the same runtime thread.

```rust
async fn handler() {
    loop {
        heavy_computation();  // Never yields — starvation!
    }
}
```

**Safe alternative:**
```rust
tokio::task::spawn_blocking(|| heavy_computation()).await;
// Or periodically: tokio::task::yield_now().await;
```

### I4. Mutex Held Across Await

```rust
let guard = std_mutex.lock().unwrap();
async_operation().await;  // Other tasks on this thread can't acquire the mutex
drop(guard);
```

**Safe alternative:** Use `tokio::sync::Mutex` or drop the guard before `.await`.

---

## J. Rust Language-Level Pitfalls

### J1. Panic in Production

```rust
// All of these crash the server on unexpected input:
value.unwrap();                    // None or Err → panic
value.expect("should exist");     // None or Err → panic
collection[user_index];           // Out of bounds → panic
todo!();                           // Always panics
unimplemented!();                  // Always panics
unreachable!();                    // Panics if reached
```

**Safe alternative:** Use `?` operator, `match`, `if let`, `.get()` for indexing.

### J2. Integer Overflow

In release mode, Rust wraps on overflow instead of panicking:
```rust
let a: u8 = 255;
let b = a + 1;  // Debug: panic! Release: wraps to 0

let big: u64 = 1_000_000_000_000;
let small = big as u32;  // Truncation — silently loses data
let signed: i32 = user_input.parse()?;
let unsigned = signed as usize;  // Negative → huge positive number
```

### J3. TOCTOU in File Checks

```rust
if path.exists() {           // Check
    // Window: attacker changes file here
    fs::read(&path)?;        // Use — may be different file now
}
```

**Safe alternative:** Open the file directly and handle errors.

### J4. Reference Cycles / Memory Leaks

```rust
use std::rc::Rc;
use std::cell::RefCell;

let a = Rc::new(RefCell::new(None));
let b = Rc::new(RefCell::new(None));
*a.borrow_mut() = Some(Rc::clone(&b));
*b.borrow_mut() = Some(Rc::clone(&a));
// Neither a nor b will ever be dropped — memory leak
```

**Safe alternative:** Use `Weak<T>` for back-references.

---

## Real-World CVE Reference

| Crate | CVE / Advisory | Issue | Severity |
|-------|---------------|-------|----------|
| h2 | RUSTSEC-2024-0003 | Unbounded reset frame queuing → OOM | High |
| h2 | RUSTSEC-2023-0034 | HTTP/2 stream reset flooding | High |
| h2 | CVE-2025-8671 | Stream reset DoS | High |
| tokio-tar | CVE-2025-62518 | TAR entry smuggling (TARmageddon) → file overwrite / RCE | Critical |
| regex | CVE-2022-24713 | Exponential compilation time (ReDoS) | High |
| actix-http | RUSTSEC-2021-0081 | HTTP/1 request smuggling | High |
| rustls | RUSTSEC-2024-0336 | Infinite loop in complete_io → DoS | High |
| yaml-rust | < 0.4.1 | Uncontrolled recursion → stack overflow | High |
| time | RUSTSEC-2026-0009 | Stack exhaustion | High |
| std | GHSA-r9cc-f5pr-p3j2 | Symlink race in remove_dir_all (Rust < 1.58.1) | High |
| RustCrypto RSA | Advisory | Variable-time modular exponentiation → timing attack | High |
| faster_log | Malware (2025) | Solana/Ethereum private key theft | Critical |
| rustdecimal | Malware (2022) | CI pipeline injection (CrateDepression) | Critical |

---

## Semgrep Detection Feasibility Summary

| Attack Vector | Semgrep Detectable? | Method | Notes |
|--------------|-------------------|--------|-------|
| SQL injection via format!() | Yes | Pattern match | Sidestep taint; match format!→prepare/execute |
| XSS via format!() into HTML | Yes | Pattern match | Match format!→content_type("text/html").body() |
| Command injection | Yes | Taint + pattern | Web input → Command::new/arg |
| SSRF | Already caught | Built-in rules | — |
| Log injection | Partial | Taint | May fail through macro args |
| Cleartext logging | Yes | Pattern-regex | Keyword match in log macros |
| Weak crypto (MD5/SHA1) | Yes | Pattern match | Very low false positive |
| Regex injection | Yes | Taint + pattern | Non-literal in Regex::new() |
| Non-HTTPS URL | Yes | Pattern-regex | Match "http://" literals |
| TLS bypass | Yes | Pattern match | danger_accept_invalid_certs |
| Hardcoded secrets | Yes | Pattern-regex | DB URIs, private keys |
| JWT bypass | Yes | Pattern match | dangerous_insecure_decode |
| Unsafe memory ops | Yes | Pattern match | transmute, from_raw_parts, etc. |
| todo!/unimplemented! | Yes | Pattern match | Trivial |
| CORS permissive | Yes | Pattern match | Cors::permissive() |
| Open redirect | Yes | Taint | Web input → Location header |
| Error info disclosure | Yes | Pattern match | InternalServerError + format! |
| TOCTOU | Yes | Pattern match | exists() then file op |
| Blocking in async | Partial | Pattern match | std::fs in async fn (needs pattern-inside) |
| Supply chain attacks | No | Out of scope | cargo-audit, cargo-deny handle this |
| Data races (Send/Sync) | No | Requires type analysis | Beyond Semgrep capabilities |
| Integer overflow | No | Requires type analysis | — |
| Deadlock | No | Requires control flow | — |
