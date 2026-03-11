# Security CI/CD Pipeline — Project Summary

## Project

GitHub repo: `Misha-Noetic/secure-cicd-example` — a Rust (actix-web) API with a full security-focused CI/CD pipeline in GitHub Actions.

---

## What's Been Built

### Workflows

#### 1. `.github/workflows/security.yml` — Main Security Workflow
- **TruffleHog** secret scanning (built-in + custom org detectors, split into two steps because `--config` disables built-ins)
- **Trivy FS** scan (GATE/WARN pattern — blocks on fixable CRITICAL/HIGH, warns on all)
- **Trivy Docker Image** scan (with Docker layer caching via `docker/build-push-action` + `type=gha`)
- **SBOM generation** (SPDX format, uploaded as artifact)
- **Slack notifications** on any scan failure (via incoming webhook, `slackapi/slack-github-action@v2.0.0`)
- Runs on push, PR, and daily schedule (`cron: '0 7 * * *'` for full-history secret scans)
- TruffleHog has a base/head identical guard for GitHub UI edits on PRs

#### 2. `.github/workflows/codeql.yml` — REMOVED
- CodeQL was removed after a head-to-head comparison (PR #17) showed that all 5 CodeQL Rust findings were already covered by custom Semgrep rules, while Semgrep caught 64 additional issues across 17 more vulnerability categories
- CodeQL's Rust support is security-only (18 queries, no code quality), and its taint-analysis advantage didn't fire without route-wired handlers
- 3 new Semgrep rules were added to cover the remaining CodeQL query gaps (cleartext storage, cleartext transmission, uncontrolled allocation)

#### 3. `.github/workflows/semgrep.yml` — Semgrep SAST (Primary Scanner)
- Uses `semgrep/semgrep` Docker image with `semgrep ci`
- Connected to Semgrep AppSec Platform with `SEMGREP_APP_TOKEN`
- Semgrep Assistant AI triage enabled
- Catches SSRF + path traversal (2 of 9 intentional vulns) — different 2 than CodeQL
- Rules set to **Block** mode in platform (exit code 1, blocks PR)
- Falls back to standalone `auto + p/rust` rulesets if no platform token

#### 4. `.github/workflows/rust-clippy.yml` — Clippy Linting
Already present prior to this work.

#### 5. OSV-Scanner Workflow — DELETED
Removed as redundant with cargo-audit + Trivy FS.

### Supporting Config Files

| File | Purpose |
|------|---------|
| `.trufflehog.yml` | Custom detector for org-specific DB connection strings (regex with capture group required) |
| `.trufflehog-exclude.txt` | Allowlist excluding `src/config\.rs` from full-history scans (rotated test secrets) |
| `.semgrep/rules/*.yml` | 22 custom Semgrep rules for Rust security (SQL injection, XSS, command injection, weak crypto, cleartext storage/transmission, uncontrolled allocation, etc.) |
| `RUST-ATTACK-SURFACE.md` | Comprehensive Rust attack surface reference catalog (10 categories, 50+ patterns) |
| `.github/dependabot.yml` | Monitors cargo, github-actions, docker ecosystems weekly |
| `.pre-commit-config.yaml` | TruffleHog + pre-commit-hooks for local scanning |
| `.trivyignore` | CVE allowlist with `exp:` expiration dates |

### Branch Protection
Required status checks, no direct push to main, PR-based workflow enforced.

---

## Intentionally Vulnerable Code

`src/vulnerable.rs` contains 23 endpoints for testing scanner coverage:

### Original Vulnerability Set (1-9)

| # | Vulnerability | Implementation |
|---|--------------|----------------|
| 1 | SQL injection | `format!()` → `rusqlite` `db.prepare()` |
| 2 | XSS | User input in HTML response via `HttpResponse::Ok().body()` |
| 3 | Path traversal | User-controlled `std::fs::read_to_string()` |
| 4 | SSRF | User-controlled `reqwest::Client::get()` |
| 5 | Log injection | Unsanitized `log::info!()` |
| 6 | Cleartext logging | Password in `log::info!()` |
| 7 | Weak crypto | MD5 (`Md5::new()`) for password hashing |
| 8 | Regex injection | User-controlled `Regex::new()` |
| 9 | Non-HTTPS URL | `http://` literal for sensitive data |

### Expanded Vulnerability Set (10-23)

| # | Vulnerability | Implementation |
|---|--------------|----------------|
| 10 | Command injection | `Command::new("sh").arg("-c").arg(&user_input)` |
| 11 | Unsafe transmute | `unsafe { std::mem::transmute::<u64, f64>(val) }` |
| 12 | CORS permissive | `Cors::permissive()` |
| 13 | Open redirect | User input in `Location` header |
| 14 | JWT insecure decode | `dangerous_insecure_decode()` |
| 15 | TLS bypass | `danger_accept_invalid_certs(true)` |
| 16 | Hardcoded DB password | Database connection string with embedded credentials |
| 17 | Error info disclosure | `format!("Internal error: {:?}", err)` in 500 response |
| 18 | todo!() in handler | `todo!()` left in production endpoint |
| 19 | YAML deserialization | `serde_yaml::from_str()` on user input |
| 20 | Blocking in async | `std::fs::read_to_string()` inside async handler |
| 21 | Unbounded allocation | `Vec::with_capacity(user_controlled_size)` |
| 22 | Timing side-channel | `stored_secret == user_token` (non-constant-time) |
| 23 | Symlink TOCTOU | `path.exists()` then `fs::read_to_string()` |

---

## Key Findings

### Scanner Coverage — Before Custom Rules (9 Original Vulns)

| Vulnerability | CodeQL | Semgrep (built-in) | Combined |
|---|---|---|---|
| SQL injection | ❌ | ❌ | ❌ |
| XSS | ❌ | ❌ | ❌ |
| Path traversal | ❌ | ✅ | ✅ |
| SSRF | ❌ | ✅ | ✅ |
| Log injection | ❌ | ❌ | ❌ |
| Cleartext logging | ✅ | ❌ | ✅ |
| Weak crypto (MD5) | ❌ | ❌ | ❌ |
| Regex injection | ❌ | ❌ | ❌ |
| Non-HTTPS URL | ✅ | ❌ | ✅ |

**Before custom rules: 4 of 9 caught, zero overlap between tools.**

### Scanner Coverage — Custom Semgrep Rules (All 23 Vulns)

CodeQL was removed after PR #17 proved 100% overlap (all 5 CodeQL findings duplicated by Semgrep).

| # | Vulnerability | Custom Rule | Status |
|---|---|---|---|
| 1 | SQL injection | `rust-sql-injection.yml` | ✅ |
| 2 | XSS | `rust-xss.yml` | ✅ |
| 3 | Path traversal | `rust-path-traversal.yml` | ✅ |
| 4 | SSRF | `rust-ssrf.yml` | ✅ |
| 5 | Log injection | `rust-log-security.yml` | ✅ |
| 6 | Cleartext logging | `rust-log-security.yml` | ✅ |
| 7 | Weak crypto | `rust-weak-crypto.yml` | ✅ |
| 8 | Regex injection | `rust-regex-injection.yml` | ✅ |
| 9 | Non-HTTPS URL | `rust-non-https.yml` | ✅ |
| 10 | Command injection | `rust-command-injection.yml` | ✅ |
| 11 | Unsafe transmute | `rust-memory-safety.yml` | ✅ |
| 12 | CORS permissive | `rust-web-security.yml` | ✅ |
| 13 | Open redirect | `rust-web-security.yml` | ✅ |
| 14 | JWT insecure decode | `rust-jwt-validation.yml` | ✅ |
| 15 | TLS bypass | `rust-tls-bypass.yml` | ✅ |
| 16 | Hardcoded DB password | `rust-hardcoded-secrets.yml` | ✅ |
| 17 | Error info disclosure | `rust-web-security.yml` | ✅ |
| 18 | todo!() in handler | `rust-production-readiness.yml` | ✅ |
| 19 | YAML deserialization | `rust-deserialization.yml` | ✅ |
| 20 | Blocking in async | `rust-async-safety.yml` | ✅ |
| 21 | Unbounded allocation | `rust-async-safety.yml` | ✅ |
| 22 | Timing side-channel | `rust-weak-crypto.yml` | ⚠️ |
| 23 | TOCTOU | `rust-toctou.yml` | ✅ |

**Expected: 22-23 of 23 caught.** (Timing side-channel ⚠️ depends on metavariable-regex support.)

**Design philosophy:** Rust library models are immature across all SAST providers. Custom Semgrep rules using pattern matching (not taint) sidestep these limitations entirely.

### SonarQube Assessment
User's team uses SonarQube — it has **zero Rust support**. Good for code quality (Java/C#/JS) but not a security tool. Complementary to Semgrep, not competing.

### Vulnhalla (CyberArk)
Open-source CLI tool that runs CodeQL + LLM-powered triage. Currently **C/C++ only**. Inspired the DIY AI triage approach below.

---

## Planned But Not Yet Deployed

### 1. DIY Semgrep + LLM Triage
A potential future `ai-triage` job that:
- Downloads SARIF output from Semgrep
- Extracts each finding + surrounding code context (±15 lines)
- Sends to Claude Haiku for classification: TRUE POSITIVE / FALSE POSITIVE / NEEDS REVIEW
- Prints a triage report in workflow logs

Requires `ANTHROPIC_API_KEY` secret. Concept designed but not committed yet.

### 2. Custom Semgrep Rules — DEPLOYED (22 rule files)
22 custom rule files in `.semgrep/rules/` covering:
- SQL injection (format!→prepare/execute), XSS (format!→HTML body), command injection
- Weak crypto (MD5/SHA1), regex injection, TLS bypass, JWT validation bypass
- Log injection, cleartext logging, non-HTTPS URLs, hardcoded secrets
- Unsafe memory ops (transmute, from_raw_parts, Box::from_raw)
- Production readiness (todo!, unimplemented!, unwrap in handlers)
- Web security (CORS permissive, open redirects, error info disclosure)
- TOCTOU file race conditions, async safety (blocking I/O, unbounded alloc)
- Deserialization (YAML, bincode), insecure random, path traversal (full sink set)
- Cleartext DB storage (rusqlite, sqlx, diesel), cleartext transmission (TCP, HTTP)
- Uncontrolled allocation (vec repeat, String::with_capacity, Vec::resize)

See `RUST-ATTACK-SURFACE.md` for the comprehensive reference catalog these rules are based on.

---

## Open PRs / Branches

- **PR #17** (`test/semgrep-rules-validation`) — Validates all 22 custom Semgrep rules with intentionally vulnerable code. Used for CodeQL vs Semgrep comparison.
- **Dependabot PRs (#1-4)** — Still open (bumping actions/checkout, actions/cache, actions/upload-artifact)
- **Old test branches** — `test/secret-in-pr`, `test/leaked-credentials` (can be cleaned up)

---

## Key Lessons Learned

1. **TruffleHog scans git diffs, not file contents** — old secrets persist in history, need allowlisting or force-push
2. **`--config` in TruffleHog disables built-in detectors** — must split into two steps (built-in + custom)
3. **`secrets` context not available in job-level `if` conditions** — use env var at step level
4. **Slack webhook v2.0.0 requires `webhook-type: incoming-webhook`** — omitting it causes a cryptic error
5. **Branch protection is the gate, workflows are traffic lights** — without branch protection, failed workflows don't prevent pushes
6. **Removing secrets via GitHub UI doesn't help TruffleHog** — old commits still in history
7. **Best practice for rotated secrets:** rotate → allowlist, don't rewrite git history
8. **Rust SAST coverage is thin across all providers** — no single tool gives Java/Python-level coverage; layering tools + custom rules is essential
9. **Semgrep custom rules > CodeQL for Rust** — PR #17 proved 100% CodeQL overlap (5/5 findings duplicated), Semgrep caught 69+ total across 22 rule categories vs CodeQL's 5. CodeQL removed from pipeline.
10. **SonarQube ≠ security scanner** — good for code quality, not for finding exploitable vulnerabilities
