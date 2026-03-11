# Secure CI/CD Example for Rust

A reference implementation of a security-focused CI/CD pipeline for Rust (actix-web) projects using GitHub Actions. Designed as a team onboarding resource for integrating security scanning into production Rust codebases.

## What's Included

| Workflow | Purpose |
|----------|---------|
| **CI** (`ci.yml`) | Build, test, Clippy linting with SARIF upload, `cargo-audit` (RustSec) |
| **Security Scanning** (`security.yml`) | TruffleHog secret detection, Trivy filesystem + Docker image scans, SBOM generation, Slack alerts |
| **Semgrep SAST** (`semgrep.yml`) | Static analysis with Semgrep platform rules + custom Rust security rules |
| **Semgrep Publish** (`semgrep-publish.yml`) | Publishes custom rules to Semgrep private registry on changes |

## Custom Semgrep Rules

Hand-crafted Semgrep rules in `.semgrep/rules/` covering Rust-specific vulnerability patterns:

- **Injection**: SQL injection, command injection, XSS, regex injection, SSRF
- **Cryptography**: Weak crypto (MD5/SHA1/DES), insecure random, TLS bypass
- **Web Security**: CORS misconfiguration, timing side-channels, open redirects, JWT validation
- **Memory & Safety**: Unsafe pointer operations, deserialization risks, path traversal, TOCTOU races
- **Production Readiness**: `.unwrap()` in handlers, hardcoded secrets, cleartext logging, async safety

See `.semgrep/rules/` for all rule files and [RUST-ATTACK-SURFACE.md](RUST-ATTACK-SURFACE.md) for the full vulnerability catalog.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Misha-Noetic/secure-cicd-example.git
cd secure-cicd-example

# Build and test locally
cargo build --release
cargo test --verbose

# Run Clippy linter
cargo clippy --all-targets --all-features -- -D warnings

# Run Semgrep custom rules locally (requires Semgrep CLI)
semgrep scan --config .semgrep/rules/ .
```

## Adapting for Your Project

1. **Copy the workflows** from `.github/workflows/` to your repo
2. **Copy `.semgrep/rules/`** for Rust-specific security scanning
3. **Set up secrets**: `SEMGREP_APP_TOKEN`, `SLACK_SECURITY_WEBHOOK_URL` (optional)
4. **Customize**: Adjust Trivy severity gates, TruffleHog exclusions, and Semgrep rule selection

## Documentation

- [Security Pipeline Summary](SECURITY-PIPELINE-SUMMARY.md) - Detailed breakdown of each workflow and tool
- [Rust Attack Surface](RUST-ATTACK-SURFACE.md) - Comprehensive catalog of Rust vulnerability patterns
