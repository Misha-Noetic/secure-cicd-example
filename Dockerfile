# Stage 1: Build
FROM rust:latest as builder

WORKDIR /app

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main.rs to build dependencies (layer caching)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copy actual source code and rebuild
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime (minimal image)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user for security
RUN useradd -r -s /bin/false appuser

COPY --from=builder /app/target/release/secure-api /usr/local/bin/secure-api

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1

CMD ["secure-api"]
