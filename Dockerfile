# Stage 1: Build
FROM rust:1.77-slim as builder

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
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/secure-api /usr/local/bin/secure-api

EXPOSE 8080

CMD ["secure-api"]
