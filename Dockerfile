# Multi-stage build for optimized container size
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /usr/src/app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this will be cached)
RUN cargo build --release && rm -rf src

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false phobos

# Copy the binary from builder stage
COPY --from=builder /usr/src/app/target/release/phobos /usr/local/bin/phobos

# Set permissions
RUN chmod +x /usr/local/bin/phobos

# Switch to non-root user
USER phobos

# Set the entrypoint
ENTRYPOINT ["phobos"]

# Default command
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="Phobos"
LABEL org.opencontainers.image.description="The Blazingly Fast Rust-Based Port Scanner"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="ibrahimsql"
LABEL org.opencontainers.image.url="https://github.com/ibrahmsql/phobos"
LABEL org.opencontainers.image.source="https://github.com/ibrahmsql/phobos"
LABEL org.opencontainers.image.licenses="MIT"