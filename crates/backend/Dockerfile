FROM rust:bookworm AS builder

WORKDIR /usr/src/app

# Install dependencies required for pcap, openssl, and pkg-config
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY .sqlx ./.sqlx
# sqlx::migrate! embeds the SQL migrations at compile time
COPY migrations ./migrations

ENV SQLX_OFFLINE=true

# Build backend release binary
RUN cargo build --release -p backend

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    libssl3 \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Run as non-root user (OWASP compliance)
RUN useradd -m -u 1000 secnet && chown -R secnet:secnet /app
USER secnet

COPY --from=builder /usr/src/app/target/release/backend /app/backend

EXPOSE 8080

CMD ["/app/backend"]
