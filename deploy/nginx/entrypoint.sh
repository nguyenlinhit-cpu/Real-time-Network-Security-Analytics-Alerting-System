#!/bin/sh
set -e

CERTS_DIR="/etc/nginx/certs"
mkdir -p "$CERTS_DIR"

if [ ! -f "$CERTS_DIR/secnet.crt" ] || [ ! -f "$CERTS_DIR/secnet.key" ]; then
    echo "🔐 Generating auto self-signed SSL certs for Nginx TLS..."
    if ! command -v openssl >/dev/null 2>&1; then
        echo "Installing openssl..."
        apk add --no-cache openssl >/dev/null 2>&1 || true
    fi
    if command -v openssl >/dev/null 2>&1; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERTS_DIR/secnet.key" \
            -out "$CERTS_DIR/secnet.crt" \
            -subj "/CN=localhost" \
            -addext "subjectAltName=DNS:localhost,DNS:secnet.local,IP:127.0.0.1" 2>/dev/null || true
    fi
fi

exec nginx -g "daemon off;"
