#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
mkdir -p "${CERTS_DIR}"

if [ ! -f "${CERTS_DIR}/secnet.key" ] || [ ! -f "${CERTS_DIR}/secnet.crt" ]; then
    echo "🔐 Generating SecNet self-signed TLS certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${CERTS_DIR}/secnet.key" \
        -out "${CERTS_DIR}/secnet.crt" \
        -subj "/C=VN/ST=Hanoi/L=Hanoi/O=SecNet/OU=Security/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:secnet.local,IP:127.0.0.1"
    echo "✅ TLS Certificate generated at ${CERTS_DIR}/secnet.crt"
else
    echo "ℹ️ TLS Certificate already exists at ${CERTS_DIR}/secnet.crt"
fi
