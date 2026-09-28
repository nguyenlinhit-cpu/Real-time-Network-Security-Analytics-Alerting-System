#!/usr/bin/env bash
# ==============================================================================
# SecNet Automated Database Backup & Disaster Recovery Script
# Purpose: Dumps PostgreSQL/TimescaleDB tables, schema, hypertables, and audit logs.
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/secnet_backup_${TIMESTAMP}.sql.gz"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-postgres}"
DB_NAME="${DB_NAME:-secnet}"

mkdir -p "${BACKUP_DIR}"

echo "📦 [SecNet Backup] Starting PostgreSQL database dump at ${TIMESTAMP}..."
echo "📍 Target database: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q "secnet-timescaledb"; then
    echo "🐳 Detected running TimescaleDB docker container, running pg_dump inside container..."
    docker exec -t secnet-timescaledb pg_dump -U "${DB_USER}" "${DB_NAME}" | gzip > "${BACKUP_FILE}"
else
    echo "⚙️ Executing local pg_dump..."
    PGPASSWORD="${DB_PASSWORD:-postgres}" pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" "${DB_NAME}" | gzip > "${BACKUP_FILE}"
fi

BACKUP_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "✅ [SecNet Backup] Backup successfully generated: ${BACKUP_FILE} (${BACKUP_SIZE})"

# Retention policy: remove backups older than 7 days
echo "🧹 Cleaning up backups older than 7 days in ${BACKUP_DIR}..."
find "${BACKUP_DIR}" -name "secnet_backup_*.sql.gz" -type f -mtime +7 -delete

echo "🛡️ Backup process completed successfully."
