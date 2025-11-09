#!/usr/bin/env bash
set -e

DB_DIR=/app/data
DB_FILE=${DB_DIR}/scans.db
SQL_FILE=/app/db_init.sql

mkdir -p "$DB_DIR"

if [ ! -f "$DB_FILE" ]; then
  echo "Initializing SQLite DB at $DB_FILE..."
  sqlite3 "$DB_FILE" < "$SQL_FILE"
else
  echo "DB already exists at $DB_FILE"
fi

# Запускаємо кінцеву команду (uvicorn) з CMD
exec "$@"
