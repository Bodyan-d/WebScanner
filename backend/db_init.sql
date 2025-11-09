-- backend/db_init.sql
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  report_path TEXT,
  summary JSON,
  details JSON
);
