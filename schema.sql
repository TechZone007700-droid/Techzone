-- TechZone Online Examination — Cloudflare D1 schema
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS app_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  state_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passwords (
  role TEXT PRIMARY KEY CHECK (role IN ('admin','website','student','restart')),
  salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('admin','website','student','restart')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);

CREATE TABLE IF NOT EXISTS resources (
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY(resource_type,resource_id)
);
