import Database from 'better-sqlite3';
import path from 'path';

const db = new Database('malware_scanner.db');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT NOT NULL,
    filesize INTEGER NOT NULL,
    hash_sha256 TEXT NOT NULL,
    entropy REAL,
    threat_score INTEGER,
    classification TEXT,
    vt_results TEXT,
    yara_matches TEXT,
    metadata TEXT,
    ai_probability REAL,
    ai_prediction TEXT,
    status TEXT DEFAULT 'completed',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// Migration: Ensure AI columns exist if table was created before AI update
const tableInfo = db.prepare("PRAGMA table_info(scans)").all() as any[];
const hasAiProb = tableInfo.some(col => col.name === 'ai_probability');
const hasAiPred = tableInfo.some(col => col.name === 'ai_prediction');
const hasContributions = tableInfo.some(col => col.name === 'contributions');

if (!hasAiProb) {
  db.exec("ALTER TABLE scans ADD COLUMN ai_probability REAL");
}
if (!hasAiPred) {
  db.exec("ALTER TABLE scans ADD COLUMN ai_prediction TEXT");
}
if (!hasContributions) {
  db.exec("ALTER TABLE scans ADD COLUMN contributions TEXT");
}

export default db;
