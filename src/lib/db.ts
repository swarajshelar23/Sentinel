import Database from 'better-sqlite3';
import path from 'path';

const db = new Database('malware_scanner.db');
db.pragma('foreign_keys = ON');

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
    contributions TEXT,
    malware_family TEXT,
    confidence_score REAL,
    status TEXT DEFAULT 'completed',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS file_intelligence (
    hash_sha256 TEXT PRIMARY KEY,
    classification TEXT,
    threat_score INTEGER,
    malware_family TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_count INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS scan_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Migration: Ensure columns exist
const tableInfo = db.prepare("PRAGMA table_info(scans)").all() as any[];
const hasAiProb = tableInfo.some(col => col.name === 'ai_probability');
const hasAiPred = tableInfo.some(col => col.name === 'ai_prediction');
const hasContributions = tableInfo.some(col => col.name === 'contributions');
const hasMalwareFamily = tableInfo.some(col => col.name === 'malware_family');
const hasConfidence = tableInfo.some(col => col.name === 'confidence_score');

if (!hasAiProb) db.exec("ALTER TABLE scans ADD COLUMN ai_probability REAL");
if (!hasAiPred) db.exec("ALTER TABLE scans ADD COLUMN ai_prediction TEXT");
if (!hasContributions) db.exec("ALTER TABLE scans ADD COLUMN contributions TEXT");
if (!hasMalwareFamily) db.exec("ALTER TABLE scans ADD COLUMN malware_family TEXT");
if (!hasConfidence) db.exec("ALTER TABLE scans ADD COLUMN confidence_score REAL");

export default db;
