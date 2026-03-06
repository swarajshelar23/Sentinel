import db from '../lib/db';

export class MonitoringService {
  static async logEvent(userId: number | null, eventType: string, message: string, metadata?: any, ip?: string) {
    db.prepare(`
      INSERT INTO logs (user_id, event_type, message, metadata, ip_address)
      VALUES (?, ?, ?, ?, ?)
    `).run(userId, eventType, message, metadata ? JSON.stringify(metadata) : null, ip || null);
  }

  static async getLogs(limit: number = 100) {
    return db.prepare(`
      SELECT l.*, u.username 
      FROM logs l
      LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC
      LIMIT ?
    `).all(limit);
  }

  static async getSystemHealth() {
    return {
      status: 'healthy',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      db_size: fs.statSync('malware_scanner.db').size,
      active_jobs: db.prepare("SELECT COUNT(*) as count FROM scan_queue WHERE status IN ('pending', 'processing')").get() as any
    };
  }
}

import fs from 'fs';
