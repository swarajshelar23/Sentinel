import db from '../lib/db.js';

export class AnalyticsService {
  static async getDashboardStats() {
    const stats = db.prepare(`
      SELECT 
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN classification = 'Safe' THEN 1 ELSE 0 END), 0) as safe,
        COALESCE(SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END), 0) as suspicious,
        COALESCE(SUM(CASE WHEN classification = 'Malware' THEN 1 ELSE 0 END), 0) as malware,
        COALESCE(SUM(CASE WHEN classification = 'High Risk' THEN 1 ELSE 0 END), 0) as high_risk
      FROM scans
    `).get() as any;

    const trends = db.prepare(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as count,
        SUM(CASE WHEN classification IN ('Malware', 'High Risk') THEN 1 ELSE 0 END) as malicious
      FROM scans
      GROUP BY DATE(created_at)
      ORDER BY date DESC
      LIMIT 30
    `).all();

    const fileTypes = db.prepare(`
      SELECT 
        json_extract(metadata, '$.extension') as extension,
        COUNT(*) as count
      FROM scans
      GROUP BY extension
      ORDER BY count DESC
      LIMIT 10
    `).all();

    return { stats, trends, fileTypes };
  }

  static async getAiAccuracy() {
    // Mock accuracy metrics
    return {
      precision: 0.94,
      recall: 0.91,
      f1_score: 0.92,
      total_trained: 15420
    };
  }
}
