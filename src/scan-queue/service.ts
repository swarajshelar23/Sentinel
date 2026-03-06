import db from '../lib/db';
import { performScan, calculateThreatScore, getAiPrediction } from '../lib/scanner';
import fs from 'fs';
import path from 'path';

export class ScanQueueService {
  private static isProcessing = false;

  static async addToQueue(userId: number, filename: string, filepath: string): Promise<number> {
    const result = db.prepare(`
      INSERT INTO scan_queue (user_id, filename, filepath, status)
      VALUES (?, ?, ?, 'pending')
    `).run(userId, filename, filepath);
    
    // Start processing in background
    this.processQueue();
    
    return result.lastInsertRowid as number;
  }

  static async getQueueStatus(userId: number): Promise<any[]> {
    return db.prepare(`
      SELECT * FROM scan_queue WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
    `).all(userId);
  }

  static async processQueue() {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      while (true) {
        const job = db.prepare(`
          SELECT * FROM scan_queue WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1
        `).get() as any;

        if (!job) break;

        // Update status to processing
        db.prepare("UPDATE scan_queue SET status = 'processing', progress = 10 WHERE id = ?").run(job.id);

        try {
          // Perform scan
          const features = await performScan(job.filepath, job.filename);
          db.prepare("UPDATE scan_queue SET progress = 40 WHERE id = ?").run(job.id);

          // AI Prediction
          const aiResult = getAiPrediction(job.filepath, features, 0); // vtMaliciousCount=0 for now
          features.ai_probability = aiResult.probability;
          features.ai_prediction = aiResult.prediction;
          db.prepare("UPDATE scan_queue SET progress = 70 WHERE id = ?").run(job.id);

          // Threat Score
          const report = calculateThreatScore(features);
          db.prepare("UPDATE scan_queue SET progress = 90 WHERE id = ?").run(job.id);

          // Store in DB
          const scanId = db.prepare(`
            INSERT INTO scans (user_id, filename, filesize, hash_sha256, entropy, threat_score, classification, vt_results, yara_matches, metadata, ai_probability, ai_prediction, contributions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            job.user_id,
            features.filename,
            features.filesize,
            features.hash_sha256,
            features.entropy,
            report.score,
            report.classification,
            JSON.stringify({}), // vtResults
            JSON.stringify(features.yara_matches),
            JSON.stringify(features.metadata),
            features.ai_probability,
            features.ai_prediction,
            JSON.stringify(report.contributions)
          ).lastInsertRowid;

          // Update queue status
          db.prepare("UPDATE scan_queue SET status = 'completed', progress = 100 WHERE id = ?").run(job.id);
          
          // Cleanup file
          if (fs.existsSync(job.filepath)) {
            fs.unlinkSync(job.filepath);
          }
        } catch (err: any) {
          console.error(`Job ${job.id} failed:`, err);
          db.prepare("UPDATE scan_queue SET status = 'failed', error = ? WHERE id = ?").run(err.message, job.id);
        }
      }
    } finally {
      this.isProcessing = false;
    }
  }
}
