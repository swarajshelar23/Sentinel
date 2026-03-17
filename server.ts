import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import multer from "multer";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import db from "./src/lib/db.js";
import { performScan, calculateThreatScore, getAiPrediction, isSafeFileType } from "./src/lib/scanner.js";
import axios from "axios";
import { MonitoringService } from "./src/monitoring/service.js";
import { AnalyticsService } from "./src/analytics/service.js";
import { ScanQueueService } from "./src/scan-queue/service.js";
import { ThreatIntelligenceService } from "./src/threat-intelligence/service.js";

const JWT_SECRET = process.env.JWT_SECRET || "super-secret-malware-scanner-key";
const UPLOAD_DIR = "uploads";
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

const THREAT_WEIGHTS = {
  entropy: Number(process.env.WEIGHT_ENTROPY) || 20,
  yara: Number(process.env.WEIGHT_YARA) || 30,
  virusTotal: Number(process.env.WEIGHT_VT) || 25,
  ai: Number(process.env.WEIGHT_AI) || 25,
};

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

const upload = multer({ 
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_FILE_SIZE }
});

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // --- Audit Logging Middleware ---
  app.use((req: any, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    res.on('finish', () => {
      if (req.user && req.path.startsWith('/api')) {
        MonitoringService.logEvent(req.user.id, 'API_REQUEST', `${req.method} ${req.path}`, { status: res.statusCode }, ip as string);
      }
    });
    next();
  });

  // --- Auth Middleware ---
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      console.warn("Auth failed: No token provided");
      return res.status(401).json({ error: "Unauthorized" });
    }
    try {
      const decoded: any = jwt.verify(token, JWT_SECRET);
      const user = db.prepare("SELECT id, username, role FROM users WHERE id = ?").get(decoded.id);
      if (!user) {
        console.warn(`Auth failed: User ${decoded.id} no longer exists`);
        return res.status(401).json({ error: "User no longer exists" });
      }
      req.user = user;
      next();
    } catch (err: any) {
      console.error("Auth failed: Invalid token", err.message);
      res.status(401).json({ error: "Invalid token" });
    }
  };

  const checkAdmin = (req: any, res: any, next: any) => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ error: "Forbidden: Admin access required" });
    }
    next();
  };

  // --- Auth Routes ---
  app.post("/api/auth/register", async (req, res) => {
    const { username, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, hashedPassword);
      MonitoringService.logEvent(Number(result.lastInsertRowid), 'USER_REGISTER', `User ${username} registered`);
      res.json({ success: true, userId: result.lastInsertRowid });
    } catch (err: any) {
      res.status(400).json({ error: "Username already exists" });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    const user: any = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      MonitoringService.logEvent(null, 'LOGIN_FAILED', `Failed login attempt for ${username}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
    MonitoringService.logEvent(user.id, 'LOGIN_SUCCESS', `User ${username} logged in`);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });

  // --- Scanner Routes ---
  app.post("/api/scan", authenticate, upload.single("file"), async (req: any, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    try {
      const buffer = fs.readFileSync(req.file.path);
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');

      // 1. File Intelligence Lookup (Cache)
      const cached = db.prepare("SELECT * FROM file_intelligence WHERE hash_sha256 = ?").get(hash) as any;
      if (cached) {
        db.prepare("UPDATE file_intelligence SET scan_count = scan_count + 1, last_seen = CURRENT_TIMESTAMP WHERE hash_sha256 = ?").run(hash);
        const previousScan = db.prepare("SELECT * FROM scans WHERE hash_sha256 = ? ORDER BY created_at DESC LIMIT 1").get(hash) as any;
        if (previousScan) {
          MonitoringService.logEvent(req.user.id, 'SCAN_CACHE_HIT', `Cache hit for ${hash}`);
          return res.json({ 
            id: previousScan.id, 
            features: { ...JSON.parse(previousScan.metadata), filename: req.file.originalname, hash_sha256: hash }, 
            report: { score: previousScan.threat_score, classification: previousScan.classification, contributions: JSON.parse(previousScan.contributions) },
            cached: true 
          });
        }
      }

      const features = await performScan(req.file.path, req.file.originalname);
      
      // 2. Threat Intelligence Lookup
      const intel = await ThreatIntelligenceService.lookupHash(features.hash_sha256);
      const intelMalicious = intel.some(i => i.malicious);
      
      // 3. VirusTotal Lookup
      let vtResults = null;
      let vtMaliciousCount = 0;
      const vtKey = process.env.VIRUSTOTAL_API_KEY;
      
      if (vtKey && vtKey.length > 10 && !vtKey.includes('YOUR_')) {
        try {
          const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${features.hash_sha256}`, {
            headers: { 'x-apikey': vtKey }
          });
          vtResults = vtResponse.data;
          vtMaliciousCount = vtResults.data?.attributes?.last_analysis_stats?.malicious || 0;
        } catch (err: any) {
          console.error("VT lookup error:", err.message);
        }
      }

      // 4. AI Prediction
      const aiResult = getAiPrediction(req.file.path, features, vtMaliciousCount);
      features.ai_probability = aiResult.probability;
      features.ai_prediction = aiResult.prediction;

      // 5. Calculate Threat Score with Multi-Stage Detection Pipeline
      const safeFileType = isSafeFileType(features.filename);
      const report = calculateThreatScore(features, vtResults, THREAT_WEIGHTS, safeFileType);

      // 5. Malware Family Identification (Mock)
      const malwareFamily = intel.find(i => i.family)?.family || (report.score > 80 ? 'Generic.Malware' : null);

      // Store in DB
      const scanId = db.prepare(`
        INSERT INTO scans (user_id, filename, filesize, hash_sha256, entropy, threat_score, classification, vt_results, yara_matches, metadata, ai_probability, ai_prediction, contributions, malware_family)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id,
        features.filename,
        features.filesize,
        features.hash_sha256,
        features.entropy,
        report.score,
        report.classification,
        JSON.stringify(vtResults),
        JSON.stringify(features.yara_matches),
        JSON.stringify(features.metadata),
        features.ai_probability,
        features.ai_prediction,
        JSON.stringify(report.contributions),
        malwareFamily
      ).lastInsertRowid;

      // Update File Intelligence
      db.prepare(`
        INSERT INTO file_intelligence (hash_sha256, classification, threat_score, malware_family)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(hash_sha256) DO UPDATE SET 
          last_seen = CURRENT_TIMESTAMP,
          scan_count = scan_count + 1
      `).run(features.hash_sha256, report.classification, report.score, malwareFamily);

      MonitoringService.logEvent(req.user.id, 'SCAN_COMPLETED', `Scanned ${features.filename} - Result: ${report.classification}`);

      // Cleanup
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      res.json({ id: scanId, features, report, vtResults, intel });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Scan failed" });
    }
  });

  // --- Batch Scanning ---
  app.post("/api/scan/batch", authenticate, upload.array("files", 10), async (req: any, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: "No files uploaded" });

    try {
      const jobIds = [];
      for (const file of req.files) {
        const jobId = await ScanQueueService.addToQueue(req.user.id, file.originalname, file.path);
        jobIds.push(jobId);
      }
      res.json({ success: true, jobIds, message: "Files queued for processing" });
    } catch (err) {
      console.error("Batch scan error:", err);
      res.status(500).json({ error: "Failed to queue batch scan" });
    }
  });

  app.get("/api/scan/queue", authenticate, async (req: any, res) => {
    try {
      const queue = await ScanQueueService.getQueueStatus(req.user.id);
      res.json(queue);
    } catch (err) {
      console.error("Queue fetch error:", err);
      res.status(500).json({ error: "Failed to fetch scan queue" });
    }
  });

  // --- Analytics & Monitoring ---
  app.get("/api/analytics/dashboard", authenticate, async (req, res) => {
    try {
      const data = await AnalyticsService.getDashboardStats();
      res.json(data);
    } catch (err) {
      console.error("Dashboard analytics error:", err);
      res.status(500).json({ error: "Failed to fetch dashboard stats" });
    }
  });

  app.get("/api/analytics/ai-accuracy", authenticate, async (req, res) => {
    const data = await AnalyticsService.getAiAccuracy();
    res.json(data);
  });

  app.get("/api/admin/logs", authenticate, checkAdmin, async (req, res) => {
    const logs = await MonitoringService.getLogs();
    res.json(logs);
  });

  app.get("/api/admin/health", authenticate, checkAdmin, async (req, res) => {
    const health = await MonitoringService.getSystemHealth();
    res.json(health);
  });

  app.get("/api/admin/scans", authenticate, checkAdmin, async (req, res) => {
    const scans = db.prepare("SELECT s.*, u.username FROM scans s JOIN users u ON s.user_id = u.id ORDER BY s.created_at DESC LIMIT 100").all();
    res.json(scans);
  });

  app.get("/api/history", authenticate, (req: any, res) => {
    const scans = db.prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
    res.json(scans);
  });

  app.get("/api/scans/:id", authenticate, (req: any, res) => {
    try {
      const { id } = req.params;
      const scan: any = db.prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?").get(id, req.user.id);
      
      if (!scan) {
        return res.status(404).json({ error: "Scan not found" });
      }

      // Parse JSON fields
      const scanResult = {
        ...scan,
        yara_matches: scan.yara_matches ? JSON.parse(scan.yara_matches) : [],
        vt_results: scan.vt_results ? JSON.parse(scan.vt_results) : null,
        metadata: scan.metadata ? JSON.parse(scan.metadata) : {},
        contributions: scan.contributions ? JSON.parse(scan.contributions) : {},
      };

      // Return in the format expected by frontend
      res.json({
        id: scan.id,
        features: {
          filename: scan.filename,
          filesize: scan.filesize,
          hash_sha256: scan.hash_sha256,
          entropy: scan.entropy,
          yara_matches: scanResult.yara_matches,
          metadata: scanResult.metadata,
          ai_probability: scan.ai_probability,
          ai_prediction: scan.ai_prediction,
          headers: {},
          indicators: [],
        },
        report: {
          score: scan.threat_score,
          classification: scan.classification,
          details: [],
          contributions: scanResult.contributions || { entropy: 0, yara: 0, virusTotal: 0, ai: 0 },
          explanation: `Classification: ${scan.classification}\nThreat Score: ${scan.threat_score}/100`,
          safeFileReason: scan.classification === 'Safe' ? 'File identified as safe based on analysis' : null,
        }
      });
    } catch (err) {
      console.error('Error fetching scan:', err);
      res.status(500).json({ error: 'Failed to fetch scan' });
    }
  });

  app.get("/api/stats", authenticate, (req: any, res) => {
    const stats = db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN classification = 'Safe' THEN 1 ELSE 0 END) as safe,
        SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END) as suspicious,
        SUM(CASE WHEN classification = 'Malware' THEN 1 ELSE 0 END) as malware,
        SUM(CASE WHEN classification = 'High Risk' THEN 1 ELSE 0 END) as high_risk
      FROM scans
    `).get();
    res.json(stats);
  });

  // --- Vite Middleware ---
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
    app.get("*", (req, res) => res.sendFile(path.resolve("dist/index.html")));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
