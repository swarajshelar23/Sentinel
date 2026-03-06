import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import fs from "fs";
import multer from "multer";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import db from "./src/lib/db.js";
import { performScan, calculateThreatScore } from "./src/lib/scanner.js";
import axios from "axios";

const JWT_SECRET = process.env.JWT_SECRET || "super-secret-malware-scanner-key";
const UPLOAD_DIR = "uploads";

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

const upload = multer({ dest: UPLOAD_DIR });

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // --- Auth Middleware ---
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: "Invalid token" });
    }
  };

  // --- Auth Routes ---
  app.post("/api/auth/register", async (req, res) => {
    const { username, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, hashedPassword);
      res.json({ success: true, userId: result.lastInsertRowid });
    } catch (err: any) {
      res.status(400).json({ error: "Username already exists" });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    const user: any = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });

  // --- Scanner Routes ---
  app.post("/api/scan", authenticate, upload.single("file"), async (req: any, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    try {
      const features = await performScan(req.file.path, req.file.originalname);
      
      // VirusTotal Lookup (Optional)
      let vtResults = null;
      if (process.env.VIRUSTOTAL_API_KEY) {
        try {
          const vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${features.hash_sha256}`, {
            headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
          });
          vtResults = vtResponse.data;
        } catch (err) {
          console.log("VT lookup failed (likely not found or rate limit)");
        }
      }

      const report = calculateThreatScore(features, vtResults);

      // Store in DB
      const scanId = db.prepare(`
        INSERT INTO scans (user_id, filename, filesize, hash_sha256, entropy, threat_score, classification, vt_results, yara_matches, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        JSON.stringify(features.metadata)
      ).lastInsertRowid;

      // Cleanup
      fs.unlinkSync(req.file.path);

      res.json({ id: scanId, features, report });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Scan failed" });
    }
  });

  app.get("/api/history", authenticate, (req: any, res) => {
    const scans = db.prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
    res.json(scans);
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
