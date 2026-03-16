# Sentinel Malware Scanner

Sentinel is a full-stack malware analysis dashboard with file scanning, threat scoring, analytics, and role-based admin monitoring.

## Project Overview

Sentinel combines:

- A React + Vite frontend for dashboard, scan history, analytics, and admin views
- An Express + TypeScript backend for authentication, scanning, queueing, and API routes
- A local SQLite database for users, scans, logs, and file intelligence cache
- A Python-powered AI engine for malware probability prediction

## Features

- Single-file scan and batch scan queue
- Threat scoring engine based on entropy, signature matches, VirusTotal reputation, and AI output
- SHA-256 hash intelligence cache with repeated-scan tracking
- Role-based access (user/admin)
- Activity logs and system health endpoints for admin users
- Optional AI explanation and chat assistance in scan result view

## Tech Stack

- Frontend: React, Vite, TypeScript, Tailwind CSS, Recharts
- Backend: Express, TypeScript, JWT auth, Multer uploads
- Database: better-sqlite3 (local file: malware_scanner.db)
- AI/ML: Python scripts in ai-engine/

## Prerequisites

- Node.js 18+ (Node.js 20 recommended)
- npm
- Python 3 with pip

## Environment Setup

1. Copy the example environment file:

```bash
cp .env.example .env.local
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env.local
```

2. Update values in .env.local as needed:

- GEMINI_API_KEY: required for AI explanation/chat in Scan Result page
- VIRUSTOTAL_API_KEY: optional, enables VirusTotal reputation checks
- WEIGHT_ENTROPY, WEIGHT_YARA, WEIGHT_VT, WEIGHT_AI: optional scoring weights
- JWT_SECRET: optional, recommended for production

## Install Dependencies

```bash
npm install
```

## Run Locally

Start the development server:

```bash
npm run dev
```

The app runs at http://localhost:3000.

## Build and Preview

Build frontend assets:

```bash
npm run build
```

Preview built assets:

```bash
npm run preview
```

Type-check the project:

```bash
npm run lint
```

## API Summary

Main backend routes include:

- Auth: /api/auth/register, /api/auth/login
- Scan: /api/scan, /api/scan/batch, /api/scan/queue
- User data: /api/history, /api/stats
- Analytics: /api/analytics/dashboard, /api/analytics/ai-accuracy
- Admin: /api/admin/logs, /api/admin/health, /api/admin/scans

## Notes

- Uploaded files are stored temporarily in uploads/ and cleaned after scan.
- Local database file is malware_scanner.db.
- If Python is not available on your system PATH as python3, update the scanner command in src/lib/scanner.ts to match your local Python executable.
