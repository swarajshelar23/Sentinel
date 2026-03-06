import crypto from 'crypto';
import fs from 'fs';

export interface ScanFeatures {
  filename: string;
  filesize: number;
  hash_sha256: string;
  entropy: number;
  yara_matches: string[];
  metadata: Record<string, any>;
}

export interface ScanResult {
  score: number;
  classification: 'Safe' | 'Suspicious' | 'Malware' | 'High Risk';
  details: string[];
}

/**
 * Calculates Shannon Entropy of a buffer.
 * Higher entropy (close to 8) suggests encryption or packing.
 */
export function calculateEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;
  const freq: Record<number, number> = {};
  for (const byte of buffer) {
    freq[byte] = (freq[byte] || 0) + 1;
  }
  let entropy = 0;
  for (const byte in freq) {
    const p = freq[byte] / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Simple pattern matching to simulate YARA rules.
 */
export function scanSignatures(buffer: Buffer): string[] {
  const matches: string[] = [];
  const signatures = [
    { name: 'Suspicious_Shellcode', pattern: Buffer.from([0xeb, 0xfe]) }, // JMP $
    { name: 'Potential_Ransomware_Note', pattern: Buffer.from('YOUR FILES HAVE BEEN ENCRYPTED') },
    { name: 'Reverse_Shell_Pattern', pattern: Buffer.from('/bin/sh -i') },
    { name: 'Crypto_Stealer_Pattern', pattern: Buffer.from('0x[a-fA-F0-9]{40}') }, // Ethereum address pattern
  ];

  for (const sig of signatures) {
    if (buffer.includes(sig.pattern)) {
      matches.push(sig.name);
    }
  }
  return matches;
}

/**
 * Threat Scoring Engine
 */
export function calculateThreatScore(features: ScanFeatures, vtResults?: any): ScanResult {
  let score = 0;
  const details: string[] = [];

  // 1. Entropy Analysis
  if (features.entropy > 7.2) {
    score += 30;
    details.push('High entropy detected (potential packing/encryption)');
  } else if (features.entropy > 6.5) {
    score += 15;
    details.push('Moderate entropy detected');
  }

  // 2. YARA/Signature Matches
  if (features.yara_matches.length > 0) {
    score += features.yara_matches.length * 25;
    details.push(`Signature matches: ${features.yara_matches.join(', ')}`);
  }

  // 3. File Size/Type Anomalies (Simple)
  if (features.filename.endsWith('.exe') || features.filename.endsWith('.dll')) {
    score += 10;
    details.push('Executable file type (higher inherent risk)');
  }

  // 4. VirusTotal Reputation (Simulated or Real)
  if (vtResults) {
    const maliciousCount = vtResults.data?.attributes?.last_analysis_stats?.malicious || 0;
    if (maliciousCount > 0) {
      score += maliciousCount * 10;
      details.push(`VirusTotal: ${maliciousCount} engines flagged this file`);
    }
  }

  // Cap score at 100
  score = Math.min(score, 100);

  let classification: ScanResult['classification'] = 'Safe';
  if (score >= 80) classification = 'High Risk';
  else if (score >= 50) classification = 'Malware';
  else if (score >= 20) classification = 'Suspicious';

  return { score, classification, details };
}

export async function performScan(filePath: string, filename: string): Promise<ScanFeatures> {
  const buffer = fs.readFileSync(filePath);
  const hash = crypto.createHash('sha256').update(buffer).digest('hex');
  const entropy = calculateEntropy(buffer);
  const yara_matches = scanSignatures(buffer);
  
  return {
    filename,
    filesize: buffer.length,
    hash_sha256: hash,
    entropy,
    yara_matches,
    metadata: {
      extension: filename.split('.').pop(),
      timestamp: new Date().toISOString(),
      magic: buffer.slice(0, 4).toString('hex'), // Magic bytes
    }
  };
}
