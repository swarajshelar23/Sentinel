import crypto from 'crypto';
import fs from 'fs';
import { execSync } from 'child_process';
import path from 'path';

export interface ScanFeatures {
  filename: string;
  filesize: number;
  hash_sha256: string;
  entropy: number;
  yara_matches: string[];
  metadata: Record<string, any>;
  ai_probability?: number;
  ai_prediction?: string;
}

export interface ScanResult {
  score: number;
  classification: 'Safe' | 'Suspicious' | 'Malware' | 'High Risk';
  details: string[];
}

/**
 * Calculates Shannon Entropy of a buffer.
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
    { name: 'Suspicious_Shellcode', pattern: Buffer.from([0xeb, 0xfe]) },
    { name: 'Potential_Ransomware_Note', pattern: Buffer.from('YOUR FILES HAVE BEEN ENCRYPTED') },
    { name: 'Reverse_Shell_Pattern', pattern: Buffer.from('/bin/sh -i') },
    { name: 'Crypto_Stealer_Pattern', pattern: Buffer.from('0x[a-fA-F0-9]{40}') },
    { name: 'Suspicious_PE_Header', pattern: Buffer.from('MZ') }, // Basic check for executables
    { name: 'PowerShell_Download', pattern: Buffer.from('Invoke-WebRequest') },
    { name: 'Base64_Encoded_Payload', pattern: Buffer.from('base64') },
    { name: 'WannaCry_Killswitch', pattern: Buffer.from('iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com') },
    { name: 'Discord_Webhook_Stealer', pattern: Buffer.from('discord.com/api/webhooks') },
  ];

  for (const sig of signatures) {
    if (buffer.includes(sig.pattern)) {
      matches.push(sig.name);
    }
  }
  return matches;
}

/**
 * Calls the Python AI Engine for prediction.
 */
export function getAiPrediction(filePath: string, features: ScanFeatures, vtMaliciousCount: number = 0): { probability: number; prediction: string } {
  try {
    const extension = path.extname(features.filename).toLowerCase();
    const extMap: Record<string, number> = { '.exe': 1, '.dll': 1, '.bin': 1, '.sh': 2, '.py': 2, '.js': 2, '.doc': 3, '.pdf': 3 };
    
    const suspiciousKeywords = [
      Buffer.from('eval'), 
      Buffer.from('exec'), 
      Buffer.from('system'), 
      Buffer.from('shell_exec'), 
      Buffer.from('powershell'), 
      Buffer.from('cmd.exe'), 
      Buffer.from('http'), 
      Buffer.from('https'),
      Buffer.from('curl'),
      Buffer.from('wget'),
      Buffer.from('chmod'),
      Buffer.from('rm -rf')
    ];
    const buffer = fs.readFileSync(filePath); 
    const suspiciousCount = suspiciousKeywords.reduce((acc, kw) => acc + (buffer.includes(kw) ? 1 : 0), 0);

    const pythonFeatures = {
      file_size: features.filesize,
      entropy: features.entropy,
      extension_type: extMap[extension] || 0,
      suspicious_strings: suspiciousCount,
      yara_matches: features.yara_matches.length,
      vt_reputation: vtMaliciousCount
    };

    const scriptPath = path.resolve('ai-engine', 'predict.py');
    const command = `python3 "${scriptPath}" '${JSON.stringify(pythonFeatures)}'`;
    const output = execSync(command, { encoding: 'utf8' });
    return JSON.parse(output);
  } catch (err) {
    console.error('AI Engine failed, using fallback:', err);
    return { probability: 0.5, prediction: 'Unknown' };
  }
}

export interface ScoringConfig {
  entropy: number;
  yara: number;
  virusTotal: number;
  ai: number;
}

const DEFAULT_WEIGHTS: ScoringConfig = {
  entropy: 20,
  yara: 30,
  virusTotal: 25,
  ai: 25
};

/**
 * Threat Scoring Engine (Updated with Dynamic Weights)
 */
export function calculateThreatScore(
  features: ScanFeatures, 
  vtResults?: any, 
  customWeights?: Partial<ScoringConfig>
): ScanResult {
  const weights = { ...DEFAULT_WEIGHTS, ...customWeights };
  let score = 0;
  const details: string[] = [];

  // Determine available components and normalize weights if necessary
  // For example, if VT is not available, we might want to redistribute its weight
  let totalAvailableWeight = weights.entropy + weights.yara + weights.ai;
  if (vtResults) {
    totalAvailableWeight += weights.virusTotal;
  }

  const getNormalizedWeight = (weight: number) => {
    return (weight / totalAvailableWeight) * 100;
  };

  // 1. Entropy Analysis
  if (features.entropy > 7.2) {
    const weight = getNormalizedWeight(weights.entropy);
    score += weight;
    details.push(`High entropy detected (${Math.round(weight)}% weight)`);
  }

  // 2. YARA/Signature Matches
  if (features.yara_matches.length > 0) {
    const maxWeight = getNormalizedWeight(weights.yara);
    const matchScore = Math.min(features.yara_matches.length * (maxWeight / 2), maxWeight);
    score += matchScore;
    details.push(`Signature matches: ${features.yara_matches.join(', ')} (${Math.round(matchScore)}% weight)`);
  }

  // 3. VirusTotal Reputation
  if (vtResults) {
    const maliciousCount = vtResults.data?.attributes?.last_analysis_stats?.malicious || 0;
    if (maliciousCount > 0) {
      const maxWeight = getNormalizedWeight(weights.virusTotal);
      const vtScore = Math.min(maliciousCount * (maxWeight / 5), maxWeight);
      score += vtScore;
      details.push(`VirusTotal: ${maliciousCount} engines flagged this file (${Math.round(vtScore)}% weight)`);
    }
  }

  // 4. AI Model Probability
  if (features.ai_probability !== undefined) {
    const maxWeight = getNormalizedWeight(weights.ai);
    const aiImpact = features.ai_probability * maxWeight;
    score += aiImpact;
    details.push(`AI Classifier: ${Math.round(features.ai_probability * 100)}% malicious probability (${Math.round(aiImpact)}% weight)`);
  }

  // Cap score at 100
  score = Math.min(Math.round(score), 100);

  let classification: ScanResult['classification'] = 'Safe';
  if (score >= 75) classification = 'High Risk';
  else if (score >= 40) classification = 'Malware';
  else if (score >= 10) classification = 'Suspicious';

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
      magic: buffer.slice(0, 4).toString('hex'),
    }
  };
}
