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
  strings?: string[];
  headers?: Record<string, any>;
  packer?: string;
  indicators?: string[];
}

export interface ScanResult {
  score: number;
  classification: 'Safe' | 'Suspicious' | 'Malware' | 'High Risk';
  details: string[];
  contributions: {
    entropy: number;
    yara: number;
    virusTotal: number;
    ai: number;
  };
}

/**
 * Extracts printable strings from a buffer.
 */
export function extractStrings(buffer: Buffer, minLength: number = 4): string[] {
  const strings: string[] = [];
  let currentString = '';
  for (const byte of buffer) {
    if (byte >= 32 && byte <= 126) {
      currentString += String.fromCharCode(byte);
    } else {
      if (currentString.length >= minLength) {
        strings.push(currentString);
      }
      currentString = '';
    }
  }
  return strings.slice(0, 100); // Limit to first 100 strings
}

/**
 * Detects common packers like UPX.
 */
export function detectPacker(buffer: Buffer): string | null {
  const packers = [
    { name: 'UPX', pattern: Buffer.from('UPX!') },
    { name: 'ASPack', pattern: Buffer.from('.aspack') },
    { name: 'Themida', pattern: Buffer.from('Themida') },
  ];
  for (const p of packers) {
    if (buffer.includes(p.pattern)) return p.name;
  }
  return null;
}

/**
 * Analyzes file headers for suspicious characteristics.
 */
export function analyzeHeaders(buffer: Buffer): Record<string, any> {
  const headers: Record<string, any> = {};
  const magic = buffer.slice(0, 4).toString('hex');
  if (buffer.slice(0, 2).toString() === 'MZ') {
    headers.type = 'PE (Windows Executable)';
    headers.is_executable = true;
  } else if (magic === '7f454c46') {
    headers.type = 'ELF (Linux Executable)';
    headers.is_executable = true;
  } else if (magic === 'cafebabe' || magic === 'feedface') {
    headers.type = 'Mach-O (macOS Executable)';
    headers.is_executable = true;
  } else {
    headers.type = 'Unknown';
    headers.is_executable = false;
  }
  headers.magic = magic;
  return headers;
}

/**
 * Identifies suspicious behavior indicators.
 */
export function getIndicators(features: ScanFeatures, buffer: Buffer): string[] {
  const indicators: string[] = [];
  if (features.entropy > 7.5) indicators.push('EXTREME_ENTROPY (Potential Encryption/Packing)');
  if (features.packer) indicators.push(`PACKED_EXECUTABLE (${features.packer})`);
  if (features.headers?.is_executable && features.entropy > 7.0) indicators.push('SUSPICIOUS_EXECUTABLE_ENTROPY');
  
  const suspiciousStrings = ['CreateRemoteThread', 'WriteProcessMemory', 'OpenProcess', 'ShellExecute', 'HttpOpenRequest'];
  const foundStrings = extractStrings(buffer).filter(s => suspiciousStrings.some(ss => s.includes(ss)));
  if (foundStrings.length > 0) indicators.push(`SUSPICIOUS_API_IMPORTS: ${foundStrings.join(', ')}`);

  return indicators;
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
  const contributions = {
    entropy: 0,
    yara: 0,
    virusTotal: 0,
    ai: 0
  };

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
    contributions.entropy = weight;
    details.push(`High entropy detected (${Math.round(weight)}% weight)`);
  }

  // 2. YARA/Signature Matches
  if (features.yara_matches.length > 0) {
    const maxWeight = getNormalizedWeight(weights.yara);
    const matchScore = Math.min(features.yara_matches.length * (maxWeight / 2), maxWeight);
    score += matchScore;
    contributions.yara = matchScore;
    details.push(`Signature matches: ${features.yara_matches.join(', ')} (${Math.round(matchScore)}% weight)`);
  }

  // 3. VirusTotal Reputation
  if (vtResults) {
    const maliciousCount = vtResults.data?.attributes?.last_analysis_stats?.malicious || 0;
    if (maliciousCount > 0) {
      const maxWeight = getNormalizedWeight(weights.virusTotal);
      const vtScore = Math.min(maliciousCount * (maxWeight / 5), maxWeight);
      score += vtScore;
      contributions.virusTotal = vtScore;
      details.push(`VirusTotal: ${maliciousCount} engines flagged this file (${Math.round(vtScore)}% weight)`);
    }
  }

  // 4. AI Model Probability
  if (features.ai_probability !== undefined) {
    const maxWeight = getNormalizedWeight(weights.ai);
    const aiImpact = features.ai_probability * maxWeight;
    score += aiImpact;
    contributions.ai = aiImpact;
    details.push(`AI Classifier: ${Math.round(features.ai_probability * 100)}% malicious probability (${Math.round(aiImpact)}% weight)`);
  }

  // Cap score at 100
  score = Math.min(Math.round(score), 100);

  let classification: ScanResult['classification'] = 'Safe';
  if (score >= 75) classification = 'High Risk';
  else if (score >= 40) classification = 'Malware';
  else if (score >= 10) classification = 'Suspicious';

  return { score, classification, details, contributions };
}

export async function performScan(filePath: string, filename: string): Promise<ScanFeatures> {
  const buffer = fs.readFileSync(filePath);
  const hash = crypto.createHash('sha256').update(buffer).digest('hex');
  const entropy = calculateEntropy(buffer);
  const yara_matches = scanSignatures(buffer);
  
  const features: ScanFeatures = {
    filename,
    filesize: buffer.length,
    hash_sha256: hash,
    entropy,
    yara_matches,
    metadata: {
      extension: filename.split('.').pop(),
      timestamp: new Date().toISOString(),
    }
  };

  features.strings = extractStrings(buffer);
  features.packer = detectPacker(buffer) || undefined;
  features.headers = analyzeHeaders(buffer);
  features.indicators = getIndicators(features, buffer);
  features.metadata.magic = features.headers.magic;

  return features;
}
