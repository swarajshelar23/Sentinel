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
 * Checks if file type is in safe list of document/media formats.
 */
export function isSafeFileType(filename: string): boolean {
  const safeExtensions = [
    '.ppt', '.pptx',          // PowerPoint
    '.doc', '.docx',          // Word
    '.xls', '.xlsx',          // Excel
    '.pdf',                   // PDF
    '.txt',                   // Text
    '.jpg', '.jpeg',          // JPEG images
    '.png',                   // PNG images
    '.gif',                   // GIF images
    '.bmp',                   // Bitmap
    '.webp',                  // WebP
    '.zip', '.rar', '.7z',    // Archives (usually safe)
    '.csv',                   // CSV
    '.rtf',                   // Rich Text Format
    '.odt', '.ods', '.odp',   // OpenDocument formats
  ];
  
  const ext = filename.toLowerCase().substring(filename.lastIndexOf('.'));
  return safeExtensions.includes(ext);
}

/**
 * Identifies suspicious behavior indicators with improved thresholds.
 */
export function getIndicators(features: ScanFeatures, buffer: Buffer, isSafeFile: boolean = false): string[] {
  const indicators: string[] = [];
  
  // For safe file types, only flag extreme indicators
  if (isSafeFile) {
    // Only flag if executable headers are present in documents (highly suspicious)
    if (features.headers?.is_executable) {
      indicators.push('EXECUTABLE_IN_DOCUMENT (Possible Archive or Embedded Malware)');
    }
  } else {
    // For executables, apply stricter entropy thresholds
    if (features.entropy > 7.8) {
      indicators.push('EXTREME_ENTROPY (Likely Encrypted/Packed Malware)');
    } else if (features.entropy > 7.5 && features.headers?.is_executable) {
      indicators.push('HIGH_ENTROPY_EXECUTABLE (Possible Packing)');
    }
  }
  
  if (features.packer) {
    indicators.push(`PACKED_EXECUTABLE (${features.packer})`);
  }
  
  // Only flag suspicious API imports for executables
  if (features.headers?.is_executable || features.headers?.type?.includes('Executable')) {
    const suspiciousStrings = ['CreateRemoteThread', 'WriteProcessMemory', 'OpenProcess', 'ShellExecute', 'HttpOpenRequest'];
    const foundStrings = extractStrings(buffer).filter(s => suspiciousStrings.some(ss => s.includes(ss)));
    if (foundStrings.length > 0) {
      indicators.push(`SUSPICIOUS_API_IMPORTS: ${foundStrings.join(', ')}`);
    }
  }

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
 * Calls the Python AI Engine for prediction with improved handling.
 */
export function getAiPrediction(filePath: string, features: ScanFeatures, vtMaliciousCount: number = 0): { probability: number; prediction: string } {
  try {
    // For safe file types, apply prior probability reduction
    const isSafeFile = isSafeFileType(features.filename);
    const extension = path.extname(features.filename).toLowerCase();
    
    // Map extensions to risk levels (safe documents get type 3, less suspicious)
    const extMap: Record<string, number> = { 
      '.exe': 1, '.dll': 1, '.bin': 1, '.com': 1,  // Executables
      '.sh': 2, '.py': 2, '.js': 2, '.bat': 2,      // Scripts
      '.ppt': 3, '.pptx': 3, '.doc': 3, '.docx': 3, '.pdf': 3, '.xlsx': 3, '.xls': 3, // Documents (safe)
      '.jpg': 4, '.png': 4, '.gif': 4, '.bmp': 4    // Media (safest)
    };
    
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
      vt_reputation: vtMaliciousCount,
      is_safe_file_type: isSafeFile ? 1 : 0
    };

    const scriptPath = path.resolve('ai-engine', 'predict.py');
    const command = `python3 "${scriptPath}" '${JSON.stringify(pythonFeatures)}'`;
    const output = execSync(command, { encoding: 'utf8' });
    return JSON.parse(output);
  } catch (err) {
    console.error('AI Engine failed, using fallback:', err);
    // For safe file types, return lower default probability
    return { probability: 0.15, prediction: 'Benign' };
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
 * Multi-Stage Threat Scoring Engine with Improved Detection Pipeline
 * 
 * Stage 1: File Type Validation - Safe document formats get reduced scores
 * Stage 2: Entropy Analysis - Updated thresholds (< 6.5 normal, 6.5-7.2 suspicious, > 7.2 packed)
 * Stage 3: VirusTotal Confidence - Only mark malware if > 5 engines detect
 * Stage 4: AI Model Threshold - < 0.40 safe, 0.40-0.70 suspicious, > 0.70 malware
 * Stage 5: Combined Threat Score - Weighted combination of all indicators
 * 
 * Classification Thresholds:
 * 0-30: SAFE
 * 30-60: SUSPICIOUS
 * 60-80: MALWARE LIKELY
 * 80-100: HIGH RISK MALWARE
 */
export function calculateThreatScore(
  features: ScanFeatures, 
  vtResults?: any, 
  customWeights?: Partial<ScoringConfig>,
  isSafeFileType: boolean = false
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

  // --- STAGE 1: FILE TYPE VALIDATION ---
  if (isSafeFileType) {
    details.push('File type: Common document format (lower risk)');
    
    // For safe file types, only proceed if there are strong suspicious indicators
    const hasSuspiciousIndicators = 
      features.yara_matches.length > 1 || 
      (features.headers?.is_executable) || 
      (features.ai_probability && features.ai_probability > 0.6) ||
      (vtResults?.data?.attributes?.last_analysis_stats?.malicious > 3);
    
    if (!hasSuspiciousIndicators) {
      // No strong indicators - mark as safe
      details.push('No strong malicious indicators detected');
      return {
        score: 5,
        classification: 'Safe',
        details,
        contributions
      };
    }
  }

  // --- STAGE 2: ENTROPY ANALYSIS THRESHOLD ---
  if (features.entropy > 7.2) {
    // Only applies significant penalty for executables with extreme entropy
    if (features.headers?.is_executable) {
      const weight = 30;
      score += weight;
      contributions.entropy = weight;
      details.push(`High entropy detected in executable (${Math.round(features.entropy * 100) / 100}) - possible packing (${weight}pts)`);
    } else if (!isSafeFileType) {
      const weight = 15;
      score += weight;
      contributions.entropy = weight;
      details.push(`High entropy detected (${Math.round(features.entropy * 100) / 100}) (${weight}pts)`);
    }
  } else if (features.entropy > 6.5 && features.headers?.is_executable) {
    // Moderate entropy for executables
    const weight = 15;
    score += weight;
    contributions.entropy = weight;
    details.push(`Moderate entropy in executable (${Math.round(features.entropy * 100) / 100}) (${weight}pts)`);
  } else if (features.entropy < 6.5) {
    // Low entropy = normal file
    details.push(`Low entropy (${Math.round(features.entropy * 100) / 100}) - typical for compressed/normal files`);
  }

  // --- STAGE 3: VIRUSTOTAL CONFIDENCE ---
  if (vtResults) {
    const maliciousCount = vtResults.data?.attributes?.last_analysis_stats?.malicious || 0;
    
    if (maliciousCount > 5) {
      // Strong detection consensus from VirusTotal (> 5 engines)
      const weight = Math.min(maliciousCount * 3, 35);
      score += weight;
      contributions.virusTotal = weight;
      details.push(`VirusTotal: ${maliciousCount} engines detected malware - strong consensus (${weight}pts)`);
    } else if (maliciousCount > 0) {
      // Weak detection (1-5 engines) - could be false positive
      const weight = maliciousCount * 2;
      score += weight;
      contributions.virusTotal = weight;
      details.push(`VirusTotal: ${maliciousCount} engines detected malware - weak consensus (${weight}pts)`);
    } else {
      // No detections - good sign
      details.push('VirusTotal: 0 engines detected malware - likely safe');
    }
  }

  // --- STAGE 4: AI MODEL THRESHOLD ---
  if (features.ai_probability !== undefined) {
    if (features.ai_probability > 0.70) {
      // High probability of malware (> 0.70)
      const weight = Math.round(features.ai_probability * 35);
      score += weight;
      contributions.ai = weight;
      details.push(`AI Model: ${Math.round(features.ai_probability * 100)}% malware probability - high confidence (${weight}pts)`);
    } else if (features.ai_probability > 0.40) {
      // Suspicious (0.40 - 0.70)
      const weight = Math.round(features.ai_probability * 20);
      score += weight;
      contributions.ai = weight;
      details.push(`AI Model: ${Math.round(features.ai_probability * 100)}% malware probability - suspicious (${weight}pts)`);
    } else {
      // Safe (< 0.40)
      details.push(`AI Model: ${Math.round(features.ai_probability * 100)}% malware probability - likely safe`);
    }
  }

  // --- STAGE 5: YARA SIGNATURE MATCHING ---
  if (features.yara_matches.length > 0) {
    // Only high-confidence signatures count significantly
    const highConfidenceSigs = features.yara_matches.filter(sig => 
      !sig.includes('base64') && 
      !sig.includes('PE_Header')
    );
    
    if (highConfidenceSigs.length > 0) {
      const weight = Math.min(highConfidenceSigs.length * 8, 40);
      score += weight;
      contributions.yara = weight;
      details.push(`Signature matches: ${features.yara_matches.join(', ')} (${weight}pts)`);
    } else {
      details.push(`Generic signatures found (not indicative): ${features.yara_matches.join(', ')}`);
    }
  }

  // Cap score at 100
  score = Math.min(Math.round(score), 100);

  // --- CLASSIFICATION WITH NEW THRESHOLDS ---
  let classification: ScanResult['classification'] = 'Safe';
  if (score >= 80) {
    classification = 'High Risk';
  } else if (score >= 60) {
    classification = 'Malware';
  } else if (score >= 30) {
    classification = 'Suspicious';
  }

  return { score, classification, details, contributions };
}

export async function performScan(filePath: string, filename: string): Promise<ScanFeatures> {
  const buffer = fs.readFileSync(filePath);
  const hash = crypto.createHash('sha256').update(buffer).digest('hex');
  const entropy = calculateEntropy(buffer);
  const yara_matches = scanSignatures(buffer);
  const isSafeFile = isSafeFileType(filename);
  
  const features: ScanFeatures = {
    filename,
    filesize: buffer.length,
    hash_sha256: hash,
    entropy,
    yara_matches,
    metadata: {
      extension: filename.split('.').pop(),
      timestamp: new Date().toISOString(),
      file_type_category: isSafeFile ? 'safe_document' : 'potentially_executable'
    }
  };

  features.strings = extractStrings(buffer);
  features.packer = detectPacker(buffer) || undefined;
  features.headers = analyzeHeaders(buffer);
  features.indicators = getIndicators(features, buffer, isSafeFile);
  features.metadata.magic = features.headers.magic;

  return features;
}
