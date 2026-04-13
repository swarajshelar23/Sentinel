import crypto from 'crypto';
import fs from 'fs';
import { spawnSync } from 'child_process';
import path from 'path';
import { 
  validateFileSignature, 
  analyzeStrings, 
  applySafeFileHeuristic, 
  calibrateProbability,
  generateClassificationExplanation 
} from './detection-modules';

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
  signatureValidation?: { isValid: boolean; riskFlag: boolean; details: string };
  stringAnalysis?: { indicatorCount: number; riskFlag: boolean; summary: string; suspiciousIndicators?: any[] };
  safeFileHeuristic?: { isSafe: boolean; confidence: number; reasons: string[] };
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
  explanation?: string;
  safeFileReason?: string;
}

type PythonRunner = {
  command: string;
  prefixArgs: string[];
};

let cachedPythonRunner: PythonRunner | null | undefined;

function resolvePythonRunner(): PythonRunner | null {
  if (cachedPythonRunner !== undefined) {
    return cachedPythonRunner;
  }

  const candidates: PythonRunner[] = process.platform === 'win32'
    ? [
        { command: 'py', prefixArgs: ['-3'] },
        { command: 'python', prefixArgs: [] },
        { command: 'python3', prefixArgs: [] }
      ]
    : [
        { command: 'python3', prefixArgs: [] },
        { command: 'python', prefixArgs: [] }
      ];

  for (const candidate of candidates) {
    const probe = spawnSync(candidate.command, [...candidate.prefixArgs, '--version'], {
      encoding: 'utf8'
    });

    if (probe.status === 0) {
      cachedPythonRunner = candidate;
      return cachedPythonRunner;
    }
  }

  cachedPythonRunner = null;
  return cachedPythonRunner;
}

function runAiPredictionScript(scriptPath: string, features: Record<string, number>): string {
  const runner = resolvePythonRunner();

  if (!runner) {
    throw new Error('No Python interpreter found. Install Python or the Python Launcher (py).');
  }

  const result = spawnSync(
    runner.command,
    [...runner.prefixArgs, scriptPath, JSON.stringify(features)],
    { encoding: 'utf8' }
  );

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    const errorOutput = (result.stderr || result.stdout || 'Unknown error').trim();
    throw new Error(`AI engine process failed (${runner.command}): ${errorOutput}`);
  }

  return (result.stdout || '').trim();
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
 * Now integrates enhanced string analysis from detection modules.
 */
export function getIndicators(features: ScanFeatures, buffer: Buffer, isSafeFile: boolean = false): string[] {
  const indicators: string[] = [];
  
  // Use enhanced string analysis from detection modules
  const stringAnalysis = analyzeStrings(buffer);
  features.stringAnalysis = {
    indicatorCount: stringAnalysis.indicatorCount,
    riskFlag: stringAnalysis.riskFlag,
    summary: stringAnalysis.summary,
    suspiciousIndicators: stringAnalysis.suspiciousIndicators
  };
  
  // For safe file types, only flag extreme indicators
  if (isSafeFile) {
    // Only flag if executable headers are present in documents (highly suspicious)
    if (features.headers?.is_executable) {
      indicators.push('EXECUTABLE_IN_DOCUMENT (Possible Archive or Embedded Malware)');
    }
    // For safe files, only add string analysis if risk flag is true
    if (stringAnalysis.riskFlag) {
      stringAnalysis.suspiciousIndicators.forEach(ind => {
        indicators.push(`SUSPICIOUS_STRINGS_${ind.category.toUpperCase()}: ${ind.keywords.join(', ')}`);
      });
    }
  } else {
    // For executables, apply stricter entropy thresholds
    if (features.entropy > 7.8) {
      indicators.push('EXTREME_ENTROPY (Likely Encrypted/Packed Malware)');
    } else if (features.entropy > 7.5 && features.headers?.is_executable) {
      indicators.push('HIGH_ENTROPY_EXECUTABLE (Possible Packing)');
    }
    
    // For non-safe files, add all significant string analysis findings
    if (stringAnalysis.indicatorCount >= 2) {
      stringAnalysis.suspiciousIndicators.forEach(ind => {
        indicators.push(`SUSPICIOUS_STRINGS_${ind.category.toUpperCase()}: ${ind.keywords.join(', ')}`);
      });
    }
  }
  
  if (features.packer) {
    indicators.push(`PACKED_EXECUTABLE (${features.packer})`);
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
 * Applies probability calibration to prevent overconfident predictions.
 */
export function getAiPrediction(filePath: string, features: ScanFeatures, vtMaliciousCount: number = 0): { probability: number; prediction: string; calibrated?: boolean; explanation?: string } {
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
    const output = runAiPredictionScript(scriptPath, pythonFeatures);
    let result = JSON.parse(output);
    
    // Apply probability calibration
    const indicatorCount = features.stringAnalysis?.indicatorCount || 0;
    const safeFileBoost = features.safeFileHeuristic?.isSafe || false;
    const calibratedProb = calibrateProbability(result.probability, safeFileBoost, indicatorCount);
    
    // Determine prediction based on calibrated probability
    let calibratedPrediction = result.prediction;
    if (calibratedProb > 0.70) {
      calibratedPrediction = 'Malicious';
    } else if (calibratedProb > 0.40) {
      calibratedPrediction = 'Suspicious';
    } else {
      calibratedPrediction = 'Benign';
    }
    
    return { 
      probability: calibratedProb, 
      prediction: calibratedPrediction,
      calibrated: true,
      explanation: `Raw probability: ${(result.probability * 100).toFixed(1)}% → Calibrated: ${(calibratedProb * 100).toFixed(1)}%`
    };
  } catch (err) {
    console.error('AI Engine failed, using fallback:', err);
    // For safe file types, return lower default probability
    return { probability: 0.15, prediction: 'Benign', calibrated: false };
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
 * Stage 1: Safe File Heuristics - Common documents with low risk signals auto-classified as SAFE
 * Stage 2: File Signature Validation - Detect extension/header mismatches
 * Stage 3: Entropy Analysis - Updated thresholds (< 6.5 normal, 6.5-7.2 suspicious, > 7.2 packed)
 * Stage 4: VirusTotal Confidence - Only mark malware if > 5 engines detect
 * Stage 5: AI Model Threshold - < 0.40 safe, 0.40-0.70 suspicious, > 0.70 malware
 * Stage 6: Combined Threat Score - Weighted combination of all indicators
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

  // --- STAGE 1: SAFE FILE HEURISTICS ---
  // Check if file can be automatically classified as SAFE
  const vtMaliciousCount = vtResults?.data?.attributes?.last_analysis_stats?.malicious || 0;
  const safeFileHeuristic = applySafeFileHeuristic(
    features.filename,
    features.entropy,
    vtMaliciousCount,
    features.yara_matches
  );
  features.safeFileHeuristic = safeFileHeuristic;
  
  if (safeFileHeuristic.isSafe) {
    details.push('Safe File Classification: Common document format with no suspicious signals');
    safeFileHeuristic.reasons.forEach(reason => details.push(`  ✓ ${reason}`));
    return {
      score: 0,
      classification: 'Safe',
      details,
      contributions,
      explanation: generateClassificationExplanation('Safe', 0, safeFileHeuristic.reasons),
      safeFileReason: safeFileHeuristic.reasons.join('; ')
    };
  }

  // If safe file heuristic failed but file is safe type, add the reasons as details
  if (isSafeFileType && safeFileHeuristic.reasons.length > 0) {
    details.push('File type: Common document format (lower risk)');
    safeFileHeuristic.reasons.forEach(reason => details.push(`  ✓ ${reason}`));
  }

  // --- STAGE 2: FILE SIGNATURE VALIDATION ---
  const signatureValidation = validateFileSignature(features.filename);
  features.signatureValidation = signatureValidation;
  
  if (!signatureValidation.isValid) {
    const weight = 25;
    score += weight;
    contributions.entropy += weight;
    details.push(`File Signature Mismatch: ${signatureValidation.details} (${weight}pts) - SUSPICIOUS`);
  } else {
    details.push(`File Signature: Valid - ${signatureValidation.actualType || 'format recognized'}`);
  }

  // --- STAGE 3: ENTROPY ANALYSIS THRESHOLD ---
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

  // --- STAGE 4: VIRUSTOTAL CONFIDENCE ---
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

  // --- STAGE 5: AI MODEL THRESHOLD WITH CALIBRATION ---
  if (features.ai_probability !== undefined) {
    if (features.ai_probability > 0.70) {
      // High probability of malware (> 0.70)
      const weight = Math.round(features.ai_probability * 35);
      score += weight;
      contributions.ai = weight;
      details.push(`AI Model: ${Math.round(features.ai_probability * 100)}% malware probability (calibrated) - high confidence (${weight}pts)`);
    } else if (features.ai_probability > 0.40) {
      // Suspicious (0.40 - 0.70)
      const weight = Math.round(features.ai_probability * 20);
      score += weight;
      contributions.ai = weight;
      details.push(`AI Model: ${Math.round(features.ai_probability * 100)}% malware probability (calibrated) - suspicious (${weight}pts)`);
    } else {
      // Safe (< 0.40)
      details.push(`AI Model: ${Math.round(features.ai_probability * 100)}% malware probability (calibrated) - likely safe`);
    }
  }

  // --- STAGE 6: YARA SIGNATURE MATCHING ---
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

  // Generate structured explanation
  const explanation = generateClassificationExplanation(classification, score, details);

  return { 
    score, 
    classification, 
    details, 
    contributions,
    explanation,
    safeFileReason: classification === 'Safe' ? details.join('; ') : undefined
  };
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
  
  // Run enhanced detection modules
  features.signatureValidation = validateFileSignature(filePath);
  features.stringAnalysis = analyzeStrings(buffer);
  
  features.indicators = getIndicators(features, buffer, isSafeFile);
  features.metadata.magic = features.headers.magic;

  return features;
}
