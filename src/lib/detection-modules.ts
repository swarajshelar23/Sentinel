/**
 * Enhanced Detection Modules for Sentinel Prime
 * 
 * This module provides advanced analysis signals to improve malware classification accuracy:
 * 1. File Signature Validation - Detects extension/header mismatches
 * 2. String Analysis - Scans for suspicious keywords with multi-indicator validation
 * 3. Safe File Heuristics - Automatically classifies known-safe files based on multiple signals
 */

import fs from 'fs';

/**
 * File signature definitions - magic bytes for common file formats
 * Maps file extensions to their expected header signatures
 */
const FileSignatures: Record<string, { signatures: Buffer[], offsets: number[], description: string }> = {
  '.pptx': {
    signatures: [Buffer.from([0x50, 0x4B, 0x03, 0x04])], // ZIP header
    offsets: [0],
    description: 'Office PowerPoint (ZIP-based)'
  },
  '.docx': {
    signatures: [Buffer.from([0x50, 0x4B, 0x03, 0x04])],
    offsets: [0],
    description: 'Office Word (ZIP-based)'
  },
  '.xlsx': {
    signatures: [Buffer.from([0x50, 0x4B, 0x03, 0x04])],
    offsets: [0],
    description: 'Office Excel (ZIP-based)'
  },
  '.pdf': {
    signatures: [Buffer.from('%PDF')],
    offsets: [0],
    description: 'PDF Document'
  },
  '.jpg': {
    signatures: [Buffer.from([0xFF, 0xD8, 0xFF])],
    offsets: [0],
    description: 'JPEG Image'
  },
  '.jpeg': {
    signatures: [Buffer.from([0xFF, 0xD8, 0xFF])],
    offsets: [0],
    description: 'JPEG Image'
  },
  '.png': {
    signatures: [Buffer.from([0x89, 0x50, 0x4E, 0x47])],
    offsets: [0],
    description: 'PNG Image'
  },
  '.gif': {
    signatures: [Buffer.from('GIF')],
    offsets: [0],
    description: 'GIF Image'
  },
  '.bmp': {
    signatures: [Buffer.from('BM')],
    offsets: [0],
    description: 'Bitmap Image'
  },
  '.zip': {
    signatures: [Buffer.from([0x50, 0x4B, 0x03, 0x04])],
    offsets: [0],
    description: 'ZIP Archive'
  },
  '.rar': {
    signatures: [Buffer.from('Rar!')],
    offsets: [0],
    description: 'RAR Archive'
  },
  '.exe': {
    signatures: [Buffer.from('MZ')],
    offsets: [0],
    description: 'Windows Executable'
  },
  '.dll': {
    signatures: [Buffer.from('MZ')],
    offsets: [0],
    description: 'Windows DLL'
  }
};

/**
 * Suspicious keyword patterns for malware detection
 * Organized by category with severity levels
 */
const SuspiciousKeywords = {
  // Process execution and injection
  processInjection: [
    { pattern: 'CreateRemoteThread', severity: 'high' },
    { pattern: 'WriteProcessMemory', severity: 'high' },
    { pattern: 'OpenProcess', severity: 'high' },
    { pattern: 'VirtualAllocEx', severity: 'high' },
    { pattern: 'SetThreadContext', severity: 'high' },
    { pattern: 'ResumeThread', severity: 'high' },
    { pattern: 'CreateProcessA', severity: 'medium' },
    { pattern: 'CreateProcessW', severity: 'medium' },
  ],
  
  // Command execution
  commandExecution: [
    { pattern: 'powershell', severity: 'high' },
    { pattern: 'cmd.exe', severity: 'high' },
    { pattern: 'cmd /c', severity: 'high' },
    { pattern: 'ShellExecute', severity: 'high' },
    { pattern: 'WinExec', severity: 'medium' },
    { pattern: '/bin/sh', severity: 'high' },
    { pattern: '/bin/bash', severity: 'medium' },
  ],
  
  // Memory allocation and shellcode
  memoryAllocation: [
    { pattern: 'VirtualAlloc', severity: 'high' },
    { pattern: 'shellcode', severity: 'high' },
    { pattern: 'LoadLibrary', severity: 'medium' },
    { pattern: 'GetProcAddress', severity: 'medium' },
  ],
  
  // Encoding and obfuscation
  encoding: [
    { pattern: 'base64', severity: 'medium' },
    { pattern: 'Base64', severity: 'medium' },
    { pattern: 'base32', severity: 'medium' },
    { pattern: 'hex encode', severity: 'low' },
    { pattern: 'XOR', severity: 'medium' },
  ],
  
  // Networking and C2
  networking: [
    { pattern: 'HttpOpenRequest', severity: 'medium' },
    { pattern: 'InternetOpen', severity: 'medium' },
    { pattern: 'socket', severity: 'low' },
    { pattern: 'connect', severity: 'low' },
  ],
  
  // Registry and system modification
  systemModification: [
    { pattern: 'RegSetValueEx', severity: 'high' },
    { pattern: 'RegCreateKey', severity: 'medium' },
    { pattern: 'SetWindowsHookEx', severity: 'high' },
  ]
};

/**
 * File Signature Validation Module
 * Checks if file extension matches the actual file header
 * 
 * @param filepath - Path to the file to validate
 * @returns Object containing validation result and details
 */
export function validateFileSignature(filepath: string): {
  isValid: boolean;
  extension: string;
  actualType: string | null;
  riskFlag: boolean;
  details: string;
} {
  try {
    const filename = filepath.split('\\').pop() || '';
    const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
    
    // If no signature definition for this extension, assume valid
    const sigDef = FileSignatures[ext];
    if (!sigDef) {
      return {
        isValid: true,
        extension: ext,
        actualType: null,
        riskFlag: false,
        details: 'No signature definition for this format'
      };
    }
    
    // Read file header
    const bufferSize = Math.min(1024, fs.statSync(filepath).size);
    const buffer = Buffer.alloc(bufferSize);
    const fd = fs.openSync(filepath, 'r');
    fs.readSync(fd, buffer, 0, bufferSize, 0);
    fs.closeSync(fd);
    
    // Check each possible signature at specified offsets
    for (let i = 0; i < sigDef.signatures.length; i++) {
      const sig = sigDef.signatures[i];
      const offset = sigDef.offsets[i] || 0;
      
      if (buffer.slice(offset, offset + sig.length).equals(sig)) {
        return {
          isValid: true,
          extension: ext,
          actualType: sigDef.description,
          riskFlag: false,
          details: `File signature matches expected format: ${sigDef.description}`
        };
      }
    }
    
    // Signature mismatch detected
    return {
      isValid: false,
      extension: ext,
      actualType: 'Unknown or Mismatched',
      riskFlag: true,
      details: `File extension (.${ext}) does not match actual file format. Possible masquerading.`
    };
  } catch (error) {
    return {
      isValid: true,
      extension: '',
      actualType: null,
      riskFlag: false,
      details: `Could not validate signature: ${error}`
    };
  }
}

/**
 * String Analysis Module
 * Scans file for suspicious keywords, returns indicators only if multiple signals exist
 * 
 * @param buffer - File buffer to analyze
 * @returns Object containing suspicious indicators and summary
 */
export function analyzeStrings(buffer: Buffer): {
  suspiciousIndicators: { category: string; keywords: string[]; severity: string }[];
  indicatorCount: number;
  totalSeverityScore: number;
  summary: string;
  riskFlag: boolean;
} {
  const suspiciousIndicators: { category: string; keywords: string[]; severity: string }[] = [];
  let totalSeverityScore = 0;
  
  // Extract string content from buffer
  const bufferStr = buffer.toString('utf8', 0, Math.min(100000, buffer.length));
  
  // Scan each category
  for (const [category, keywords] of Object.entries(SuspiciousKeywords)) {
    const foundKeywords = keywords
      .filter(kw => bufferStr.includes(kw.pattern) || buffer.includes(Buffer.from(kw.pattern)))
      .map(kw => kw.pattern);
    
    if (foundKeywords.length > 0) {
      const severity = keywords
        .filter(kw => bufferStr.includes(kw.pattern) || buffer.includes(Buffer.from(kw.pattern)))
        .map(kw => kw.severity)[0] || 'medium';
      
      suspiciousIndicators.push({
        category: category.replace(/([A-Z])/g, ' $1').trim(),
        keywords: foundKeywords,
        severity
      });
      
      // Score: high=3, medium=2, low=1
      const severityScore = severity === 'high' ? 3 : severity === 'medium' ? 2 : 1;
      totalSeverityScore += foundKeywords.length * severityScore;
    }
  }
  
  const indicatorCount = suspiciousIndicators.reduce((sum, ind) => sum + ind.keywords.length, 0);
  
  // Only raise risk flag if multiple indicators from different categories or high severity
  const riskFlag = indicatorCount >= 2 || totalSeverityScore >= 4;
  
  let summary = '';
  if (indicatorCount === 0) {
    summary = 'No suspicious keywords detected';
  } else if (riskFlag) {
    summary = `Found ${indicatorCount} suspicious keywords from ${suspiciousIndicators.length} categories (risk indicator)`;
  } else {
    summary = `Found ${indicatorCount} suspicious keyword(s) - insufficient indicators for risk classification`;
  }
  
  return {
    suspiciousIndicators,
    indicatorCount,
    totalSeverityScore,
    summary,
    riskFlag
  };
}

/**
 * Safe File Heuristics Module
 * Automatically classifies common office/media documents as SAFE based on multiple signals
 * 
 * Criteria for SAFE classification:
 * - File is a known office/media format
 * - VirusTotal detections = 0
 * - Entropy < 6.8 (normal for office documents)
 * - No YARA signature matches
 * 
 * @param filename - Name of the file
 * @param entropy - Calculated file entropy
 * @param vtDetections - Number of VirusTotal detections
 * @param yaraMatches - Array of YARA signature matches
 * @returns Object with heuristic result and confidence
 */
export function applySafeFileHeuristic(
  filename: string,
  entropy: number,
  vtDetections: number = 0,
  yaraMatches: string[] = []
): {
  isSafe: boolean;
  confidence: number;
  reasons: string[];
  flags: string[];
} {
  const reasons: string[] = [];
  const flags: string[] = [];
  let confidence = 0;
  
  // Define common safe formats
  const safeDocumentExtensions = /\.(pptx?|docx?|xlsx?|pdf|txt|odt|ods|odp|rtf|csv|jpg|jpeg|png|gif|bmp|webp|zip|rar|7z)$/i;
  
  const isSafeFormat = safeDocumentExtensions.test(filename);
  
  if (!isSafeFormat) {
    return {
      isSafe: false,
      confidence: 0,
      reasons: ['File is not a known safe document or media format'],
      flags: []
    };
  }
  
  // Check VirusTotal detections
  if (vtDetections === 0) {
    reasons.push('No VirusTotal detections (0 malicious engines)');
    confidence += 0.35;
  } else if (vtDetections > 0) {
    flags.push(`VirusTotal: ${vtDetections} engine(s) flagged as malicious`);
    return {
      isSafe: false,
      confidence: 0,
      reasons: [`File detected as malicious by ${vtDetections} VirusTotal engine(s)`],
      flags: []
    };
  }
  
  // Check entropy threshold (6.8 is threshold for normal office documents)
  if (entropy < 6.8) {
    reasons.push(`Low entropy (${entropy.toFixed(2)}) - typical for office documents`);
    confidence += 0.35;
  } else if (entropy < 7.0) {
    flags.push(`Moderate entropy (${entropy.toFixed(2)}) - slightly elevated`);
  } else {
    flags.push(`High entropy (${entropy.toFixed(2)}) - unusual for office documents`);
    return {
      isSafe: false,
      confidence: 0,
      reasons: [`High entropy (${entropy.toFixed(2)}) - indicates possible encryption or compression`],
      flags: []
    };
  }
  
  // Check YARA matches
  if (yaraMatches.length === 0) {
    reasons.push('No YARA signature matches');
    confidence += 0.30;
  } else {
    const highConfidenceSigs = yaraMatches.filter(sig => 
      !sig.includes('base64') && 
      !sig.includes('PE_Header') &&
      !sig.includes('Suspicious')
    );
    
    if (highConfidenceSigs.length > 0) {
      flags.push(`YARA matches found: ${yaraMatches.join(', ')}`);
      return {
        isSafe: false,
        confidence: 0,
        reasons: [`YARA signatures detected: ${yaraMatches.join(', ')}`],
        flags: []
      };
    } else {
      reasons.push(`Generic YARA matches: ${yaraMatches.join(', ')} (low risk)`);
      confidence += 0.20;
    }
  }
  
  // Final determination
  const isSafe = confidence >= 0.80;
  
  return {
    isSafe,
    confidence: Math.round(confidence * 100),
    reasons,
    flags
  };
}

/**
 * Probability Calibration Function
 * Adjusts raw ML predictions to be more reliable and prevent overconfidence
 * Uses Platt scaling concepts to normalize probabilities
 * 
 * @param rawProbability - Raw probability from ML model (0-1)
 * @param safeFileBoost - Whether file passed safe heuristics
 * @param indicatorCount - Number of suspicious indicators found
 * @returns Calibrated probability (0-1)
 */
export function calibrateProbability(
  rawProbability: number,
  safeFileBoost: boolean = false,
  indicatorCount: number = 0
): number {
  // Clamp input
  let calibrated = Math.min(Math.max(rawProbability, 0), 1);
  
  // Apply safe file boost (reduces confidence if file appears safe)
  if (safeFileBoost) {
    calibrated = calibrated * 0.6;
  }
  
  // Indicator-based adjustment
  // Low indicators = reduce confidence in malware classification
  if (indicatorCount === 0 && calibrated > 0.4) {
    calibrated = Math.max(0.2, calibrated * 0.7);
  } else if (indicatorCount === 1 && calibrated > 0.5) {
    calibrated = Math.max(0.35, calibrated * 0.8);
  } else if (indicatorCount >= 3 && calibrated < 0.5) {
    // Multiple indicators suggest higher risk
    calibrated = Math.min(0.7, calibrated * 1.2);
  }
  
  // Prevent extreme overconfidence
  if (calibrated > 0.95) {
    calibrated = 0.95;
  } else if (calibrated < 0.05) {
    calibrated = 0.05;
  }
  
  return calibrated;
}

/**
 * Generate detailed explanation for classification
 * Provides human-readable reasoning for the threat score
 * 
 * @param classification - Classification result (Safe/Suspicious/Malware/etc)
 * @param score - Threat score (0-100)
 * @param reasons - List of reason strings
 * @returns Formatted explanation string
 */
export function generateClassificationExplanation(
  classification: string,
  score: number,
  reasons: string[]
): string {
  const lines = [
    `Classification: ${classification}`,
    `Threat Score: ${score}/100`,
    'Reasons:'
  ];
  
  reasons.forEach(reason => {
    lines.push(`  • ${reason}`);
  });
  
  return lines.join('\n');
}
