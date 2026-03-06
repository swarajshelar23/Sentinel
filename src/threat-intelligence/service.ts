import axios from 'axios';

export interface ThreatReputation {
  malicious: boolean;
  score: number;
  family?: string;
  provider: string;
}

export class ThreatIntelligenceService {
  private static MOCK_MALICIOUS_HASHES = [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // Empty file hash (just for testing)
    '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'  // 'password' hash
  ];

  static async lookupHash(hash: string): Promise<ThreatReputation[]> {
    const results: ThreatReputation[] = [];

    // Mock Internal Feed
    if (this.MOCK_MALICIOUS_HASHES.includes(hash)) {
      results.push({
        malicious: true,
        score: 90,
        family: 'Generic.Malware.Internal',
        provider: 'Sentinel_Internal_Feed'
      });
    }

    // Mock External Feed 1
    results.push({
      malicious: hash.startsWith('a'),
      score: hash.startsWith('a') ? 85 : 0,
      family: hash.startsWith('a') ? 'Trojan.Win32.Generic' : undefined,
      provider: 'Global_Threat_Network'
    });

    return results;
  }

  static async lookupIp(ip: string): Promise<ThreatReputation | null> {
    // Mock IP lookup
    const maliciousIps = ['1.1.1.1', '8.8.8.8']; // Mock
    if (maliciousIps.includes(ip)) {
      return {
        malicious: true,
        score: 70,
        provider: 'IP_Reputation_Service'
      };
    }
    return null;
  }
}
