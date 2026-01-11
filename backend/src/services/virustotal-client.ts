import axios from 'axios';
import crypto from 'crypto';

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';

export interface VirusTotalResult {
  checked: boolean;
  found: boolean;
  detections?: number;
  totalEngines?: number;
  scanDate?: string;
  permalink?: string;
  positives?: {
    [engine: string]: {
      detected: boolean;
      result: string;
    };
  };
  sha256?: string;
}

/**
 * Calculate SHA-256 hash of file buffer
 */
function calculateSHA256(buffer: Buffer): string {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Check file hash against VirusTotal database
 */
export async function checkFileHash(fileBuffer: Buffer): Promise<VirusTotalResult> {
  // If no API key, return unchecked result
  if (!VT_API_KEY) {
    console.log('⚠️  VirusTotal API key not configured, skipping check');
    return {
      checked: false,
      found: false,
    };
  }

  try {
    const sha256 = calculateSHA256(fileBuffer);
    console.log(`🔍 Checking VirusTotal for hash: ${sha256.substring(0, 16)}...`);

    // Query VirusTotal API v3 for file report
    const response = await axios.get(
      `${VT_BASE_URL}/files/${sha256}`,
      {
        headers: {
          'x-apikey': VT_API_KEY,
        },
        timeout: 5000, // 5 second timeout
      }
    );

    const data = response.data.data;
    const stats = data.attributes.last_analysis_stats;
    const results = data.attributes.last_analysis_results;

    // Count detections
    const detections = stats.malicious + stats.suspicious;
    const totalEngines = Object.keys(results).length;

    // Get top detections (engines that flagged it)
    const positives: { [engine: string]: { detected: boolean; result: string } } = {};
    Object.entries(results).forEach(([engine, result]: [string, any]) => {
      if (result.category === 'malicious' || result.category === 'suspicious') {
        positives[engine] = {
          detected: true,
          result: result.result || 'Malicious',
        };
      }
    });

    console.log(`   ✓ VirusTotal: ${detections}/${totalEngines} engines detected threats`);

    return {
      checked: true,
      found: true,
      detections,
      totalEngines,
      scanDate: data.attributes.last_analysis_date,
      permalink: `https://www.virustotal.com/gui/file/${sha256}`,
      positives,
      sha256,
    };
  } catch (error: any) {
    // File not found in VirusTotal database (404 is normal for new files)
    if (error.response?.status === 404) {
      console.log('   ℹ️  File not found in VirusTotal database (likely new/unique file)');
      return {
        checked: true,
        found: false,
        sha256: calculateSHA256(fileBuffer),
      };
    }

    // Rate limit or other API errors
    if (error.response?.status === 429) {
      console.log('   ⚠️  VirusTotal rate limit exceeded');
    } else {
      console.error('   ❌ VirusTotal API error:', error.message);
    }

    return {
      checked: false,
      found: false,
    };
  }
}

/**
 * Get top threat names from VirusTotal detections
 */
export function getTopThreats(vtResult: VirusTotalResult, limit = 5): string[] {
  if (!vtResult.positives) return [];

  return Object.entries(vtResult.positives)
    .slice(0, limit)
    .map(([engine, data]) => `${engine}: ${data.result}`);
}
