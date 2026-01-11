/**
 * Embedded Payload Hunter
 * Detects hidden executables, shellcode, and encrypted blobs
 */

export interface EmbeddedPayload {
  type: 'shellcode' | 'executable' | 'base64_encoded' | 'encrypted_blob' | 'script';
  offset: number;
  size: number;
  confidence: number;
  preview: string;
  analysis: string;
}

export interface PayloadAnalysis {
  foundPayloads: EmbeddedPayload[];
  overallRisk: number;
  summary: string;
}

/**
 * Hunt for embedded payloads in files
 */
export function huntPayloads(buffer: Buffer, fileType: string): PayloadAnalysis {
  const payloads: EmbeddedPayload[] = [];

  // 1. Detect shellcode patterns
  const shellcodeResults = detectShellcodePatterns(buffer);
  payloads.push(...shellcodeResults);

  // 2. Detect Base64 encoded blobs
  const base64Results = detectBase64Blobs(buffer);
  payloads.push(...base64Results);

  // 3. Detect embedded PE headers (if not a PE file)
  if (fileType !== 'pe') {
    const embeddedPE = findEmbeddedPE(buffer);
    payloads.push(...embeddedPE);
  }

  // 4. Detect high-entropy encrypted blobs in unexpected locations
  const encryptedBlobs = findSuspiciousEncryptedBlobs(buffer, fileType);
  payloads.push(...encryptedBlobs);

  // 5. Detect embedded scripts
  const scripts = detectEmbeddedScripts(buffer, fileType);
  payloads.push(...scripts);

  // Calculate overall risk
  const overallRisk = calculatePayloadRisk(payloads);

  return {
    foundPayloads: payloads,
    overallRisk,
    summary: generatePayloadSummary(payloads, overallRisk)
  };
}

/**
 * Detect shellcode patterns
 */
function detectShellcodePatterns(buffer: Buffer): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];

  // Common shellcode patterns
  const patterns = [
    // x86 NOP sled
    { pattern: Buffer.from([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]), name: 'NOP sled', confidence: 75 },
    // Common x86 shellcode prologue
    { pattern: Buffer.from([0xEB, 0x1E, 0x5E, 0x89, 0x76]), name: 'x86 shellcode prologue', confidence: 85 },
    // x64 shellcode patterns
    { pattern: Buffer.from([0x48, 0x31, 0xC0, 0x48, 0x31, 0xDB]), name: 'x64 shellcode pattern', confidence: 80 },
  ];

  for (const { pattern, name, confidence } of patterns) {
    let offset = 0;
    while ((offset = buffer.indexOf(pattern, offset)) !== -1) {
      payloads.push({
        type: 'shellcode',
        offset,
        size: pattern.length,
        confidence,
        preview: buffer.slice(offset, offset + 32).toString('hex'),
        analysis: `Detected ${name} at offset ${offset}`
      });
      offset += pattern.length;

      // Limit detections to avoid overwhelming results
      if (payloads.length >= 5) break;
    }
  }

  return payloads;
}

/**
 * Detect Base64 encoded blobs
 */
function detectBase64Blobs(buffer: Buffer): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];

  try {
    const text = buffer.toString('utf-8');
    // Look for base64 strings (at least 100 chars long)
    const base64Regex = /[A-Za-z0-9+\/]{100,}={0,2}/g;
    let match;

    while ((match = base64Regex.exec(text)) !== null) {
      const base64String = match[0];

      // Try to decode
      try {
        const decoded = Buffer.from(base64String, 'base64');

        // Check if decoded data looks suspicious
        if (decoded.length > 50) {
          const analysis = analyzeDecodedData(decoded);

          payloads.push({
            type: 'base64_encoded',
            offset: match.index,
            size: base64String.length,
            confidence: analysis.confidence,
            preview: base64String.substring(0, 50) + '...',
            analysis: `Base64 encoded data (${decoded.length} bytes decoded). ${analysis.description}`
          });
        }

        if (payloads.length >= 5) break;
      } catch {
        // Invalid base64, skip
      }
    }
  } catch {
    // Not UTF-8 text, skip base64 detection
  }

  return payloads;
}

/**
 * Analyze decoded base64 data
 */
function analyzeDecodedData(data: Buffer): { confidence: number; description: string } {
  // Check for PE header
  if (data.length > 2 && data[0] === 0x4D && data[1] === 0x5A) {
    return { confidence: 95, description: 'Contains PE executable' };
  }

  // Check for ELF header
  if (data.length > 4 && data[0] === 0x7F && data[1] === 0x45 && data[2] === 0x4C && data[3] === 0x46) {
    return { confidence: 95, description: 'Contains ELF executable' };
  }

  // Check for high entropy (encrypted/compressed)
  let entropy = 0;
  const freq: Record<number, number> = {};
  for (const byte of data) {
    freq[byte] = (freq[byte] || 0) + 1;
  }
  for (const count of Object.values(freq)) {
    const p = count / data.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }

  if (entropy > 7.5) {
    return { confidence: 70, description: 'High entropy (likely encrypted/compressed)' };
  }

  return { confidence: 50, description: 'Encoded data of unknown type' };
}

/**
 * Find embedded PE executables
 */
function findEmbeddedPE(buffer: Buffer): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];

  // Search for MZ header
  for (let i = 0; i < buffer.length - 64; i++) {
    if (buffer[i] === 0x4D && buffer[i + 1] === 0x5A) {
      // Found MZ, check for PE signature
      if (i + 0x3C + 4 < buffer.length) {
        const peOffset = buffer.readUInt32LE(i + 0x3C);

        if (i + peOffset + 4 < buffer.length) {
          const peSignature = buffer.slice(i + peOffset, i + peOffset + 4).toString('ascii');

          if (peSignature === 'PE\0\0') {
            payloads.push({
              type: 'executable',
              offset: i,
              size: Math.min(1024, buffer.length - i),
              confidence: 95,
              preview: buffer.slice(i, i + 64).toString('hex'),
              analysis: `Embedded PE executable found at offset ${i}`
            });

            // Limit detections
            if (payloads.length >= 3) break;
          }
        }
      }
    }
  }

  return payloads;
}

/**
 * Find suspicious encrypted blobs
 */
function findSuspiciousEncryptedBlobs(buffer: Buffer, fileType: string): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];

  // Only check non-compressed formats
  if (['jpeg', 'png', 'heic', 'avif', 'mp4', 'zip'].includes(fileType)) {
    return payloads; // These formats normally have high entropy
  }

  // Scan in 1KB blocks
  const blockSize = 1024;

  for (let offset = 0; offset < buffer.length; offset += blockSize) {
    const block = buffer.slice(offset, Math.min(offset + blockSize, buffer.length));

    // Calculate entropy
    let entropy = 0;
    const freq: Record<number, number> = {};

    for (const byte of block) {
      freq[byte] = (freq[byte] || 0) + 1;
    }

    for (const count of Object.values(freq)) {
      const p = count / block.length;
      if (p > 0) entropy -= p * Math.log2(p);
    }

    // Anomalous high entropy in non-compressed file
    if (entropy > 7.7 && block.length >= 512) {
      payloads.push({
        type: 'encrypted_blob',
        offset,
        size: block.length,
        confidence: 65,
        preview: block.slice(0, 32).toString('hex'),
        analysis: `High entropy region (${entropy.toFixed(2)}) in ${fileType} file suggests encrypted/compressed data`
      });

      // Limit detections
      if (payloads.length >= 3) break;
    }
  }

  return payloads;
}

/**
 * Detect embedded scripts
 */
function detectEmbeddedScripts(buffer: Buffer, fileType: string): EmbeddedPayload[] {
  const payloads: EmbeddedPayload[] = [];

  // Only scan if not already a script file
  if (['script', 'html', 'xml'].includes(fileType)) {
    return payloads;
  }

  try {
    const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 100000));

    // Look for script patterns
    const scriptPatterns = [
      { regex: /<script[^>]*>[\s\S]{50,}<\/script>/gi, name: 'HTML script tag', confidence: 85 },
      { regex: /eval\s*\([^)]{50,}\)/gi, name: 'JavaScript eval()', confidence: 90 },
      { regex: /powershell\s+-e(nc?)?\s+[A-Za-z0-9+\/=]{50,}/gi, name: 'PowerShell encoded command', confidence: 95 },
    ];

    for (const { regex, name, confidence } of scriptPatterns) {
      let match;
      while ((match = regex.exec(text)) !== null) {
        payloads.push({
          type: 'script',
          offset: match.index,
          size: match[0].length,
          confidence,
          preview: match[0].substring(0, 100),
          analysis: `Embedded ${name} detected in ${fileType} file`
        });

        if (payloads.length >= 5) break;
      }
    }
  } catch {
    // Not valid UTF-8, skip script detection
  }

  return payloads;
}

/**
 * Calculate overall payload risk
 */
function calculatePayloadRisk(payloads: EmbeddedPayload[]): number {
  if (payloads.length === 0) return 0;

  // Weight by confidence
  const totalConfidence = payloads.reduce((sum, p) => sum + p.confidence, 0);
  const avgConfidence = totalConfidence / payloads.length;

  // More payloads = higher risk
  const countFactor = Math.min(payloads.length / 3, 1);

  return Math.min(avgConfidence * (0.7 + countFactor * 0.3), 100);
}

/**
 * Generate payload summary
 */
function generatePayloadSummary(payloads: EmbeddedPayload[], risk: number): string {
  if (payloads.length === 0) {
    return 'No embedded payloads detected.';
  }

  const types = [...new Set(payloads.map(p => p.type))];

  return `Found ${payloads.length} embedded payload(s): ${types.join(', ')}. Overall risk: ${risk.toFixed(0)}/100`;
}
