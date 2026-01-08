import type { FileStructure } from '../types/index.js';

/**
 * Extract printable strings from binary data
 */
function extractStrings(buffer: Buffer, minLength = 4): string[] {
  const strings: string[] = [];
  let current = '';

  for (const byte of buffer) {
    // Printable ASCII range
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        strings.push(current);
      }
      current = '';
    }
  }

  if (current.length >= minLength) {
    strings.push(current);
  }

  return strings;
}

/**
 * Detect suspicious API calls or system interactions
 */
function detectSuspiciousAPIs(content: string): string[] {
  const suspiciousPatterns = [
    // Windows APIs
    'CreateRemoteThread',
    'VirtualAllocEx',
    'WriteProcessMemory',
    'LoadLibrary',
    'GetProcAddress',
    'ShellExecute',
    'WinExec',
    'CreateProcess',

    // PowerShell
    'Invoke-Expression',
    'iex',
    'DownloadString',
    'DownloadFile',
    'Net.WebClient',
    'Start-Process',
    '-EncodedCommand',
    '-enc',
    'bypass',

    // Linux/macOS
    '/bin/sh',
    '/bin/bash',
    'chmod +x',
    'curl',
    'wget',
    'nc -',

    // General suspicious
    'eval(',
    'exec(',
    'system(',
    'base64',
    'FromBase64String',
    'ToBase64String',
  ];

  const found: string[] = [];
  const lowerContent = content.toLowerCase();

  for (const pattern of suspiciousPatterns) {
    if (lowerContent.includes(pattern.toLowerCase())) {
      found.push(pattern);
    }
  }

  return [...new Set(found)]; // Remove duplicates
}

/**
 * Parse file structure and extract key information
 */
export function parseStructure(
  filename: string,
  buffer: Buffer
): FileStructure {
  // Get preview of file content (first 1KB or full file if smaller)
  const previewLength = Math.min(1024, buffer.length);
  const previewBuffer = buffer.slice(0, previewLength);

  // Try to decode as text
  let preview = '';
  try {
    preview = previewBuffer.toString('utf-8');
    // If it contains too many non-printable characters, show hex instead
    const nonPrintable = preview.split('').filter(c => c.charCodeAt(0) < 32 && c !== '\n' && c !== '\r' && c !== '\t').length;
    if (nonPrintable > preview.length * 0.3) {
      preview = `[Binary data - ${buffer.length} bytes]\nHex dump: ${previewBuffer.toString('hex').slice(0, 200)}...`;
    }
  } catch {
    preview = `[Binary data - ${buffer.length} bytes]\nHex dump: ${previewBuffer.toString('hex').slice(0, 200)}...`;
  }

  // Extract strings from entire buffer
  const strings = extractStrings(buffer);
  const fullContent = strings.join(' ');

  // Detect suspicious APIs
  const apis = detectSuspiciousAPIs(fullContent);

  // Detect sections (for PE files, this would be more sophisticated)
  const sections: string[] = [];
  if (strings.some(s => s.includes('.text') || s.includes('.data') || s.includes('.rdata'))) {
    sections.push('PE sections detected');
  }

  return {
    preview,
    sections: sections.length > 0 ? sections : undefined,
    apis: apis.length > 0 ? apis : undefined,
  };
}
