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
 * Detect suspicious API calls or system interactions with context awareness
 */
function detectSuspiciousAPIs(content: string, strings: string[]): string[] {
  const suspiciousPatterns = [
    // Windows APIs - require exact match in a string
    'CreateRemoteThread',
    'VirtualAllocEx',
    'WriteProcessMemory',
    'LoadLibrary',
    'GetProcAddress',
    'ShellExecute',
    'WinExec',
    'CreateProcess',

    // PowerShell - require longer context
    'Invoke-Expression',
    'DownloadString',
    'DownloadFile',
    'Net.WebClient',
    'Start-Process',
    '-EncodedCommand',
    'bypass -ExecutionPolicy',

    // Linux/macOS
    '/bin/sh',
    '/bin/bash',
    'chmod +x',

    // General suspicious - require function call context
    'eval(',
    'exec(',
    'system(',
    'FromBase64String',
    'ToBase64String',
  ];

  // Short patterns that need additional context to avoid false positives
  const contextualPatterns: { pattern: string; context: RegExp }[] = [
    // 'iex' must appear as standalone word or with PowerShell context
    { pattern: 'iex', context: /\b(iex|Invoke-Expression)\s+[\(\$\-]/ },
    // 'curl' or 'wget' must be in command context
    { pattern: 'curl', context: /\bcurl\s+-/ },
    { pattern: 'wget', context: /\bwget\s+-/ },
    // 'nc' must be netcat usage
    { pattern: 'nc', context: /\bnc\s+-[lep]/ },
    // base64 in decode context
    { pattern: 'base64', context: /base64\s+(-d|--decode)/ },
  ];

  const found: string[] = [];

  // Check standard patterns - look for them as complete strings within extracted strings
  for (const pattern of suspiciousPatterns) {
    // Must appear as a complete word/phrase in one of the extracted strings
    const regex = new RegExp(`\\b${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (strings.some(str => regex.test(str))) {
      found.push(pattern);
    }
  }

  // Check contextual patterns - require specific surrounding context
  for (const { pattern, context } of contextualPatterns) {
    if (strings.some(str => context.test(str))) {
      found.push(pattern);
    }
  }

  return [...new Set(found)]; // Remove duplicates
}

/**
 * Parse file structure and extract key information
 * @param filename - Original filename (legacy support)
 * @param buffer - File buffer
 * @param detectedType - Validated file type from file-identifier (preferred)
 */
export function parseStructure(
  filename: string,
  buffer: Buffer,
  detectedType?: string
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

  // Determine if file is media type (use validated type if available, fallback to extension)
  let isMediaFile = false;

  if (detectedType) {
    // Use validated file type (much more reliable)
    const mediaTypes = ['jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'heic', 'heif', 'avif',
                        'mp4', 'mov', 'avi', 'mkv', 'm4v', 'm4a',
                        'mp3', 'wav', 'flac', 'aac', 'ogg'];
    isMediaFile = mediaTypes.includes(detectedType);
  } else {
    // Fallback to extension-based detection (less reliable)
    isMediaFile = /\.(jpg|jpeg|png|gif|heic|webp|bmp|mp4|mov|avi|mkv|mp3|wav|flac|aac)$/i.test(filename);
  }

  let apis: string[] | undefined;

  if (!isMediaFile) {
    // Only scan for suspicious APIs in non-media files
    const strings = extractStrings(buffer);
    const fullContent = strings.join(' ');
    const detectedApis = detectSuspiciousAPIs(fullContent, strings);
    apis = detectedApis.length > 0 ? detectedApis : undefined;
  }

  // Detect sections (for PE files, this would be more sophisticated)
  // Only check for executable sections in non-media files
  let sections: string[] | undefined;
  if (!isMediaFile) {
    const strings = extractStrings(buffer);
    if (strings.some(s => s.includes('.text') || s.includes('.data') || s.includes('.rdata'))) {
      sections = ['PE sections detected'];
    }
  }

  return {
    preview,
    sections,
    apis,
  };
}
