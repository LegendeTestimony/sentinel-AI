/**
 * Magic Byte Detection with Offset Support
 * Comprehensive signature database for file type identification
 */

export interface MagicSignature {
  signature: string;          // Hex pattern (e.g., 'FFD8FF')
  offset: number;             // Byte offset (0 for most, 4 for HEIC, etc.)
  mask?: string;              // Optional mask for partial matches
  fileType: string;           // Detected type identifier
  mimeType: string;           // Canonical MIME type
  confidence: number;         // Base confidence (0-100)
  description: string;        // Human-readable description
  category: 'image' | 'video' | 'audio' | 'document' | 'archive' | 'executable' | 'script' | 'unknown';
}

export interface MagicDetectionResult extends MagicSignature {
  matchedAt: number;          // Actual offset where match was found
}

// Comprehensive magic byte database
const MAGIC_DATABASE: MagicSignature[] = [
  // IMAGES - Standard Formats
  { signature: 'FFD8FF', offset: 0, fileType: 'jpeg', mimeType: 'image/jpeg', confidence: 95, description: 'JPEG Image', category: 'image' },
  { signature: '89504E47', offset: 0, fileType: 'png', mimeType: 'image/png', confidence: 95, description: 'PNG Image', category: 'image' },
  { signature: '474946383761', offset: 0, fileType: 'gif', mimeType: 'image/gif', confidence: 95, description: 'GIF87a Image', category: 'image' },
  { signature: '474946383961', offset: 0, fileType: 'gif', mimeType: 'image/gif', confidence: 95, description: 'GIF89a Image', category: 'image' },
  { signature: '424D', offset: 0, fileType: 'bmp', mimeType: 'image/bmp', confidence: 90, description: 'BMP Image', category: 'image' },

  // IMAGES - TIFF (two variants)
  { signature: '49492A00', offset: 0, fileType: 'tiff', mimeType: 'image/tiff', confidence: 95, description: 'TIFF (Little Endian)', category: 'image' },
  { signature: '4D4D002A', offset: 0, fileType: 'tiff', mimeType: 'image/tiff', confidence: 95, description: 'TIFF (Big Endian)', category: 'image' },

  // IMAGES - WebP (RIFF container)
  { signature: '52494646', offset: 0, fileType: 'riff_container', mimeType: 'application/octet-stream', confidence: 60, description: 'RIFF Container (WebP/WAV/AVI)', category: 'unknown' },

  // IMAGES/VIDEO - ISOBMFF containers (HEIC, HEIF, AVIF, MP4, MOV)
  // Critical: ftyp signature is at offset 4, not 0!
  { signature: '66747970', offset: 4, fileType: 'isobmff', mimeType: 'application/octet-stream', confidence: 70, description: 'ISO Base Media Container (requires brand check)', category: 'unknown' },

  // EXECUTABLES
  { signature: '4D5A', offset: 0, fileType: 'pe', mimeType: 'application/x-msdownload', confidence: 95, description: 'PE Executable (EXE/DLL)', category: 'executable' },
  { signature: '7F454C46', offset: 0, fileType: 'elf', mimeType: 'application/x-executable', confidence: 95, description: 'ELF Executable', category: 'executable' },
  { signature: 'CAFEBABE', offset: 0, fileType: 'macho', mimeType: 'application/x-mach-binary', confidence: 95, description: 'Mach-O Binary (32-bit)', category: 'executable' },
  { signature: 'CFFAEDFE', offset: 0, fileType: 'macho', mimeType: 'application/x-mach-binary', confidence: 95, description: 'Mach-O Binary (64-bit)', category: 'executable' },

  // ARCHIVES
  { signature: '504B0304', offset: 0, fileType: 'zip', mimeType: 'application/zip', confidence: 90, description: 'ZIP Archive', category: 'archive' },
  { signature: '504B0506', offset: 0, fileType: 'zip', mimeType: 'application/zip', confidence: 90, description: 'ZIP Archive (empty)', category: 'archive' },
  { signature: '526172211A07', offset: 0, fileType: 'rar', mimeType: 'application/x-rar-compressed', confidence: 95, description: 'RAR Archive v4+', category: 'archive' },
  { signature: '526172211A0700', offset: 0, fileType: 'rar', mimeType: 'application/x-rar-compressed', confidence: 95, description: 'RAR Archive v5+', category: 'archive' },
  { signature: '377ABCAF271C', offset: 0, fileType: '7z', mimeType: 'application/x-7z-compressed', confidence: 95, description: '7-Zip Archive', category: 'archive' },
  { signature: '1F8B', offset: 0, fileType: 'gzip', mimeType: 'application/gzip', confidence: 95, description: 'GZIP Archive', category: 'archive' },
  { signature: '425A68', offset: 0, fileType: 'bzip2', mimeType: 'application/x-bzip2', confidence: 95, description: 'BZIP2 Archive', category: 'archive' },

  // DOCUMENTS
  { signature: '25504446', offset: 0, fileType: 'pdf', mimeType: 'application/pdf', confidence: 95, description: 'PDF Document', category: 'document' },
  { signature: 'D0CF11E0A1B11AE1', offset: 0, fileType: 'ole', mimeType: 'application/x-ole-storage', confidence: 90, description: 'OLE Document (DOC/XLS/PPT)', category: 'document' },

  // AUDIO
  { signature: '494433', offset: 0, fileType: 'mp3', mimeType: 'audio/mpeg', confidence: 90, description: 'MP3 with ID3v2 Tag', category: 'audio' },
  { signature: 'FFFB', offset: 0, fileType: 'mp3', mimeType: 'audio/mpeg', confidence: 70, description: 'MP3 Frame Sync', category: 'audio' },
  { signature: '664C6143', offset: 0, fileType: 'flac', mimeType: 'audio/flac', confidence: 95, description: 'FLAC Audio', category: 'audio' },

  // SCRIPTS
  { signature: '23212F', offset: 0, fileType: 'script', mimeType: 'text/plain', confidence: 80, description: 'Shell Script (#!)', category: 'script' },
  { signature: '3C3F786D6C', offset: 0, fileType: 'xml', mimeType: 'application/xml', confidence: 85, description: 'XML Document', category: 'document' },
  { signature: '3C68746D6C', offset: 0, fileType: 'html', mimeType: 'text/html', confidence: 85, description: 'HTML Document', category: 'document' },
];

/**
 * Detect file type using magic byte signatures with offset support
 */
export function detectMagicBytes(buffer: Buffer): MagicDetectionResult[] {
  const results: MagicDetectionResult[] = [];

  for (const sig of MAGIC_DATABASE) {
    const sigBytes = Buffer.from(sig.signature, 'hex');

    // Check if buffer is long enough for this signature
    if (buffer.length < sig.offset + sigBytes.length) {
      continue;
    }

    // Extract bytes at the specified offset
    const targetBytes = buffer.slice(sig.offset, sig.offset + sigBytes.length);

    // Compare with optional mask support
    if (sig.mask) {
      const maskBytes = Buffer.from(sig.mask, 'hex');
      const match = targetBytes.every((byte, i) =>
        (byte & maskBytes[i]) === (sigBytes[i] & maskBytes[i])
      );
      if (match) {
        results.push({ ...sig, matchedAt: sig.offset });
      }
    } else {
      // Direct comparison
      if (targetBytes.equals(sigBytes)) {
        results.push({ ...sig, matchedAt: sig.offset });
      }
    }
  }

  // Sort by confidence (highest first)
  return results.sort((a, b) => b.confidence - a.confidence);
}

/**
 * Get file extension from filename
 */
export function getFileExtension(filename: string): string {
  const parts = filename.toLowerCase().split('.');
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

/**
 * Check if extension suggests executable content
 */
export function isExecutableExtension(filename: string): boolean {
  const ext = getFileExtension(filename);
  const executableExts = ['exe', 'dll', 'com', 'bat', 'cmd', 'ps1', 'sh', 'bash', 'run', 'app', 'dmg', 'pkg', 'deb', 'rpm'];
  return executableExts.includes(ext);
}
