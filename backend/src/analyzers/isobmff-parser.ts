/**
 * ISO Base Media File Format (ISOBMFF) Container Parser
 * Handles HEIC, HEIF, AVIF, MP4, MOV and other ISOBMFF-based formats
 */

export interface FileTypeInfo {
  type: string;
  mime: string;
  category: 'image' | 'video' | 'audio' | 'unknown';
  description: string;
}

export interface ISOBMFFBox {
  size: number;
  type: string;
  offset: number;
}

export interface FtypBox {
  majorBrand: string;
  minorVersion: number;
  compatibleBrands: string[];
  size: number;
}

export interface ISOBMFFResult {
  valid: boolean;
  majorBrand?: string;
  compatibleBrands?: string[];
  fileType?: FileTypeInfo;
  boxes?: Array<{ type: string; size: number }>;
  confidence: number;
  error?: string;
}

// ISOBMFF brand database
const ISOBMFF_BRANDS: Record<string, FileTypeInfo> = {
  // HEIC/HEIF brands
  'heic': { type: 'heic', mime: 'image/heic', category: 'image', description: 'HEIC Image' },
  'heix': { type: 'heic', mime: 'image/heic', category: 'image', description: 'HEIC Image (extended)' },
  'hevc': { type: 'heic', mime: 'image/heic', category: 'image', description: 'HEVC Image' },
  'hevx': { type: 'heic', mime: 'image/heic', category: 'image', description: 'HEVC Image (extended)' },
  'heim': { type: 'heic', mime: 'image/heic-sequence', category: 'image', description: 'HEIC Image Sequence' },
  'heis': { type: 'heic', mime: 'image/heic-sequence', category: 'image', description: 'HEIC Image Sequence' },
  'mif1': { type: 'heif', mime: 'image/heif', category: 'image', description: 'HEIF Image' },
  'msf1': { type: 'heif', mime: 'image/heif-sequence', category: 'image', description: 'HEIF Sequence' },

  // AVIF brands
  'avif': { type: 'avif', mime: 'image/avif', category: 'image', description: 'AVIF Image' },
  'avis': { type: 'avif', mime: 'image/avif-sequence', category: 'image', description: 'AVIF Sequence' },
  'MA1A': { type: 'avif', mime: 'image/avif', category: 'image', description: 'AVIF (AV1)' },
  'MA1B': { type: 'avif', mime: 'image/avif', category: 'image', description: 'AVIF (AV1)' },

  // MP4/MOV brands
  'isom': { type: 'mp4', mime: 'video/mp4', category: 'video', description: 'ISO Base Media' },
  'iso2': { type: 'mp4', mime: 'video/mp4', category: 'video', description: 'ISO Base Media v2' },
  'mp41': { type: 'mp4', mime: 'video/mp4', category: 'video', description: 'MP4 v1' },
  'mp42': { type: 'mp4', mime: 'video/mp4', category: 'video', description: 'MP4 v2' },
  'M4V ': { type: 'm4v', mime: 'video/x-m4v', category: 'video', description: 'Apple M4V' },
  'M4A ': { type: 'm4a', mime: 'audio/mp4', category: 'audio', description: 'Apple M4A' },
  'qt  ': { type: 'mov', mime: 'video/quicktime', category: 'video', description: 'QuickTime' },
  'avc1': { type: 'mp4', mime: 'video/mp4', category: 'video', description: 'H.264/AVC' },
  'hvc1': { type: 'mp4', mime: 'video/mp4', category: 'video', description: 'H.265/HEVC' },
  'crx ': { type: 'cr3', mime: 'image/x-canon-cr3', category: 'image', description: 'Canon CR3 RAW' },
};

/**
 * Parse ISOBMFF container structure
 */
export function parseISOBMFF(buffer: Buffer): ISOBMFFResult {
  try {
    // Parse ftyp box (File Type Box - always first in valid ISOBMFF)
    const ftypBox = parseFtypBox(buffer);

    if (!ftypBox) {
      return {
        valid: false,
        error: 'No ftyp box found or invalid structure',
        confidence: 0
      };
    }

    // Determine file type from brands
    let fileType: FileTypeInfo | undefined;

    // Check major brand first
    if (ISOBMFF_BRANDS[ftypBox.majorBrand]) {
      fileType = ISOBMFF_BRANDS[ftypBox.majorBrand];
    }

    // If major brand not recognized, check compatible brands
    if (!fileType) {
      for (const brand of ftypBox.compatibleBrands) {
        if (ISOBMFF_BRANDS[brand]) {
          fileType = ISOBMFF_BRANDS[brand];
          break;
        }
      }
    }

    // Parse additional boxes for structural validation
    const boxes = parseTopLevelBoxes(buffer);
    const hasMetaBox = boxes.some(b => b.type === 'meta');
    const hasMoovBox = boxes.some(b => b.type === 'moov');
    const hasMdatBox = boxes.some(b => b.type === 'mdat');

    // Calculate confidence based on structure
    let confidence = 50; // Base confidence for ftyp detection
    if (ftypBox) confidence += 20;
    if (fileType) confidence += 15; // Recognized brand
    if (hasMetaBox || hasMoovBox) confidence += 10; // Has metadata
    if (hasMdatBox) confidence += 5; // Has media data

    return {
      valid: true,
      majorBrand: ftypBox.majorBrand,
      compatibleBrands: ftypBox.compatibleBrands,
      fileType: fileType || {
        type: 'unknown_isobmff',
        mime: 'application/octet-stream',
        category: 'unknown',
        description: `Unknown ISOBMFF (brand: ${ftypBox.majorBrand})`
      },
      boxes: boxes.map(b => ({ type: b.type, size: b.size })),
      confidence: Math.min(confidence, 100)
    };

  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Parse error',
      confidence: 0
    };
  }
}

/**
 * Parse the ftyp (File Type) box
 */
function parseFtypBox(buffer: Buffer): FtypBox | null {
  // ftyp box must be at the beginning (after optional offset)
  // Structure:
  // [0-3]: size (uint32 BE)
  // [4-7]: 'ftyp'
  // [8-11]: major brand (4 chars)
  // [12-15]: minor version (uint32 BE)
  // [16+]: compatible brands (4 chars each)

  if (buffer.length < 16) return null;

  // Read size and type
  const size = buffer.readUInt32BE(0);
  const type = buffer.slice(4, 8).toString('ascii');

  if (type !== 'ftyp') {
    return null;
  }

  // Validate size
  if (size < 16 || size > buffer.length) {
    return null;
  }

  const majorBrand = buffer.slice(8, 12).toString('ascii');
  const minorVersion = buffer.readUInt32BE(12);

  // Extract compatible brands
  const compatibleBrands: string[] = [];
  for (let i = 16; i < size && i + 4 <= buffer.length; i += 4) {
    const brand = buffer.slice(i, i + 4).toString('ascii');
    compatibleBrands.push(brand);
  }

  return {
    majorBrand,
    minorVersion,
    compatibleBrands,
    size
  };
}

/**
 * Parse top-level boxes for structural validation
 */
function parseTopLevelBoxes(buffer: Buffer): ISOBMFFBox[] {
  const boxes: ISOBMFFBox[] = [];
  let offset = 0;

  while (offset < buffer.length - 8) {
    try {
      const size = buffer.readUInt32BE(offset);
      const type = buffer.slice(offset + 4, offset + 8).toString('ascii');

      // Validate size
      if (size < 8 || size > buffer.length - offset) {
        break;
      }

      boxes.push({ size, type, offset });

      // Move to next box
      offset += size;

      // Limit to first 10 boxes to avoid processing huge files
      if (boxes.length >= 10) break;

    } catch {
      break;
    }
  }

  return boxes;
}

/**
 * Check if buffer appears to be an ISOBMFF container
 */
export function isLikelyISOBMFF(buffer: Buffer): boolean {
  if (buffer.length < 12) return false;

  // Check for ftyp at offset 4
  const ftypSig = buffer.slice(4, 8).toString('ascii');
  return ftypSig === 'ftyp';
}
