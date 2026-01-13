/**
 * Unified File Type Identification System
 * Multi-layer approach: magic bytes → container parsing → structure validation
 */
import { detectMagicBytes, getFileExtension } from './magic-bytes.js';
import { parseISOBMFF } from './isobmff-parser.js';
/**
 * Identify file type using multi-layer analysis
 */
export function identifyFile(filename, buffer) {
    const claimedExtension = getFileExtension(filename);
    // Initialize result
    const result = {
        identifiedType: 'unknown',
        mimeType: 'application/octet-stream',
        category: 'unknown',
        confidence: 0,
        confidenceBreakdown: {
            magicBytes: 0,
            containerParsing: 0,
            extensionMatch: 0
        },
        magicByteMatches: [],
        claimedExtension,
        extensionMismatch: false,
        mismatchSeverity: 'none',
        humanDescription: '',
        securityNotes: []
    };
    // Layer 1: Magic byte detection
    const magicMatches = detectMagicBytes(buffer);
    result.magicByteMatches = magicMatches;
    if (magicMatches.length > 0) {
        const topMatch = magicMatches[0];
        result.confidenceBreakdown.magicBytes = topMatch.confidence;
        // Layer 2: Container parsing (if applicable)
        if (topMatch.fileType === 'isobmff') {
            // Parse ISOBMFF container (HEIC, HEIF, AVIF, MP4, MOV)
            const isobmff = parseISOBMFF(buffer);
            result.containerInfo = isobmff;
            if (isobmff.valid && isobmff.fileType) {
                result.identifiedType = isobmff.fileType.type;
                result.mimeType = isobmff.fileType.mime;
                result.category = isobmff.fileType.category;
                result.confidenceBreakdown.containerParsing = isobmff.confidence;
                // High confidence for successfully parsed containers
                result.confidence = Math.min((result.confidenceBreakdown.magicBytes * 0.3 + isobmff.confidence * 0.7), 100);
            }
            else {
                // Failed to parse container
                result.identifiedType = 'unknown_isobmff';
                result.mimeType = 'application/octet-stream';
                result.category = 'unknown';
                result.confidence = topMatch.confidence * 0.5; // Reduce confidence
                result.securityNotes.push('ISOBMFF signature detected but container parsing failed');
            }
        }
        else if (topMatch.fileType === 'riff_container') {
            // Check for WebP
            if (buffer.length >= 12) {
                const riffType = buffer.slice(8, 12).toString('ascii');
                if (riffType === 'WEBP') {
                    result.identifiedType = 'webp';
                    result.mimeType = 'image/webp';
                    result.category = 'image';
                    result.confidenceBreakdown.containerParsing = 85;
                    result.confidence = 90;
                }
                else if (riffType === 'WAVE') {
                    result.identifiedType = 'wav';
                    result.mimeType = 'audio/wav';
                    result.category = 'audio';
                    result.confidenceBreakdown.containerParsing = 85;
                    result.confidence = 90;
                }
                else if (riffType === 'AVI ') {
                    result.identifiedType = 'avi';
                    result.mimeType = 'video/x-msvideo';
                    result.category = 'video';
                    result.confidenceBreakdown.containerParsing = 85;
                    result.confidence = 90;
                }
                else {
                    result.identifiedType = 'riff_unknown';
                    result.confidence = 60;
                }
            }
        }
        else {
            // Direct magic byte match (non-container formats)
            result.identifiedType = topMatch.fileType;
            result.mimeType = topMatch.mimeType;
            result.category = topMatch.category;
            result.confidence = topMatch.confidence;
        }
    }
    else {
        // No magic bytes matched
        result.identifiedType = 'unknown';
        result.securityNotes.push('No recognized file signature found');
    }
    // Layer 3: Extension correlation
    const extensionMatch = checkExtensionMatch(claimedExtension, result.identifiedType);
    result.extensionMismatch = !extensionMatch;
    if (extensionMatch) {
        result.confidenceBreakdown.extensionMatch = 10;
        result.confidence = Math.min(result.confidence + 5, 100);
        result.mismatchSeverity = 'none';
    }
    else {
        result.mismatchSeverity = calculateMismatchSeverity(claimedExtension, result.identifiedType, result.category);
        if (result.mismatchSeverity === 'critical') {
            result.securityNotes.push(`CRITICAL: File claims to be .${claimedExtension} but content is ${result.identifiedType}`);
        }
        else if (result.mismatchSeverity === 'suspicious') {
            result.securityNotes.push(`SUSPICIOUS: Extension .${claimedExtension} doesn't match detected type ${result.identifiedType}`);
        }
    }
    // Generate human description
    result.humanDescription = generateHumanDescription(result);
    return result;
}
/**
 * Check if extension matches detected type
 */
function checkExtensionMatch(extension, detectedType) {
    // Extension mapping
    const extensionMap = {
        'jpeg': ['jpg', 'jpeg', 'jpe', 'jfif'],
        'png': ['png'],
        'gif': ['gif'],
        'bmp': ['bmp', 'dib'],
        'tiff': ['tif', 'tiff'],
        'webp': ['webp'],
        'heic': ['heic', 'heif'],
        'heif': ['heic', 'heif'],
        'avif': ['avif'],
        'mp4': ['mp4', 'm4v'],
        'm4v': ['m4v', 'mp4'],
        'm4a': ['m4a'],
        'mov': ['mov', 'qt'],
        'pe': ['exe', 'dll', 'sys'],
        'elf': ['elf', ''],
        'macho': ['dylib', 'bundle', ''],
        'zip': ['zip', 'jar', 'apk', 'docx', 'xlsx', 'pptx'],
        'rar': ['rar'],
        '7z': ['7z'],
        'gzip': ['gz'],
        'pdf': ['pdf'],
        'mp3': ['mp3'],
        'flac': ['flac'],
        'script': ['sh', 'bash', 'zsh'],
        'html': ['html', 'htm'],
        'xml': ['xml'],
    };
    const validExtensions = extensionMap[detectedType] || [];
    return validExtensions.includes(extension);
}
/**
 * Calculate severity of extension mismatch
 */
function calculateMismatchSeverity(extension, detectedType, category) {
    // Executable masquerading as something else
    if (['pe', 'elf', 'macho'].includes(detectedType)) {
        if (!['exe', 'dll', 'com', 'app', 'dylib'].includes(extension)) {
            return 'critical'; // Executable disguised as non-executable
        }
    }
    // Script masquerading as document/image
    if (detectedType === 'script' || detectedType === 'html') {
        if (['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'].includes(extension)) {
            return 'critical'; // Script disguised as document
        }
    }
    // Different categories
    if (category === 'executable' && !['exe', 'dll', 'com', 'app'].includes(extension)) {
        return 'critical';
    }
    if (category === 'image' && !['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'heic', 'heif', 'avif'].includes(extension)) {
        return 'suspicious';
    }
    // Unknown type is just unknown, not suspicious
    if (detectedType === 'unknown') {
        return 'none';
    }
    // Minor mismatch (e.g., jpg vs jpeg)
    return 'minor';
}
/**
 * Generate human-readable description
 */
function generateHumanDescription(result) {
    const descriptions = {
        'heic': 'HEIC image file (High Efficiency Image Container)',
        'heif': 'HEIF image file (High Efficiency Image Format)',
        'avif': 'AVIF image file (AV1 Image File Format)',
        'jpeg': 'JPEG image file',
        'png': 'PNG image file',
        'gif': 'GIF animated image',
        'webp': 'WebP image file',
        'mp4': 'MP4 video file',
        'mov': 'QuickTime video file',
        'pdf': 'PDF document',
        'zip': 'ZIP archive',
        'pe': 'Windows executable',
        'elf': 'Linux/Unix executable',
        'unknown': 'Unknown file type (no recognized signature)',
    };
    return descriptions[result.identifiedType] || `${result.identifiedType} file`;
}
