/**
 * Magic numbers (file signatures) for common file types
 * Format: first few bytes of the file in hex
 */
const MAGIC_NUMBERS = {
    // Images
    jpg: ['FFD8FF'],
    jpeg: ['FFD8FF'],
    png: ['89504E47'],
    gif: ['474946383761', '474946383961'], // GIF87a, GIF89a
    bmp: ['424D'],
    ico: ['00000100'],
    // Documents
    pdf: ['25504446'],
    zip: ['504B0304', '504B0506', '504B0708'],
    rar: ['526172211A07'],
    '7z': ['377ABCAF271C'],
    // Executables
    exe: ['4D5A'],
    dll: ['4D5A'],
    // Archives
    tar: ['7573746172'], // "ustar" at offset 257
    gz: ['1F8B'],
    // Office
    docx: ['504B0304'], // ZIP-based
    xlsx: ['504B0304'], // ZIP-based
    pptx: ['504B0304'], // ZIP-based
    // Media
    mp3: ['494433', 'FFFB'],
    mp4: ['66747970'],
    avi: ['52494646'],
    // Scripts/Code (no magic numbers, but we check anyway)
    js: [],
    ts: [],
    py: [],
    sh: [],
    ps1: [],
};
/**
 * Extract file extension from filename
 */
function getExtension(filename) {
    const parts = filename.split('.');
    return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}
/**
 * Get hex representation of first N bytes
 */
function getFileHeader(buffer, bytes = 8) {
    const headerBytes = buffer.slice(0, bytes);
    return headerBytes.toString('hex').toUpperCase();
}
/**
 * Detect file type from magic number
 */
function detectFromMagicNumber(header) {
    for (const [type, signatures] of Object.entries(MAGIC_NUMBERS)) {
        for (const sig of signatures) {
            if (header.startsWith(sig.toUpperCase())) {
                return type;
            }
        }
    }
    return 'unknown';
}
/**
 * Validate file header matches claimed extension
 */
export function validateHeader(filename, buffer) {
    const claimedType = getExtension(filename);
    const header = getFileHeader(buffer);
    const actualType = detectFromMagicNumber(header);
    // Special handling for text-based files (no magic numbers)
    const textBasedExtensions = ['txt', 'js', 'ts', 'py', 'sh', 'ps1', 'json', 'xml', 'html', 'css', 'md'];
    const isTextBased = textBasedExtensions.includes(claimedType);
    let match = false;
    let suspicious = false;
    if (isTextBased && actualType === 'unknown') {
        // Text files won't have magic numbers, this is expected
        match = true;
        suspicious = false;
    }
    else if (actualType === 'unknown') {
        // Unknown type - could be suspicious
        match = false;
        suspicious = true;
    }
    else if (claimedType === actualType) {
        // Perfect match
        match = true;
        suspicious = false;
    }
    else if (MAGIC_NUMBERS[claimedType]?.length === 0) {
        // Claimed type has no magic number, can't validate
        match = false;
        suspicious = false;
    }
    else {
        // Mismatch - suspicious!
        match = false;
        suspicious = true;
    }
    // Check for double extensions (common attack vector)
    const extensionCount = (filename.match(/\./g) || []).length;
    if (extensionCount > 1) {
        const parts = filename.split('.');
        const hasExecutableExtension = ['exe', 'dll', 'bat', 'cmd', 'ps1', 'sh'].some(ext => parts.includes(ext));
        if (hasExecutableExtension) {
            suspicious = true;
        }
    }
    return {
        claimedType: claimedType || 'none',
        actualType,
        match,
        suspicious,
    };
}
