/**
 * Polyglot File Detector
 * Detects files that are valid as multiple file types simultaneously
 */
/**
 * Detect if file is a polyglot (valid as multiple formats)
 */
export function detectPolyglot(buffer) {
    const validFormats = [];
    // Check each format
    if (isValidPDF(buffer))
        validFormats.push('PDF');
    if (isValidZIP(buffer))
        validFormats.push('ZIP');
    if (isValidJPEG(buffer))
        validFormats.push('JPEG');
    if (isValidPNG(buffer))
        validFormats.push('PNG');
    if (isValidHTML(buffer))
        validFormats.push('HTML');
    if (isValidJavaScript(buffer))
        validFormats.push('JavaScript');
    if (isValidPE(buffer))
        validFormats.push('PE Executable');
    if (isValidScript(buffer))
        validFormats.push('Shell Script');
    const isPolyglot = validFormats.length > 1;
    if (!isPolyglot) {
        return {
            isPolyglot: false,
            validFormats,
            confidence: 0,
            securityRisk: 'low',
            description: 'File is not a polyglot.',
            dangerousCombinations: []
        };
    }
    // Assess risk based on combination
    const { risk, dangerousCombinations } = assessPolyglotRisk(validFormats);
    return {
        isPolyglot: true,
        validFormats,
        confidence: 95,
        securityRisk: risk,
        description: `File is valid as multiple formats: ${validFormats.join(', ')}. This is often used in sophisticated attacks to bypass security filters.`,
        dangerousCombinations
    };
}
/**
 * Assess security risk of polyglot combination
 */
function assessPolyglotRisk(formats) {
    const dangerousCombinations = [];
    // Critical combinations (executable + document/image)
    const criticalPairs = [
        ['PE Executable', 'JPEG'],
        ['PE Executable', 'PNG'],
        ['PE Executable', 'PDF'],
        ['JavaScript', 'PDF'],
        ['Shell Script', 'JPEG'],
        ['Shell Script', 'PNG']
    ];
    for (const [type1, type2] of criticalPairs) {
        if (formats.includes(type1) && formats.includes(type2)) {
            dangerousCombinations.push(`${type1} + ${type2}`);
            return { risk: 'critical', dangerousCombinations };
        }
    }
    // High risk combinations
    const highRiskPairs = [
        ['HTML', 'JPEG'],
        ['HTML', 'PNG'],
        ['ZIP', 'PE Executable'],
        ['PDF', 'HTML']
    ];
    for (const [type1, type2] of highRiskPairs) {
        if (formats.includes(type1) && formats.includes(type2)) {
            dangerousCombinations.push(`${type1} + ${type2}`);
            return { risk: 'high', dangerousCombinations };
        }
    }
    // Medium risk: any executable component
    if (formats.some(f => ['PE Executable', 'JavaScript', 'Shell Script'].includes(f))) {
        dangerousCombinations.push('Contains executable component');
        return { risk: 'medium', dangerousCombinations };
    }
    return { risk: 'low', dangerousCombinations };
}
/**
 * Check if buffer is valid PDF
 */
function isValidPDF(buffer) {
    if (buffer.length < 8)
        return false;
    const header = buffer.slice(0, 5).toString('ascii');
    return header === '%PDF-';
}
/**
 * Check if buffer is valid ZIP
 */
function isValidZIP(buffer) {
    if (buffer.length < 4)
        return false;
    return buffer[0] === 0x50 && buffer[1] === 0x4B &&
        (buffer[2] === 0x03 || buffer[2] === 0x05 || buffer[2] === 0x07) &&
        (buffer[3] === 0x04 || buffer[3] === 0x06 || buffer[3] === 0x08);
}
/**
 * Check if buffer is valid JPEG
 */
function isValidJPEG(buffer) {
    if (buffer.length < 3)
        return false;
    return buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
}
/**
 * Check if buffer is valid PNG
 */
function isValidPNG(buffer) {
    if (buffer.length < 8)
        return false;
    const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    return buffer.slice(0, 8).equals(pngSignature);
}
/**
 * Check if buffer contains valid HTML
 */
function isValidHTML(buffer) {
    try {
        const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 1024));
        const htmlPatterns = [
            /<html/i,
            /<head/i,
            /<body/i,
            /<!doctype\s+html/i,
            /<script/i
        ];
        return htmlPatterns.some(pattern => pattern.test(text));
    }
    catch {
        return false;
    }
}
/**
 * Check if buffer contains valid JavaScript
 */
function isValidJavaScript(buffer) {
    try {
        const text = buffer.toString('utf-8', 0, Math.min(buffer.length, 1024));
        const jsPatterns = [
            /function\s+\w+\s*\(/,
            /const\s+\w+\s*=/,
            /let\s+\w+\s*=/,
            /var\s+\w+\s*=/,
            /=>\s*{/,
            /console\.log\(/
        ];
        // Must have at least 2 patterns to be considered JS
        const matches = jsPatterns.filter(pattern => pattern.test(text)).length;
        return matches >= 2;
    }
    catch {
        return false;
    }
}
/**
 * Check if buffer is valid PE executable
 */
function isValidPE(buffer) {
    if (buffer.length < 64)
        return false;
    // Check MZ header
    if (buffer[0] !== 0x4D || buffer[1] !== 0x5A)
        return false;
    // Check PE signature location
    const peOffset = buffer.readUInt32LE(0x3C);
    if (peOffset + 4 > buffer.length)
        return false;
    // Check PE signature
    const peSignature = buffer.slice(peOffset, peOffset + 4).toString('ascii');
    return peSignature === 'PE\0\0';
}
/**
 * Check if buffer is valid shell script
 */
function isValidScript(buffer) {
    if (buffer.length < 3)
        return false;
    // Check for shebang
    if (buffer[0] === 0x23 && buffer[1] === 0x21) { // #!
        try {
            const firstLine = buffer.toString('utf-8', 0, Math.min(buffer.length, 128)).split('\n')[0];
            return /^#!.*\/(bash|sh|zsh|python|perl|ruby|node)/.test(firstLine);
        }
        catch {
            return false;
        }
    }
    return false;
}
