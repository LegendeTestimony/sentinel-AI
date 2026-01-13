/**
 * Calculate Shannon entropy of file content
 * High entropy (close to 8) suggests encryption or compression
 * Low entropy suggests text or structured data
 */
export function calculateEntropy(buffer) {
    if (buffer.length === 0)
        return 0;
    // Count byte frequencies
    const freq = {};
    for (const byte of buffer) {
        freq[byte] = (freq[byte] || 0) + 1;
    }
    // Calculate Shannon entropy
    let entropy = 0;
    const len = buffer.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        if (p > 0) {
            entropy -= p * Math.log2(p);
        }
    }
    return entropy; // Returns value between 0 and 8
}
/**
 * Analyze entropy and provide interpretation
 */
export function analyzeEntropy(entropy) {
    if (entropy >= 7.5) {
        return {
            score: entropy,
            interpretation: 'Very high entropy - likely encrypted, compressed, or obfuscated',
            suspicious: true,
        };
    }
    else if (entropy >= 6.5) {
        return {
            score: entropy,
            interpretation: 'High entropy - possible compression or binary data',
            suspicious: false,
        };
    }
    else if (entropy >= 4.5) {
        return {
            score: entropy,
            interpretation: 'Medium entropy - mixed content or structured data',
            suspicious: false,
        };
    }
    else {
        return {
            score: entropy,
            interpretation: 'Low entropy - likely text or simple structured data',
            suspicious: false,
        };
    }
}
