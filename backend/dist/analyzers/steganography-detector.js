/**
 * Steganography Detection Engine
 * Detects hidden data in image and media files
 */
import * as zlib from 'zlib';
/**
 * Detect steganography in files
 */
export function detectSteganography(buffer, fileType) {
    const techniques = [];
    // Collect extracted data for Gemini analysis
    const extractedData = {
        textMessages: [],
        rawDataSamples: [],
        totalHiddenBytes: 0,
        dataLocations: []
    };
    // JPEG steganography detection
    if (fileType === 'jpeg') {
        // Check for data after EOI marker
        const appendedData = detectJPEGAppendedData(buffer);
        if (appendedData.found) {
            // Try to extract the hidden content
            const hiddenContent = buffer.slice(appendedData.offset, Math.min(appendedData.offset + appendedData.size, buffer.length));
            const textAttempt = tryExtractText(hiddenContent);
            techniques.push({
                name: 'JPEG Appended Data',
                confidence: 85,
                description: 'Data found after JPEG End-Of-Image (EOI) marker',
                evidence: [
                    `${appendedData.size} bytes appended after EOI marker at offset ${appendedData.offset}`,
                    `First 32 bytes (hex): ${hiddenContent.slice(0, 32).toString('hex')}`,
                    ...(textAttempt ? [`Extracted text: "${textAttempt}"`] : [])
                ]
            });
            extractedData.totalHiddenBytes += appendedData.size;
            extractedData.dataLocations.push(`After JPEG EOI marker at offset ${appendedData.offset}`);
            extractedData.rawDataSamples.push(hiddenContent.slice(0, 128).toString('hex'));
            if (textAttempt) {
                extractedData.textMessages.push(textAttempt);
            }
        }
        // Chi-square analysis for LSB steganography
        const chiSquare = performChiSquareJPEG(buffer);
        if (chiSquare.suspicious) {
            techniques.push({
                name: 'JPEG LSB Anomaly (Chi-Square)',
                confidence: chiSquare.confidence,
                description: 'Statistical anomaly detected in DCT coefficients',
                evidence: chiSquare.evidence
            });
            extractedData.dataLocations.push('LSB modifications detected in image data');
        }
    }
    // PNG steganography detection
    if (fileType === 'png') {
        // Debug: List all PNG chunks found
        const chunkInfo = listPNGChunks(buffer);
        console.log('   📦 PNG Chunks found:', chunkInfo.map(c => `${c.type}(${c.length})`).join(', '));
        // Check for embedded text messages first
        const textMessages = extractPNGTextChunks(buffer);
        console.log('   📝 Text chunks extracted:', textMessages.length);
        if (textMessages.length > 0) {
            techniques.push({
                name: 'PNG Text Chunks',
                confidence: 85,
                description: 'PNG contains embedded text metadata with hidden message',
                evidence: [
                    `Found ${textMessages.length} text chunk(s):`,
                    ...textMessages.map(msg => `  "${msg}"`)
                ]
            });
            // Add to extracted data - parse out actual message content
            textMessages.forEach(msg => {
                // Format is "keyword: message"
                const colonIndex = msg.indexOf(':');
                if (colonIndex !== -1) {
                    const message = msg.substring(colonIndex + 1).trim();
                    extractedData.textMessages.push(message);
                }
                else {
                    extractedData.textMessages.push(msg);
                }
            });
            extractedData.dataLocations.push('PNG tEXt/iTXt/zTXt metadata chunks');
        }
        // Try LSB extraction from pixel data (common steganography method)
        const lsbMessage = extractLSBFromPNG(buffer);
        if (lsbMessage) {
            techniques.push({
                name: 'PNG LSB Steganography',
                confidence: 80,
                description: 'Hidden message found in least significant bits of pixel data',
                evidence: [
                    `Extracted message: "${lsbMessage}"`
                ]
            });
            extractedData.textMessages.push(lsbMessage);
            extractedData.dataLocations.push('LSB of PNG pixel data');
        }
        // Check for suspicious ancillary chunks
        const suspiciousChunks = detectSuspiciousPNGChunks(buffer);
        if (suspiciousChunks.found) {
            techniques.push({
                name: 'PNG Suspicious Chunks',
                confidence: 70,
                description: 'Unusual ancillary chunks detected',
                evidence: suspiciousChunks.evidence
            });
        }
        // Check for data after IEND
        const appendedData = detectPNGAppendedData(buffer);
        if (appendedData.found) {
            const hiddenContent = buffer.slice(appendedData.offset, Math.min(appendedData.offset + appendedData.size, buffer.length));
            const textAttempt = tryExtractText(hiddenContent);
            techniques.push({
                name: 'PNG Appended Data',
                confidence: 90,
                description: 'Data found after PNG IEND chunk',
                evidence: [
                    `${appendedData.size} bytes appended after IEND`,
                    `Offset: ${appendedData.offset}`,
                    `First 64 bytes (hex): ${hiddenContent.slice(0, 64).toString('hex')}`,
                    ...(textAttempt ? [`Extracted text: "${textAttempt}"`] : [])
                ]
            });
            extractedData.totalHiddenBytes += appendedData.size;
            extractedData.dataLocations.push(`After PNG IEND at offset ${appendedData.offset}`);
            extractedData.rawDataSamples.push(hiddenContent.slice(0, 128).toString('hex'));
            if (textAttempt) {
                extractedData.textMessages.push(textAttempt);
            }
        }
    }
    // Generic: Large hidden data in any file
    const hiddenData = detectLargeHiddenData(buffer, fileType);
    if (hiddenData.found) {
        techniques.push({
            name: 'Large Hidden Data Section',
            confidence: 60,
            description: 'Unusually large region with anomalous characteristics',
            evidence: hiddenData.evidence
        });
        extractedData.dataLocations.push('High entropy blocks throughout file');
    }
    // Calculate overall confidence
    const overallConfidence = techniques.length > 0
        ? Math.max(...techniques.map(t => t.confidence))
        : 0;
    const hasExtractedData = extractedData.textMessages.length > 0 ||
        extractedData.rawDataSamples.length > 0 ||
        extractedData.totalHiddenBytes > 0;
    return {
        detected: techniques.length > 0,
        confidence: overallConfidence,
        techniques,
        analysis: generateSteganographyReport(techniques, extractedData),
        ...(hasExtractedData ? { extractedData } : {})
    };
}
/**
 * Try to extract readable text from binary data
 */
function tryExtractText(buffer) {
    // Try UTF-8 first
    let text = buffer.toString('utf8');
    // Check if it's printable ASCII/UTF-8
    const printableChars = text.split('').filter(c => {
        const code = c.charCodeAt(0);
        return (code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9;
    });
    // If more than 70% printable, consider it text
    if (printableChars.length / text.length > 0.7 && printableChars.length > 3) {
        // Clean up the text
        text = printableChars.join('').trim();
        if (text.length > 0 && text.length < 10000) {
            return text;
        }
    }
    // Try Latin1 as fallback
    text = buffer.toString('latin1');
    const latin1Printable = text.split('').filter(c => {
        const code = c.charCodeAt(0);
        return (code >= 32 && code <= 126) || (code >= 160 && code <= 255) || code === 10 || code === 13;
    });
    if (latin1Printable.length / text.length > 0.7 && latin1Printable.length > 3) {
        text = latin1Printable.join('').trim();
        if (text.length > 0 && text.length < 10000) {
            return text;
        }
    }
    return null;
}
/**
 * List all PNG chunks in the file (for debugging)
 */
function listPNGChunks(buffer) {
    const chunks = [];
    try {
        let offset = 8; // Skip PNG signature
        while (offset < buffer.length - 12) {
            const length = buffer.readUInt32BE(offset);
            if (length < 0 || length > 50000000)
                break;
            const type = buffer.slice(offset + 4, offset + 8).toString('ascii');
            chunks.push({ type, length, offset });
            offset += 12 + length;
            if (type === 'IEND')
                break;
        }
    }
    catch (err) {
        // Ignore errors
    }
    return chunks;
}
/**
 * Extract LSB-encoded message from PNG pixel data
 * Many steganography tools hide messages in the least significant bits of pixels
 */
function extractLSBFromPNG(buffer) {
    try {
        // Find IDAT chunks (compressed pixel data)
        const chunks = listPNGChunks(buffer);
        const idatChunks = chunks.filter(c => c.type === 'IDAT');
        if (idatChunks.length === 0)
            return null;
        // Combine all IDAT data
        let compressedData = Buffer.alloc(0);
        for (const chunk of idatChunks) {
            const chunkData = buffer.slice(chunk.offset + 8, chunk.offset + 8 + chunk.length);
            compressedData = Buffer.concat([compressedData, chunkData]);
        }
        // Decompress using zlib
        let pixelData;
        try {
            pixelData = zlib.inflateSync(compressedData);
        }
        catch {
            return null; // Decompression failed
        }
        console.log(`   🔍 Decompressed ${pixelData.length} bytes of pixel data`);
        // Try multiple LSB extraction methods
        const methods = [
            { name: 'LSB-MSB', extractor: () => extractLSB_MSBFirst(pixelData) },
            { name: 'LSB-LSB', extractor: () => extractLSB_LSBFirst(pixelData) },
            { name: 'RGB-LSB', extractor: () => extractRGB_LSB(pixelData) },
            { name: 'Skip-Filter', extractor: () => extractLSB_SkipFilter(pixelData) },
            { name: 'Sequential-RGB', extractor: () => extractSequentialRGB(pixelData) },
            { name: 'ManyTools-Style', extractor: () => extractManyToolsStyle(pixelData) }
        ];
        for (const method of methods) {
            const result = method.extractor();
            if (result && result.length >= 3) {
                console.log(`   🔍 ${method.name} extraction found: "${result.substring(0, 100)}${result.length > 100 ? '...' : ''}"`);
                return result;
            }
        }
        return null;
    }
    catch (err) {
        console.error('LSB extraction error:', err);
        return null;
    }
}
/**
 * Extract LSB with MSB-first bit ordering (most common)
 */
function extractLSB_MSBFirst(pixelData) {
    const maxBytes = Math.min(pixelData.length, 20000);
    let bits = '';
    for (let i = 0; i < maxBytes; i++) {
        bits += (pixelData[i] & 1).toString();
    }
    return bitsToText(bits);
}
/**
 * Extract LSB with LSB-first bit ordering
 */
function extractLSB_LSBFirst(pixelData) {
    const maxBytes = Math.min(pixelData.length, 20000);
    let message = '';
    for (let charIndex = 0; charIndex < maxBytes / 8; charIndex++) {
        let byte = 0;
        for (let bit = 0; bit < 8; bit++) {
            const pixelIndex = charIndex * 8 + bit;
            if (pixelIndex >= pixelData.length)
                break;
            byte |= (pixelData[pixelIndex] & 1) << bit; // LSB first
        }
        if (byte === 0)
            break;
        if (byte >= 32 && byte <= 126) {
            message += String.fromCharCode(byte);
        }
        else if (message.length > 3) {
            break;
        }
        else {
            message = '';
        }
    }
    return validateMessage(message);
}
/**
 * Extract LSB from RGB channels only (skip alpha and filter bytes)
 */
function extractRGB_LSB(pixelData) {
    const maxBytes = Math.min(pixelData.length, 30000);
    let bits = '';
    // Skip filter byte at start of each row (every width*4+1 bytes typically)
    // Just sample every RGB byte, skip every 4th (alpha)
    for (let i = 0; i < maxBytes; i++) {
        // Skip if this might be a filter byte or alpha
        if (i % 4 !== 3) { // Skip alpha channel (every 4th byte in RGBA)
            bits += (pixelData[i] & 1).toString();
        }
    }
    return bitsToText(bits);
}
/**
 * Extract LSB skipping PNG filter bytes (first byte of each scanline)
 */
function extractLSB_SkipFilter(pixelData) {
    // PNG pixel data has a filter byte at the start of each row
    // Common image widths, try to detect and skip filter bytes
    const maxBytes = Math.min(pixelData.length, 20000);
    let bits = '';
    // Simple approach: just skip bytes that look like filter values (0-4)
    let skipNext = true; // Skip first byte (filter)
    let byteCount = 0;
    for (let i = 0; i < maxBytes; i++) {
        if (skipNext) {
            skipNext = false;
            continue;
        }
        bits += (pixelData[i] & 1).toString();
        byteCount++;
        // Assume ~1000-2000 pixel width, check periodically for filter bytes
        // This is a heuristic
    }
    return bitsToText(bits);
}
/**
 * Convert bit string to text (MSB first)
 */
function bitsToText(bits) {
    let message = '';
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        const byte = parseInt(bits.substring(i, i + 8), 2);
        if (byte === 0)
            break; // Null terminator
        if (byte >= 32 && byte <= 126) {
            message += String.fromCharCode(byte);
        }
        else if (message.length > 3) {
            break;
        }
        else {
            message = '';
        }
    }
    return validateMessage(message);
}
/**
 * Validate extracted message looks like real text
 */
function validateMessage(message) {
    if (!message || message.length < 3 || message.length > 10000) {
        return null;
    }
    // Check if it looks like real text
    const hasSpaces = message.includes(' ');
    const isAlphanumeric = /^[a-zA-Z0-9\s.,!?'"()\-:;@#$%&*+=\[\]{}|\\/<>~`]+$/.test(message);
    if (hasSpaces || (isAlphanumeric && message.length >= 3)) {
        return message;
    }
    return null;
}
/**
 * Extract using sequential RGB channels (R, then G, then B across all pixels)
 * Some tools embed 1 bit per color channel sequentially
 */
function extractSequentialRGB(pixelData) {
    // PNG pixel data format: [filter][R][G][B][A]... per row
    // Try extracting LSB from RGB channels only, assuming RGBA format
    const maxPixels = Math.min(pixelData.length / 4, 10000);
    let bits = '';
    // Skip filter bytes - they appear at the start of each row
    // For simplicity, try reading without row awareness first
    for (let pixel = 0; pixel < maxPixels; pixel++) {
        const baseIdx = pixel * 4 + 1; // +1 to potentially skip filter byte alignment
        if (baseIdx + 2 >= pixelData.length)
            break;
        // Extract LSB from R, G, B (skip A)
        bits += (pixelData[baseIdx] & 1).toString(); // R
        bits += (pixelData[baseIdx + 1] & 1).toString(); // G
        bits += (pixelData[baseIdx + 2] & 1).toString(); // B
    }
    return bitsToText(bits);
}
/**
 * ManyTools-style extraction
 * Many online tools use simple sequential LSB in pixel order
 * Try different starting offsets and bit patterns
 */
function extractManyToolsStyle(pixelData) {
    // Try different starting offsets (0-10) to account for headers/padding
    for (let startOffset = 0; startOffset <= 10; startOffset++) {
        // Try standard LSB from offset
        let bits = '';
        const maxBytes = Math.min(pixelData.length - startOffset, 20000);
        for (let i = startOffset; i < startOffset + maxBytes; i++) {
            bits += (pixelData[i] & 1).toString();
        }
        const result = bitsToText(bits);
        if (result && result.length >= 5) {
            return result;
        }
        // Try reading 2 LSBs per byte
        bits = '';
        for (let i = startOffset; i < startOffset + maxBytes; i++) {
            bits += ((pixelData[i] >> 1) & 1).toString();
            bits += (pixelData[i] & 1).toString();
        }
        const result2 = bitsToText(bits);
        if (result2 && result2.length >= 5) {
            return result2;
        }
    }
    // Try looking for a length header (common pattern: first 32 bits = message length)
    if (pixelData.length > 40) {
        let lengthBits = '';
        for (let i = 0; i < 32; i++) {
            lengthBits += (pixelData[i] & 1).toString();
        }
        const messageLength = parseInt(lengthBits, 2);
        // Sanity check the length
        if (messageLength > 0 && messageLength < 100000 && messageLength * 8 + 32 < pixelData.length) {
            let messageBits = '';
            for (let i = 32; i < 32 + messageLength * 8; i++) {
                if (i >= pixelData.length)
                    break;
                messageBits += (pixelData[i] & 1).toString();
            }
            const result = bitsToText(messageBits);
            if (result && result.length >= 3) {
                console.log(`   🔍 Found message with length header: ${messageLength} chars`);
                return result;
            }
        }
    }
    return null;
}
/**
 * Detect data appended after JPEG EOI marker
 */
function detectJPEGAppendedData(buffer) {
    // JPEG EOI marker: FF D9
    let eoiOffset = -1;
    for (let i = 0; i < buffer.length - 1; i++) {
        if (buffer[i] === 0xFF && buffer[i + 1] === 0xD9) {
            eoiOffset = i + 2; // After the EOI marker
        }
    }
    if (eoiOffset > 0 && eoiOffset < buffer.length) {
        const remainingSize = buffer.length - eoiOffset;
        // Ignore trailing null bytes (common padding)
        if (remainingSize > 16) {
            return { found: true, size: remainingSize, offset: eoiOffset };
        }
    }
    return { found: false, size: 0, offset: 0 };
}
/**
 * Detect data appended after PNG IEND chunk
 */
function detectPNGAppendedData(buffer) {
    // PNG IEND: 00 00 00 00 49 45 4E 44 AE 42 60 82
    const iendSignature = Buffer.from([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);
    for (let i = 0; i < buffer.length - iendSignature.length; i++) {
        if (buffer.slice(i, i + iendSignature.length).equals(iendSignature)) {
            const iendEnd = i + iendSignature.length;
            const remainingSize = buffer.length - iendEnd;
            if (remainingSize > 16) {
                return { found: true, size: remainingSize, offset: iendEnd };
            }
        }
    }
    return { found: false, size: 0, offset: 0 };
}
/**
 * Chi-square analysis for JPEG LSB steganography
 */
function performChiSquareJPEG(buffer) {
    // Simplified chi-square analysis
    // In production, this would analyze DCT coefficients
    // For now, we check for unusual byte pair distributions
    const pairs = {};
    let totalPairs = 0;
    // Sample every 8th byte pair (to avoid sampling entire file)
    for (let i = 0; i < buffer.length - 1; i += 8) {
        const pair = `${buffer[i]},${buffer[i + 1]}`;
        pairs[pair] = (pairs[pair] || 0) + 1;
        totalPairs++;
    }
    // Calculate chi-square statistic
    const expected = totalPairs / Object.keys(pairs).length;
    let chiSquare = 0;
    for (const count of Object.values(pairs)) {
        chiSquare += Math.pow(count - expected, 2) / expected;
    }
    // Normalize by degrees of freedom
    const degreesOfFreedom = Object.keys(pairs).length - 1;
    const normalizedChiSquare = chiSquare / degreesOfFreedom;
    // Threshold for suspicion (empirically determined)
    if (normalizedChiSquare > 1.5 && normalizedChiSquare < 2.5) {
        return {
            suspicious: true,
            confidence: 65,
            evidence: [
                `Chi-square statistic: ${normalizedChiSquare.toFixed(2)}`,
                'Unusual byte pair distribution may indicate LSB modification'
            ]
        };
    }
    return { suspicious: false, confidence: 0, evidence: [] };
}
/**
 * Extract text from PNG tEXt chunks (for steganography message extraction)
 */
function extractPNGTextChunks(buffer) {
    const messages = [];
    try {
        // PNG signature is 8 bytes, chunks start after that
        let offset = 8;
        // PNG chunk structure: [length(4)][type(4)][data(length)][crc(4)]
        while (offset < buffer.length - 12) {
            try {
                const length = buffer.readUInt32BE(offset);
                // Validate length
                if (length < 0 || length > 10000000 || offset + length + 12 > buffer.length) {
                    offset++;
                    continue;
                }
                const type = buffer.slice(offset + 4, offset + 8).toString('ascii');
                // Check for text chunks
                if (type === 'tEXt' || type === 'iTXt' || type === 'zTXt') {
                    const dataStart = offset + 8;
                    const chunkData = buffer.slice(dataStart, dataStart + length);
                    // tEXt format: keyword\0text
                    const nullIndex = chunkData.indexOf(0);
                    if (nullIndex !== -1 && nullIndex < chunkData.length - 1) {
                        const keyword = chunkData.slice(0, nullIndex).toString('utf8');
                        let text = chunkData.slice(nullIndex + 1).toString('utf8');
                        // Try latin1 if utf8 fails
                        if (text.includes('\ufffd')) {
                            text = chunkData.slice(nullIndex + 1).toString('latin1');
                        }
                        // Only include if text is readable
                        const isPrintable = text.split('').every(c => {
                            const code = c.charCodeAt(0);
                            return (code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9;
                        });
                        if (text.length > 0 && text.length < 10000 && isPrintable) {
                            messages.push(`${keyword}: ${text}`);
                        }
                    }
                }
                // Move to next chunk (length + 4 bytes type + 4 bytes CRC)
                offset += length + 12;
                // Safety check: if IEND found, stop
                if (type === 'IEND')
                    break;
            }
            catch (err) {
                offset++;
            }
        }
    }
    catch (err) {
        console.error('Error extracting PNG text chunks:', err);
    }
    return messages;
}
/**
 * Detect suspicious PNG chunks
 */
function detectSuspiciousPNGChunks(buffer) {
    const evidence = [];
    const suspiciousChunks = ['tEXt', 'zTXt', 'iTXt', 'sPLT', 'iCCP'];
    // First, extract any text messages
    const textMessages = extractPNGTextChunks(buffer);
    if (textMessages.length > 0) {
        evidence.push(`Found ${textMessages.length} text chunk(s):`);
        textMessages.forEach(msg => evidence.push(`  - ${msg}`));
    }
    // PNG chunk structure: [length(4)][type(4)][data(length)][crc(4)]
    for (let i = 8; i < buffer.length - 12; i++) {
        const length = buffer.readUInt32BE(i);
        const type = buffer.slice(i + 4, i + 8).toString('ascii');
        if (suspiciousChunks.includes(type)) {
            if (length > 10000) {
                evidence.push(`Large ${type} chunk found: ${length} bytes`);
            }
        }
        // Move to next chunk
        i += length + 12;
        if (i >= buffer.length)
            break;
    }
    return { found: evidence.length > 0, evidence };
}
/**
 * Detect large hidden data sections
 */
function detectLargeHiddenData(buffer, fileType) {
    // Look for large sections of high-entropy data in unexpected locations
    // This is a simplified heuristic
    if (buffer.length < 100000) {
        return { found: false, evidence: [] };
    }
    // Sample entropy in 4KB blocks
    const blockSize = 4096;
    const highEntropyBlocks = [];
    for (let offset = 0; offset < buffer.length; offset += blockSize) {
        const block = buffer.slice(offset, Math.min(offset + blockSize, buffer.length));
        const entropy = calculateBlockEntropy(block);
        if (entropy > 7.8) {
            highEntropyBlocks.push(offset);
        }
    }
    // If we have many consecutive high-entropy blocks in a media file
    if (highEntropyBlocks.length > 5 && ['jpeg', 'png', 'bmp'].includes(fileType)) {
        return {
            found: true,
            evidence: [
                `Found ${highEntropyBlocks.length} blocks with entropy > 7.8`,
                'May indicate encrypted or compressed hidden data'
            ]
        };
    }
    return { found: false, evidence: [] };
}
/**
 * Calculate Shannon entropy for a block
 */
function calculateBlockEntropy(block) {
    const freq = {};
    for (const byte of block) {
        freq[byte] = (freq[byte] || 0) + 1;
    }
    let entropy = 0;
    const len = block.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        if (p > 0) {
            entropy -= p * Math.log2(p);
        }
    }
    return entropy;
}
/**
 * Generate steganography report
 */
function generateSteganographyReport(techniques, extractedData) {
    if (techniques.length === 0) {
        return 'No steganography detected.';
    }
    let report = `Detected ${techniques.length} potential steganography technique(s):\n\n`;
    techniques.forEach((tech, i) => {
        report += `${i + 1}. ${tech.name} (${tech.confidence}% confidence)\n`;
        report += `   ${tech.description}\n`;
        tech.evidence.forEach(ev => {
            report += `   - ${ev}\n`;
        });
        report += '\n';
    });
    // Add extracted content summary
    if (extractedData && extractedData.textMessages.length > 0) {
        report += '\n=== EXTRACTED HIDDEN MESSAGES ===\n';
        extractedData.textMessages.forEach((msg, i) => {
            report += `Message ${i + 1}: "${msg}"\n`;
        });
    }
    if (extractedData && extractedData.totalHiddenBytes > 0) {
        report += `\nTotal hidden data: ${extractedData.totalHiddenBytes} bytes\n`;
        report += `Locations: ${extractedData.dataLocations.join(', ')}\n`;
    }
    return report;
}
