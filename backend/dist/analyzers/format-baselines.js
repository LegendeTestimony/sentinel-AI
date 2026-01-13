/**
 * Format-Specific Baseline Expectations
 * Defines expected characteristics for each file format to reduce false positives
 */
// Comprehensive format baseline database
export const FORMAT_BASELINES = {
    // === IMAGES - COMPRESSED (HIGH ENTROPY IS NORMAL) ===
    jpeg: {
        type: 'jpeg',
        entropy: {
            min: 7.0,
            max: 7.99,
            typical: 7.5,
            explanation: 'JPEG uses DCT compression which produces high entropy. Values of 7-8 are completely normal and expected.'
        },
        structure: {
            hasHeader: true,
            hasTrailer: true,
            knownSections: ['SOI', 'APP0', 'DQT', 'SOF', 'DHT', 'SOS', 'EOI'],
            maxHeaderSize: 1024
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'high' // JPEG is commonly used for steganography
        }
    },
    png: {
        type: 'png',
        entropy: {
            min: 6.5,
            max: 7.95,
            typical: 7.2,
            explanation: 'PNG uses DEFLATE compression resulting in high entropy. Values of 6.5-8 are normal.'
        },
        structure: {
            hasHeader: true,
            hasTrailer: true,
            knownSections: ['IHDR', 'PLTE', 'IDAT', 'IEND'],
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'high'
        }
    },
    heic: {
        type: 'heic',
        entropy: {
            min: 7.2,
            max: 7.99,
            typical: 7.7,
            explanation: 'HEIC uses HEVC (H.265) compression which is extremely efficient and produces very high entropy. Values of 7.2-8 are completely normal and expected for this modern format.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['ftyp', 'meta', 'mdat', 'moov'],
            maxHeaderSize: 512
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'medium'
        }
    },
    heif: {
        type: 'heif',
        entropy: {
            min: 7.2,
            max: 7.99,
            typical: 7.7,
            explanation: 'HEIF uses advanced compression producing very high entropy. Values of 7.2-8 are completely normal.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['ftyp', 'meta', 'mdat'],
            maxHeaderSize: 512
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'medium'
        }
    },
    avif: {
        type: 'avif',
        entropy: {
            min: 7.3,
            max: 7.99,
            typical: 7.8,
            explanation: 'AVIF uses AV1 compression which is state-of-the-art and produces extremely high entropy. Values of 7.3-8 are completely normal and expected.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['ftyp', 'meta', 'mdat'],
            maxHeaderSize: 512
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'medium'
        }
    },
    webp: {
        type: 'webp',
        entropy: {
            min: 7.0,
            max: 7.95,
            typical: 7.4,
            explanation: 'WebP uses VP8/VP8L compression producing high entropy. Values of 7-8 are normal.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['RIFF', 'WEBP', 'VP8', 'VP8L', 'VP8X'],
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'medium'
        }
    },
    gif: {
        type: 'gif',
        entropy: {
            min: 5.0,
            max: 7.5,
            typical: 6.0,
            explanation: 'GIF uses LZW compression which is less efficient than modern formats. Entropy of 5-7.5 is normal.'
        },
        structure: {
            hasHeader: true,
            hasTrailer: true,
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'medium'
        }
    },
    bmp: {
        type: 'bmp',
        entropy: {
            min: 3.0,
            max: 7.0,
            typical: 5.0,
            explanation: 'BMP is typically uncompressed or lightly compressed. Entropy of 3-7 is normal, higher if compressed.'
        },
        structure: {
            hasHeader: true,
            maxHeaderSize: 128
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'low'
        }
    },
    // === VIDEO ===
    mp4: {
        type: 'mp4',
        entropy: {
            min: 7.0,
            max: 7.99,
            typical: 7.6,
            explanation: 'MP4 uses H.264/H.265 compression producing high entropy. Values of 7-8 are normal.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['ftyp', 'moov', 'mdat'],
            maxHeaderSize: 1024
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: true, // Can contain metadata scripts
            commonAttackVector: false,
            steganographyRisk: 'low'
        }
    },
    mov: {
        type: 'mov',
        entropy: {
            min: 7.0,
            max: 7.99,
            typical: 7.5,
            explanation: 'QuickTime MOV uses compression producing high entropy. Values of 7-8 are normal.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['ftyp', 'moov', 'mdat'],
            maxHeaderSize: 1024
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: true,
            commonAttackVector: false,
            steganographyRisk: 'low'
        }
    },
    // === AUDIO ===
    mp3: {
        type: 'mp3',
        entropy: {
            min: 6.8,
            max: 7.95,
            typical: 7.3,
            explanation: 'MP3 uses lossy compression producing high entropy. Values of 6.8-8 are normal.'
        },
        structure: {
            hasHeader: true,
            maxHeaderSize: 512
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'low'
        }
    },
    flac: {
        type: 'flac',
        entropy: {
            min: 6.5,
            max: 7.8,
            typical: 7.0,
            explanation: 'FLAC uses lossless compression. Entropy of 6.5-7.8 is normal.'
        },
        structure: {
            hasHeader: true,
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: false,
            canContainScripts: false,
            commonAttackVector: false,
            steganographyRisk: 'low'
        }
    },
    // === ARCHIVES ===
    zip: {
        type: 'zip',
        entropy: {
            min: 7.0,
            max: 7.99,
            typical: 7.5,
            explanation: 'ZIP compression results in high entropy. Values of 7-8 are normal for compressed archives.'
        },
        structure: {
            hasHeader: true,
            hasTrailer: true,
            knownSections: ['Local Header', 'Central Directory', 'EOCD'],
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: true,
            canContainScripts: true,
            commonAttackVector: true, // ZIP bombs, nested archives
            steganographyRisk: 'low'
        }
    },
    rar: {
        type: 'rar',
        entropy: {
            min: 7.0,
            max: 7.99,
            typical: 7.6,
            explanation: 'RAR compression produces high entropy. Values of 7-8 are normal.'
        },
        structure: {
            hasHeader: true,
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: true,
            canContainScripts: true,
            commonAttackVector: true,
            steganographyRisk: 'low'
        }
    },
    // === EXECUTABLES ===
    pe: {
        type: 'pe',
        entropy: {
            min: 4.0,
            max: 7.8,
            typical: 5.5,
            explanation: 'PE executables vary widely. Unpacked: 4-6, Packed/encrypted: 7+. High entropy MAY indicate packing/encryption.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['DOS Header', 'PE Header', '.text', '.data', '.rdata', '.rsrc'],
            maxHeaderSize: 2048
        },
        riskProfile: {
            canContainExecutable: true,
            canContainScripts: true,
            commonAttackVector: true,
            steganographyRisk: 'low'
        }
    },
    elf: {
        type: 'elf',
        entropy: {
            min: 4.0,
            max: 7.8,
            typical: 5.0,
            explanation: 'ELF executables vary. Unpacked: 4-6, Packed/encrypted: 7+. High entropy MAY indicate packing.'
        },
        structure: {
            hasHeader: true,
            knownSections: ['.text', '.data', '.bss', '.rodata'],
            maxHeaderSize: 1024
        },
        riskProfile: {
            canContainExecutable: true,
            canContainScripts: true,
            commonAttackVector: true,
            steganographyRisk: 'low'
        }
    },
    // === DOCUMENTS ===
    pdf: {
        type: 'pdf',
        entropy: {
            min: 3.0,
            max: 7.8,
            typical: 5.0,
            explanation: 'PDF entropy varies with content. Text-heavy: 3-5, Image-heavy/compressed: 6-7.8.'
        },
        structure: {
            hasHeader: true,
            hasTrailer: true,
            knownSections: ['%PDF', 'obj', 'endobj', 'xref', '%%EOF'],
            maxHeaderSize: 256
        },
        riskProfile: {
            canContainExecutable: true, // Can embed executables
            canContainScripts: true, // JavaScript
            commonAttackVector: true, // Common malware vector
            steganographyRisk: 'medium'
        }
    },
};
/**
 * Get baseline expectations for a file type
 */
export function getBaseline(fileType) {
    return FORMAT_BASELINES[fileType] || null;
}
/**
 * Analyze entropy against format baseline
 */
export function analyzeEntropyAgainstBaseline(fileType, entropy) {
    const baseline = getBaseline(fileType);
    if (!baseline) {
        return {
            hasBaseline: false,
            status: 'unknown',
            deviation: 0,
            explanation: `No baseline available for file type "${fileType}". Unable to determine if entropy is normal.`,
            suspicious: false
        };
    }
    const { min, max, typical, explanation } = baseline.entropy;
    // Check if within expected range
    if (entropy >= min && entropy <= max) {
        const deviation = Math.abs(entropy - typical);
        return {
            hasBaseline: true,
            status: 'normal',
            deviation,
            explanation: `Entropy ${entropy.toFixed(2)} is within expected range (${min.toFixed(1)}-${max.toFixed(1)}) for ${fileType}. ${explanation}`,
            suspicious: false
        };
    }
    // Above expected maximum
    if (entropy > max) {
        return {
            hasBaseline: true,
            status: 'high',
            deviation: entropy - max,
            explanation: `Entropy ${entropy.toFixed(2)} is ABOVE expected maximum (${max.toFixed(1)}) for ${fileType}. This may indicate additional encryption, obfuscation, or embedded encrypted data beyond normal compression.`,
            suspicious: true
        };
    }
    // Below expected minimum
    return {
        hasBaseline: true,
        status: 'low',
        deviation: min - entropy,
        explanation: `Entropy ${entropy.toFixed(2)} is BELOW expected minimum (${min.toFixed(1)}) for ${fileType}. This may indicate incomplete compression, corrupted data, or unusual content.`,
        suspicious: false // Low entropy is generally not a security concern
    };
}
