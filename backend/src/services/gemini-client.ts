import { GoogleGenerativeAI } from '@google/generative-ai';
import dotenv from 'dotenv';
import { MASTER_SYSTEM_PROMPT } from '../config/prompts.js';
import type { FileAnalysis, ThreatAnalysis, ThreatLevel, SteganographyAnalysis } from '../types/index.js';

// Load environment variables
dotenv.config();

// Debug logging
console.log('🔑 Gemini API Key loaded:', process.env.GEMINI_API_KEY ? `${process.env.GEMINI_API_KEY.substring(0, 10)}...` : 'NOT FOUND');

if (!process.env.GEMINI_API_KEY) {
  console.error('❌ ERROR: GEMINI_API_KEY not found in environment variables!');
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

/**
 * Retry function with exponential backoff for 429 errors
 */
async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  maxRetries = 3,
  initialDelay = 1000
): Promise<T> {
  let lastError: any;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;
      
      // If it's a 429 (rate limit), retry with backoff
      if (error.status === 429) {
        const delay = initialDelay * Math.pow(2, attempt);
        console.log(`⏱️  Rate limit hit (429). Retrying in ${delay}ms... (Attempt ${attempt + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        // For other errors, don't retry
        throw error;
      }
    }
  }
  
  throw lastError;
}

/**
 * Parse Gemini's text response into structured threat analysis
 */
function parseThreatResponse(text: string): ThreatAnalysis {
  // Helper function to extract section content between headers
  // Looks for content after a section header until the next section header or end
  const extractSection = (sectionName: string): string | undefined => {
    // Match section header with optional ** markers and capture everything until next header
    const escapedName = sectionName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(
      `\\*{0,2}${escapedName}\\*{0,2}[:\\s]*\\n?([\\s\\S]*?)(?=\\n\\*{0,2}[A-Z][A-Z ]{2,}\\*{0,2}:|$)`,
      'i'
    );
    const match = text.match(pattern);
    const content = match?.[1]?.trim();
    // Return undefined if content is empty or just whitespace
    return content && content.length > 0 ? content : undefined;
  };

  // Extract threat level (handle both **THREAT LEVEL**: and THREAT LEVEL:)
  const threatLevelMatch = text.match(/\*{0,2}THREAT LEVEL\*{0,2}:\s*(\w+)/i);
  const level: ThreatLevel = (threatLevelMatch?.[1]?.toUpperCase() as ThreatLevel) || 'UNKNOWN';

  // Extract confidence score
  const confidenceMatch = text.match(/\*{0,2}CONFIDENCE\*{0,2}:\s*(\d+)/i);
  const confidence = confidenceMatch ? parseInt(confidenceMatch[1], 10) : 0;

  // Extract summary - handle inline format "**SUMMARY**: text" or block format
  const summaryInlineMatch = text.match(/\*{0,2}SUMMARY\*{0,2}:\s*([^\n]+)/i);
  const summary = summaryInlineMatch?.[1]?.trim() || extractSection('SUMMARY') || 'No summary provided';

  // Extract technical analysis
  const technicalAnalysis = extractSection('TECHNICAL ANALYSIS');

  // Extract predicted attack vector
  const predictedAttackVector = extractSection('PREDICTED ATTACK VECTOR');

  // Extract indicators
  const indicatorsText = extractSection('INDICATORS');
  const indicators = indicatorsText
    ?.split('\n')
    .map(line => line.replace(/^[-•*\d.)\s]+/, '').trim())
    .filter(line => line.length > 0 && !line.match(/^(key finding|indicator)/i));

  // Extract recommendation
  const recommendation = extractSection('RECOMMENDATION');

  // Extract reasoning
  const reasoning = extractSection('REASONING');

  // Extract hidden content analysis (for steganography)
  const hiddenContentMatch = text.match(/\*{0,2}HIDDEN CONTENT ANALYSIS\*{0,2}:\s*(.+?)(?=\*\*[A-Z]|$)/s);
  const hiddenContentText = hiddenContentMatch?.[1]?.trim();

  // Try to parse hidden content threat level
  let hiddenContentAnalysis: {
    extractedMessages: string[];
    contentThreatLevel: 'HARMLESS' | 'SUSPICIOUS' | 'MALICIOUS';
    contentAnalysis: string;
  } | undefined;

  if (hiddenContentText) {
    // Extract message quotes from the analysis
    const messageMatches = hiddenContentText.match(/"([^"]+)"/g) || [];
    const extractedMessages = messageMatches.map(m => m.replace(/"/g, ''));

    // Determine content threat level
    let contentThreatLevel: 'HARMLESS' | 'SUSPICIOUS' | 'MALICIOUS' = 'HARMLESS';
    const lowerText = hiddenContentText.toLowerCase();
    if (lowerText.includes('malicious') || lowerText.includes('malware') || lowerText.includes('shellcode') || lowerText.includes('exploit')) {
      contentThreatLevel = 'MALICIOUS';
    } else if (lowerText.includes('suspicious') || lowerText.includes('encoded') || lowerText.includes('encrypted') || lowerText.includes('command')) {
      contentThreatLevel = 'SUSPICIOUS';
    }

    hiddenContentAnalysis = {
      extractedMessages,
      contentThreatLevel,
      contentAnalysis: hiddenContentText
    };
  }

  return {
    level,
    confidence,
    summary,
    fullAnalysis: text,
    timestamp: Date.now(),
    technicalAnalysis,
    predictedAttackVector,
    indicators,
    recommendation,
    reasoning,
    ...(hiddenContentAnalysis ? { hiddenContentAnalysis } : {})
  };
}

/**
 * Get format-specific context for Gemini
 */
function getFormatContext(fileType: string, category?: string): string {
  const contexts: Record<string, string> = {
    'heic': 'HEIC (High Efficiency Image Container) is Apple\'s modern image format using HEVC compression. Files are ISOBMFF containers with ftyp boxes containing "heic" brand. **Entropy of 7.2-8.0 is COMPLETELY NORMAL and EXPECTED**. These are legitimate image files that cannot execute code.',

    'heif': 'HEIF (High Efficiency Image Format) is a modern container format. **Entropy of 7.2-8.0 is COMPLETELY NORMAL**. These are legitimate image files.',

    'avif': 'AVIF (AV1 Image File Format) is a cutting-edge image format using AV1 compression. **Entropy of 7.3-8.0 is COMPLETELY NORMAL and EXPECTED**. These are legitimate image files that cannot execute code.',

    'webp': 'WebP is Google\'s modern image format in RIFF container using VP8/VP8L compression. **Entropy of 7.0-8.0 is COMPLETELY NORMAL**. These are legitimate image files.',

    'jpeg': 'JPEG is a compressed image format using DCT compression. **Entropy of 7.0-8.0 is COMPLETELY NORMAL due to compression**. These are legitimate image files that cannot execute code.',

    'png': 'PNG is a compressed image format using DEFLATE compression. **Entropy of 6.5-8.0 is COMPLETELY NORMAL**. These are legitimate image files that cannot execute code.',

    'mp4': 'MP4 is a video container using H.264/H.265 compression. **Entropy of 7.0-8.0 is COMPLETELY NORMAL**. These are legitimate video files.',

    'unknown': 'File type could not be identified from signature. This does NOT necessarily indicate malicious intent - it may be a rare legitimate format, corrupted file, or proprietary format.'
  };

  return contexts[fileType] || `${fileType} file format. Analyze based on detected characteristics.`;
}

/**
 * Analyze file with Gemini AI - Enhanced version with structured data
 */
export async function analyzeWithGemini(
  fileAnalysis: FileAnalysis,
  fileIdentification?: any,
  entropyAnalysis?: any,
  threatScore?: any,
  steganography?: SteganographyAnalysis
): Promise<ThreatAnalysis> {
  try {
    // Use Gemini 3 Flash - our most balanced model for speed and intelligence
    const model = genAI.getGenerativeModel({ model: 'gemini-3-flash-preview' });

    // Build structured analysis data (neutral, fact-based)
    const structuredData = {
      fileMetadata: {
        filename: fileAnalysis.metadata.filename,
        size: fileAnalysis.metadata.size,
        hash: fileAnalysis.metadata.hash
      },

      typeIdentification: fileIdentification ? {
        detectedType: fileIdentification.identifiedType,
        mimeType: fileIdentification.mimeType,
        category: fileIdentification.category,
        confidence: `${fileIdentification.confidence.toFixed(0)}%`,
        extensionMatchesContent: !fileIdentification.extensionMismatch,
        mismatchSeverity: fileIdentification.mismatchSeverity,
        claimedExtension: fileIdentification.claimedExtension,
        humanDescription: fileIdentification.humanDescription,
        securityNotes: fileIdentification.securityNotes
      } : {
        detectedType: fileAnalysis.headerValid.actualType,
        claimedType: fileAnalysis.headerValid.claimedType,
        headerMatch: fileAnalysis.headerValid.match
      },

      entropyAnalysis: entropyAnalysis ? {
        measured: fileAnalysis.entropy.toFixed(2),
        hasBaseline: entropyAnalysis.hasBaseline,
        status: entropyAnalysis.status,
        deviation: entropyAnalysis.deviation.toFixed(2),
        explanation: entropyAnalysis.explanation,
        suspicious: entropyAnalysis.suspicious
      } : {
        measured: fileAnalysis.entropy.toFixed(2),
        scale: '0-8 (Shannon entropy)'
      },

      structureAnalysis: {
        sections: fileAnalysis.structure.sections || [],
        suspiciousAPIs: fileAnalysis.structure.apis || [],
        preview: fileAnalysis.structure.preview
      },

      localThreatScore: threatScore ? {
        normalizedScore: `${threatScore.normalizedScore.toFixed(0)}/100`,
        riskLevel: threatScore.riskLevel,
        benignIndicators: threatScore.indicators.filter((i: any) => i.weight < 0).map((i: any) => i.name),
        riskIndicators: threatScore.indicators.filter((i: any) => i.weight > 0).map((i: any) => ({
          name: i.name,
          weight: i.weight
        }))
      } : null,

      steganographyAnalysis: steganography?.detected ? {
        detected: true,
        confidence: steganography.confidence,
        techniques: steganography.techniques.map(t => ({
          name: t.name,
          confidence: t.confidence,
          description: t.description
        })),
        extractedContent: steganography.extractedData ? {
          hiddenMessages: steganography.extractedData.textMessages,
          totalHiddenBytes: steganography.extractedData.totalHiddenBytes,
          dataLocations: steganography.extractedData.dataLocations,
          rawDataSamples: steganography.extractedData.rawDataSamples.slice(0, 2) // Limit for prompt size
        } : null,
        summary: steganography.analysis
      } : { detected: false }
    };

    // Get format-specific context
    const formatContext = fileIdentification
      ? getFormatContext(fileIdentification.identifiedType, fileIdentification.category)
      : '';

    const prompt = `
${MASTER_SYSTEM_PROMPT}

## Structured File Analysis Data (JSON Format):

\`\`\`json
${JSON.stringify(structuredData, null, 2)}
\`\`\`

${formatContext ? `\n## Format-Specific Context:\n${formatContext}\n` : ''}

---

**CRITICAL ANALYSIS GUIDELINES**:

1. **Entropy Interpretation**:
   - High entropy (7-8) is COMPLETELY NORMAL for compressed formats (JPEG, PNG, HEIC, AVIF, WebP, MP4, ZIP, etc.)
   - Do NOT flag legitimate compressed media as suspicious based on entropy alone
   - Only flag entropy as suspicious if it's ABNORMAL for the detected file type

2. **Accuracy Over Caution**:
   - Most files are legitimate - default to SAFE/LOW unless concrete malicious indicators exist
   - Require MULTIPLE concrete indicators for HIGH/CRITICAL ratings
   - A single characteristic (high entropy, unknown type, etc.) is NOT sufficient

3. **Concrete Malicious Indicators Required**:
   - Extension/content mismatches with critical severity (e.g., .exe claiming to be .jpg)
   - Embedded executables in non-executable files
   - Shellcode patterns or obfuscated scripts
   - Suspicious APIs in unexpected file types (e.g., "CreateRemoteThread" in image file)
   - Polyglot files (valid as multiple formats)

4. **What NOT to Flag**:
   - Unknown file types (unknown ≠ malicious)
   - High entropy in compressed formats
   - Modern file formats (HEIC, AVIF, WebP)
   - Legitimate file structures

5. **Use Local Threat Score**:
   - If provided, heavily weight the local threat score in your analysis
   - The local score is evidence-based with format-specific knowledge

6. **Steganography Analysis** (if detected):
   - If steganography is detected, analyze the EXTRACTED HIDDEN CONTENT
   - Report the exact hidden message(s) found in your analysis
   - Assess whether the hidden content is:
     * HARMLESS: Simple text messages, watermarks, metadata, copyright info
     * SUSPICIOUS: Encoded data, URLs, commands, scripts, or encrypted content
     * MALICIOUS: Shellcode, malware payloads, C2 commands, exploit code
   - Include a dedicated "HIDDEN CONTENT ANALYSIS" section in your response
   - Tell the user exactly what message was hidden and whether it poses a threat

Perform comprehensive threat analysis with explicit reasoning for your threat level assignment.

**IMPORTANT**: If hidden messages were extracted, you MUST include them in your response and analyze their threat potential.
`;

    // Wrap the Gemini API call with retry logic
    const result = await retryWithBackoff(async () => {
      return await model.generateContent(prompt);
    });
    
    const response = result.response;
    const analysisText = response.text();

    console.log('📝 Gemini response received, length:', analysisText.length);
    console.log('📝 First 200 chars:', analysisText.substring(0, 200));

    const parsed = parseThreatResponse(analysisText);
    console.log('✅ Parsed threat level:', parsed.level, 'Confidence:', parsed.confidence);

    return parsed;
  } catch (error: any) {
    console.error('Gemini analysis error:', error);

    // Handle quota exceeded error specifically
    if (error.status === 429) {
      return {
        level: 'UNKNOWN',
        confidence: 0,
        summary: 'Rate limit exceeded - Gemini API quota exhausted',
        fullAnalysis: `⏱️ Gemini API rate limit exceeded. Your free tier quota has been exhausted.\n\nError: ${error.message}\n\n📈 Check usage: https://aistudio.google.com/app/apikey\n📚 Rate limits: https://ai.google.dev/gemini-api/docs/rate-limits\n\n💡 Quota resets at midnight Pacific Time.`,
        timestamp: Date.now(),
        recommendation: 'Analysis limited - wait for quota reset or upgrade API plan',
      };
    }

    // Return fallback analysis on error
    return {
      level: 'UNKNOWN',
      confidence: 0,
      summary: 'Analysis failed due to API error',
      fullAnalysis: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      timestamp: Date.now(),
      recommendation: 'Manual review recommended due to analysis failure',
    };
  }
}
