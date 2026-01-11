import { GoogleGenerativeAI } from '@google/generative-ai';
import type { SandboxPrediction, FileAnalysis, ThreatScore, SteganographyAnalysis } from '../types/index.js';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

/**
 * Use AI to predict what would happen if file is executed in a sandbox
 */
export async function predictSandboxBehavior(
  fileAnalysis: FileAnalysis,
  threatScore?: ThreatScore,
  steganography?: SteganographyAnalysis,
  fileIdentification?: any
): Promise<SandboxPrediction> {
  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });

    const prompt = `You are a malware analysis sandbox simulator. Based on static analysis of a file, predict what would happen if it were executed in an isolated sandbox environment.

## File Analysis Data:
\`\`\`json
${JSON.stringify({
  filename: fileAnalysis.metadata.filename,
  fileType: fileAnalysis.metadata.type,
  size: fileAnalysis.metadata.size,
  entropy: fileAnalysis.entropy,
  headerValid: fileAnalysis.headerValid,
  structure: fileAnalysis.structure,
  threatScore: threatScore ? {
    normalizedScore: threatScore.normalizedScore,
    riskLevel: threatScore.riskLevel,
    indicators: threatScore.indicators.map(i => ({ type: i.type, description: i.description }))
  } : null,
  steganography: steganography?.detected ? {
    confidence: steganography.confidence,
    techniques: steganography.techniques.map(t => t.name)
  } : null,
  fileIdentification: fileIdentification ? {
    actualFormat: fileIdentification.actualFormat,
    confidence: fileIdentification.confidence
  } : null
}, null, 2)}
\`\`\`

**YOUR TASK:**
Based on this static analysis, predict the file's behavior if executed. Be specific and technical.

**FORMAT YOUR RESPONSE EXACTLY AS:**

FILE OPERATIONS:
- [Specific file operation 1]
- [Specific file operation 2]
...

NETWORK ACTIVITY:
- [Specific network activity 1]
- [Specific network activity 2]
...

REGISTRY CHANGES:
- [Specific registry change 1]
- [Specific registry change 2]
...

PROCESS CREATION:
- [Specific process 1]
- [Specific process 2]
...

RISK SCORE: [0-100]

BEHAVIOR SUMMARY:
[2-3 sentence summary of predicted behavior]

**IMPORTANT RULES:**
1. If file appears benign, predict normal behavior (e.g., "Display image in viewer")
2. If file shows malicious indicators, predict specific attack behaviors
3. Be realistic - base predictions on actual file type and indicators
4. Each section can have 0-5 items depending on file type
5. Risk score should match threat level (SAFE=0-20, LOW=21-40, MEDIUM=41-60, HIGH=61-80, CRITICAL=81-100)`;

    const result = await model.generateContent(prompt);
    const text = result.response.text();

    // Parse the response
    const fileOpsMatch = text.match(/FILE OPERATIONS:([\s\S]*?)(?=NETWORK ACTIVITY:|$)/i);
    const networkMatch = text.match(/NETWORK ACTIVITY:([\s\S]*?)(?=REGISTRY CHANGES:|$)/i);
    const registryMatch = text.match(/REGISTRY CHANGES:([\s\S]*?)(?=PROCESS CREATION:|$)/i);
    const processMatch = text.match(/PROCESS CREATION:([\s\S]*?)(?=RISK SCORE:|$)/i);
    const riskMatch = text.match(/RISK SCORE:\s*(\d+)/i);
    const summaryMatch = text.match(/BEHAVIOR SUMMARY:([\s\S]*?)$/i);

    const parseList = (match: RegExpMatchArray | null): string[] => {
      if (!match || !match[1]) return [];
      return match[1]
        .split('\n')
        .map(line => line.trim().replace(/^-\s*/, ''))
        .filter(line => line.length > 0 && !line.startsWith('FILE') && !line.startsWith('NETWORK'));
    };

    return {
      fileOperations: parseList(fileOpsMatch),
      networkActivity: parseList(networkMatch),
      registryChanges: parseList(registryMatch),
      processCreation: parseList(processMatch),
      riskScore: riskMatch ? parseInt(riskMatch[1]) : 50,
      behaviorSummary: summaryMatch ? summaryMatch[1].trim() : 'Unable to predict behavior based on available data.',
    };
  } catch (error) {
    console.error('Sandbox prediction error:', error);

    // Return safe default prediction on error
    return {
      fileOperations: ['Analysis unavailable due to prediction error'],
      networkActivity: [],
      registryChanges: [],
      processCreation: [],
      riskScore: 50,
      behaviorSummary: 'Sandbox behavior prediction unavailable. Analysis completed without behavioral simulation.',
    };
  }
}
