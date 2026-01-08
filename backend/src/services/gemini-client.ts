import { GoogleGenerativeAI } from '@google/generative-ai';
import { MASTER_SYSTEM_PROMPT } from '../config/prompts.js';
import type { FileAnalysis, ThreatAnalysis, ThreatLevel } from '../types/index.js';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

/**
 * Parse Gemini's text response into structured threat analysis
 */
function parseThreatResponse(text: string): ThreatAnalysis {
  // Extract threat level
  const threatLevelMatch = text.match(/THREAT LEVEL:\s*(\w+)/i);
  const level: ThreatLevel = (threatLevelMatch?.[1]?.toUpperCase() as ThreatLevel) || 'UNKNOWN';

  // Extract confidence score
  const confidenceMatch = text.match(/CONFIDENCE:\s*(\d+)/);
  const confidence = confidenceMatch ? parseInt(confidenceMatch[1], 10) : 0;

  // Extract summary
  const summaryMatch = text.match(/SUMMARY:\s*(.+?)(?=\n\n|\*\*)/s);
  const summary = summaryMatch?.[1]?.trim() || 'No summary provided';

  // Extract technical analysis
  const techAnalysisMatch = text.match(/TECHNICAL ANALYSIS:\s*(.+?)(?=\*\*|$)/s);
  const technicalAnalysis = techAnalysisMatch?.[1]?.trim();

  // Extract predicted attack vector
  const attackVectorMatch = text.match(/PREDICTED ATTACK VECTOR:\s*(.+?)(?=\*\*|$)/s);
  const predictedAttackVector = attackVectorMatch?.[1]?.trim();

  // Extract indicators
  const indicatorsMatch = text.match(/INDICATORS:\s*(.+?)(?=\*\*|$)/s);
  const indicatorsText = indicatorsMatch?.[1]?.trim();
  const indicators = indicatorsText
    ?.split('\n')
    .map(line => line.replace(/^[-•*]\s*/, '').trim())
    .filter(line => line.length > 0);

  // Extract recommendation
  const recommendationMatch = text.match(/RECOMMENDATION:\s*(.+?)(?=\*\*|$)/s);
  const recommendation = recommendationMatch?.[1]?.trim();

  // Extract reasoning
  const reasoningMatch = text.match(/REASONING:\s*(.+?)(?=\*\*|$)/s);
  const reasoning = reasoningMatch?.[1]?.trim();

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
  };
}

/**
 * Analyze file with Gemini AI
 */
export async function analyzeWithGemini(
  fileAnalysis: FileAnalysis
): Promise<ThreatAnalysis> {
  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });

    const prompt = `
${MASTER_SYSTEM_PROMPT}

## File Analysis Data:

**Filename**: ${fileAnalysis.metadata.filename}
**Size**: ${fileAnalysis.metadata.size} bytes
**Claimed Type**: ${fileAnalysis.headerValid.claimedType}
**Actual Header Type**: ${fileAnalysis.headerValid.actualType}
**Header Match**: ${fileAnalysis.headerValid.match ? 'Yes' : 'NO - SUSPICIOUS'}
**Entropy Score**: ${fileAnalysis.entropy.toFixed(2)} / 8.0 ${fileAnalysis.entropy > 7 ? '(HIGH - potential obfuscation)' : ''}

**Metadata**:
- Created: ${fileAnalysis.metadata.created}
- Modified: ${fileAnalysis.metadata.modified}
- Hash (SHA-256): ${fileAnalysis.metadata.hash}

**File Structure Analysis**:
${fileAnalysis.structure.sections ? `Sections: ${fileAnalysis.structure.sections.join(', ')}` : 'No special sections detected'}
${fileAnalysis.structure.apis ? `Suspicious APIs Found: ${fileAnalysis.structure.apis.join(', ')}` : 'No suspicious API calls detected'}

**File Content Preview**:
\`\`\`
${fileAnalysis.structure.preview}
\`\`\`

**Behavioral Context**:
${fileAnalysis.context || 'Unknown source - analyze as high-risk'}

---

Perform comprehensive threat analysis and predict potential attack vectors.
`;

    const result = await model.generateContent(prompt);
    const response = result.response;
    const analysisText = response.text();

    return parseThreatResponse(analysisText);
  } catch (error) {
    console.error('Gemini analysis error:', error);

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
