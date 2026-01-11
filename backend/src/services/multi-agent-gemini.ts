import { GoogleGenerativeAI } from '@google/generative-ai';
import dotenv from 'dotenv';
import type { FileAnalysis, ThreatLevel, SteganographyAnalysis } from '../types/index.js';

dotenv.config();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

export interface AgentArgument {
  agent: 'prosecutor' | 'defense' | 'judge';
  analysis: string;
  threatLevel?: ThreatLevel;
  confidence?: number;
  reasoning: string;
}

export interface MultiAgentAnalysis {
  prosecutor: AgentArgument;
  defense: AgentArgument;
  judge: AgentArgument;
  finalVerdict: {
    level: ThreatLevel;
    confidence: number;
    summary: string;
    fullAnalysis: string;
  };
  debateTranscript: string;
}

/**
 * PROSECUTOR AGENT - Finds all suspicious indicators
 */
async function prosecutorAnalysis(
  fileData: any,
  formatContext: string
): Promise<AgentArgument> {
  const model = genAI.getGenerativeModel({ model: 'gemini-3-flash' });

  const prompt = `You are a SECURITY PROSECUTOR analyzing a potentially malicious file. Your job is to find ALL suspicious indicators and argue for the HIGHEST threat level justified by evidence.

## File Analysis Data:
\`\`\`json
${JSON.stringify(fileData, null, 2)}
\`\`\`

${formatContext ? `\n## Format Context:\n${formatContext}\n` : ''}

**YOUR TASK:**
1. List EVERY suspicious indicator found in the data
2. Explain why each indicator suggests malicious intent
3. Propose a threat level (CRITICAL/HIGH/MEDIUM/LOW/SAFE)
4. Build the strongest case for why this file is dangerous

**FORMAT YOUR RESPONSE AS:**
THREAT LEVEL: [Your assessment]
CONFIDENCE: [0-100]

SUSPICIOUS INDICATORS:
- [Indicator 1 and why it's concerning]
- [Indicator 2 and why it's concerning]
...

PROSECUTION ARGUMENT:
[Your detailed argument for why this file is a threat]

Be aggressive in your analysis. Assume worst-case scenarios. Your job is to protect users.`;

  const result = await model.generateContent(prompt);
  const text = result.response.text();

  // Parse response
  const levelMatch = text.match(/THREAT LEVEL:\s*(\w+)/i);
  const confMatch = text.match(/CONFIDENCE:\s*(\d+)/i);

  return {
    agent: 'prosecutor',
    analysis: text,
    threatLevel: (levelMatch?.[1]?.toUpperCase() as ThreatLevel) || 'MEDIUM',
    confidence: confMatch ? parseInt(confMatch[1]) : 70,
    reasoning: text.split('PROSECUTION ARGUMENT:')[1]?.trim() || text
  };
}

/**
 * DEFENSE AGENT - Explains benign reasons for each indicator
 */
async function defenseAnalysis(
  fileData: any,
  formatContext: string,
  prosecutorArgument: AgentArgument
): Promise<AgentArgument> {
  const model = genAI.getGenerativeModel({ model: 'gemini-3-flash' });

  const prompt = `You are a SECURITY DEFENSE ANALYST. The prosecutor claims this file is malicious. Your job is to provide ALTERNATIVE BENIGN EXPLANATIONS for each suspicious indicator.

## File Analysis Data:
\`\`\`json
${JSON.stringify(fileData, null, 2)}
\`\`\`

${formatContext ? `\n## Format Context:\n${formatContext}\n` : ''}

## Prosecutor's Argument:
${prosecutorArgument.analysis}

**YOUR TASK:**
1. Address EACH indicator the prosecutor mentioned
2. Provide legitimate, benign explanations
3. Explain why this could be a false positive
4. Propose a LOWER threat level with justification

**FORMAT YOUR RESPONSE AS:**
THREAT LEVEL: [Your assessment]
CONFIDENCE: [0-100]

DEFENSE REBUTTALS:
- [Prosecutor's point 1]: [Your benign explanation]
- [Prosecutor's point 2]: [Your benign explanation]
...

DEFENSE ARGUMENT:
[Your detailed argument for why this file is likely benign or lower threat]

Be thorough in finding innocent explanations. Consider legitimate use cases. Your job is to prevent false positives.`;

  const result = await model.generateContent(prompt);
  const text = result.response.text();

  // Parse response
  const levelMatch = text.match(/THREAT LEVEL:\s*(\w+)/i);
  const confMatch = text.match(/CONFIDENCE:\s*(\d+)/i);

  return {
    agent: 'defense',
    analysis: text,
    threatLevel: (levelMatch?.[1]?.toUpperCase() as ThreatLevel) || 'LOW',
    confidence: confMatch ? parseInt(confMatch[1]) : 60,
    reasoning: text.split('DEFENSE ARGUMENT:')[1]?.trim() || text
  };
}

/**
 * JUDGE AGENT - Weighs both arguments and makes final decision
 */
async function judgeAnalysis(
  fileData: any,
  formatContext: string,
  prosecutor: AgentArgument,
  defense: AgentArgument
): Promise<AgentArgument> {
  const model = genAI.getGenerativeModel({ model: 'gemini-3-flash' });

  const prompt = `You are a SENIOR SECURITY JUDGE. Two expert analysts have debated this file. Your job is to weigh BOTH arguments and make the FINAL, BALANCED decision.

## File Analysis Data:
\`\`\`json
${JSON.stringify(fileData, null, 2)}
\`\`\`

${formatContext ? `\n## Format Context:\n${formatContext}\n` : ''}

## Prosecutor's Argument (Threat Level: ${prosecutor.threatLevel}, Confidence: ${prosecutor.confidence}%):
${prosecutor.analysis}

## Defense's Argument (Threat Level: ${defense.threatLevel}, Confidence: ${defense.confidence}%):
${defense.analysis}

**YOUR TASK:**
1. Evaluate the STRENGTH of each argument
2. Identify which points are FACTUALLY CORRECT
3. Make a BALANCED decision based on evidence weight
4. Provide FINAL threat level and confidence
5. Explain your reasoning for the verdict

**CRITICAL GUIDELINES:**
- If both agents agree, validate their consensus
- If they disagree, weigh evidence objectively
- High-confidence prosecution + weak defense → Higher threat
- Strong defense rebuttals + weak evidence → Lower threat
- Consider false positive cost vs false negative cost

**FORMAT YOUR RESPONSE AS:**
FINAL VERDICT:
THREAT LEVEL: [Your final decision]
CONFIDENCE: [0-100]

SUMMARY: [1-2 sentence verdict summary]

ANALYSIS OF ARGUMENTS:
Prosecutor's Strongest Points:
- [Point and evaluation]
...

Defense's Strongest Points:
- [Point and evaluation]

REASONING:
[Detailed explanation of your final decision, weighing both sides]

RECOMMENDATION:
[What the user should do]`;

  const result = await model.generateContent(prompt);
  const text = result.response.text();

  // Parse response
  const levelMatch = text.match(/THREAT LEVEL:\s*(\w+)/i);
  const confMatch = text.match(/CONFIDENCE:\s*(\d+)/i);
  const summaryMatch = text.match(/SUMMARY:\s*(.+?)(?=\n\n|\nANALYSIS)/s);

  return {
    agent: 'judge',
    analysis: text,
    threatLevel: (levelMatch?.[1]?.toUpperCase() as ThreatLevel) || 'MEDIUM',
    confidence: confMatch ? parseInt(confMatch[1]) : 65,
    reasoning: text.split('REASONING:')[1]?.trim() || text
  };
}

/**
 * Run multi-agent analysis with Prosecutor -> Defense -> Judge debate
 */
export async function analyzeWithMultiAgent(
  fileAnalysis: FileAnalysis,
  fileIdentification?: any,
  entropyAnalysis?: any,
  threatScore?: any,
  steganography?: SteganographyAnalysis
): Promise<MultiAgentAnalysis> {
  console.log('⚖️  Starting multi-agent debate...');

  // Build structured data for agents
  const structuredData = {
    fileMetadata: {
      filename: fileAnalysis.metadata.filename,
      size: fileAnalysis.metadata.size,
      hash: fileAnalysis.metadata.hash
    },
    typeIdentification: fileIdentification ? {
      detectedType: fileIdentification.identifiedType,
      category: fileIdentification.category,
      confidence: `${fileIdentification.confidence.toFixed(0)}%`,
      extensionMatchesContent: !fileIdentification.extensionMismatch,
      mismatchSeverity: fileIdentification.mismatchSeverity
    } : null,
    entropyAnalysis: entropyAnalysis ? {
      measured: fileAnalysis.entropy.toFixed(2),
      status: entropyAnalysis.status,
      deviation: entropyAnalysis.deviation.toFixed(2),
      suspicious: entropyAnalysis.suspicious,
      explanation: entropyAnalysis.explanation
    } : null,
    structureAnalysis: {
      sections: fileAnalysis.structure.sections || [],
      suspiciousAPIs: fileAnalysis.structure.apis || []
    },
    localThreatScore: threatScore ? {
      normalizedScore: `${threatScore.normalizedScore.toFixed(0)}/100`,
      riskLevel: threatScore.riskLevel,
      riskIndicators: threatScore.indicators.filter((i: any) => i.weight > 0)
    } : null,
    steganographyAnalysis: steganography?.detected ? {
      detected: true,
      confidence: steganography.confidence,
      techniques: steganography.techniques,
      extractedMessages: steganography.extractedData?.textMessages || []
    } : { detected: false }
  };

  // Get format context
  const formatContext = fileIdentification?.identifiedType === 'heic'
    ? 'HEIC files are Apple image format with NORMAL high entropy (7.2-8.0). High entropy is NOT suspicious for HEIC.'
    : fileIdentification?.identifiedType === 'png'
    ? 'PNG files use DEFLATE compression with NORMAL entropy (6.5-8.0). High entropy is NOT suspicious for PNG.'
    : '';

  try {
    // STAGE 1: Prosecutor finds threats
    console.log('   🔍 Prosecutor analyzing...');
    const prosecutor = await prosecutorAnalysis(structuredData, formatContext);
    console.log(`   ✓ Prosecutor verdict: ${prosecutor.threatLevel} (${prosecutor.confidence}%)`);

    // STAGE 2: Defense provides counter-arguments
    console.log('   🛡️  Defense analyzing...');
    const defense = await defenseAnalysis(structuredData, formatContext, prosecutor);
    console.log(`   ✓ Defense verdict: ${defense.threatLevel} (${defense.confidence}%)`);

    // STAGE 3: Judge weighs both sides
    console.log('   ⚖️  Judge deliberating...');
    const judge = await judgeAnalysis(structuredData, formatContext, prosecutor, defense);
    console.log(`   ✓ Judge final verdict: ${judge.threatLevel} (${judge.confidence}%)`);

    // Build debate transcript
    const debateTranscript = `
=== MULTI-AGENT SECURITY ANALYSIS ===

📋 PROSECUTOR'S ARGUMENT (${prosecutor.threatLevel} - ${prosecutor.confidence}% confidence):
${prosecutor.analysis}

───────────────────────────────────────

🛡️ DEFENSE'S REBUTTAL (${defense.threatLevel} - ${defense.confidence}% confidence):
${defense.analysis}

───────────────────────────────────────

⚖️ JUDGE'S FINAL VERDICT (${judge.threatLevel} - ${judge.confidence}% confidence):
${judge.analysis}
`;

    return {
      prosecutor,
      defense,
      judge,
      finalVerdict: {
        level: judge.threatLevel!,
        confidence: judge.confidence!,
        summary: judge.analysis.match(/SUMMARY:\s*(.+?)(?=\n\n|\nANALYSIS)/s)?.[1]?.trim() ||
                 `Final verdict after multi-agent debate: ${judge.threatLevel}`,
        fullAnalysis: debateTranscript
      },
      debateTranscript
    };
  } catch (error) {
    console.error('Multi-agent analysis error:', error);
    throw error;
  }
}
