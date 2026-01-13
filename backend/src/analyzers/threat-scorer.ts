/**
 * Evidence-Based Threat Scoring System
 * Uses weighted indicators to calculate accurate threat levels
 */

import type { FileIdentificationResult } from './file-identifier.js';
import type { EntropyBaselineAnalysis } from './format-baselines.js';
import type { FileStructure } from '../types/index.js';

export interface ThreatIndicator {
  id: string;
  name: string;
  category: 'header' | 'entropy' | 'structure' | 'content' | 'behavior';
  weight: number;          // -100 to +100 (negative = benign, positive = threat)
  confidence: number;      // How sure are we about this indicator (0-100)
  description: string;
}

export interface ThreatScore {
  rawScore: number;        // Sum of weighted indicators
  normalizedScore: number; // 0-100 scale
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  indicators: ThreatIndicator[];
  explanation: string;
}

export interface ComprehensiveAnalysis {
  fileIdentification: FileIdentificationResult;
  entropyAnalysis: EntropyBaselineAnalysis;
  entropy: number;
  structure: FileStructure;
  filename: string;
}

/**
 * Calculate threat score based on all evidence
 */
export function calculateThreatScore(analysis: ComprehensiveAnalysis): ThreatScore {
  const indicators: ThreatIndicator[] = [];

  // === POSITIVE INDICATORS (reduce threat score, indicate benign file) ===

  // 1. High confidence format identification
  if (analysis.fileIdentification.confidence > 90) {
    indicators.push({
      id: 'high_confidence_format',
      name: 'High Confidence Format Match',
      category: 'header',
      weight: -20,
      confidence: analysis.fileIdentification.confidence,
      description: `File type "${analysis.fileIdentification.identifiedType}" identified with ${analysis.fileIdentification.confidence.toFixed(0)}% confidence`
    });
  }

  // 2. Entropy within baseline range
  if (analysis.entropyAnalysis.hasBaseline && analysis.entropyAnalysis.status === 'normal') {
    indicators.push({
      id: 'normal_entropy',
      name: 'Normal Entropy for Format',
      category: 'entropy',
      weight: -15,
      confidence: 95,
      description: analysis.entropyAnalysis.explanation
    });
  }

  // 3. Extension matches detected type
  if (!analysis.fileIdentification.extensionMismatch) {
    indicators.push({
      id: 'extension_match',
      name: 'Extension Matches Content',
      category: 'header',
      weight: -10,
      confidence: 100,
      description: 'File extension is consistent with detected content type'
    });
  }

  // 4. Known safe format with proper structure
  const safeFormats = ['jpeg', 'png', 'gif', 'bmp', 'heic', 'heif', 'avif', 'webp', 'mp3', 'flac', 'wav'];
  if (safeFormats.includes(analysis.fileIdentification.identifiedType) &&
      analysis.fileIdentification.confidence > 85) {
    indicators.push({
      id: 'known_safe_format',
      name: 'Known Safe Media Format',
      category: 'header',
      weight: -15,
      confidence: 90,
      description: `${analysis.fileIdentification.identifiedType.toUpperCase()} is a standard media format that cannot execute code`
    });
  }

  // === NEGATIVE INDICATORS (increase threat score, indicate potential threat) ===

  // 1. Extension mismatch (varies by severity)
  if (analysis.fileIdentification.extensionMismatch) {
    const severityWeights: Record<string, number> = {
      none: 0,
      minor: 10,
      suspicious: 40,
      critical: 80
    };
    const weight = severityWeights[analysis.fileIdentification.mismatchSeverity] || 10;

    indicators.push({
      id: 'extension_mismatch',
      name: 'Extension/Content Mismatch',
      category: 'header',
      weight,
      confidence: 95,
      description: `File claims to be "${analysis.fileIdentification.claimedExtension}" but content is "${analysis.fileIdentification.identifiedType}" (severity: ${analysis.fileIdentification.mismatchSeverity})`
    });
  }

  // 2. Suspicious APIs detected in non-executable files
  if (analysis.structure.apis && analysis.structure.apis.length > 0) {
    const isExecutableType = ['pe', 'elf', 'macho', 'script', 'html', 'pdf'].includes(
      analysis.fileIdentification.identifiedType
    );

    if (!isExecutableType) {
      // APIs in non-executable files are HIGHLY suspicious
      indicators.push({
        id: 'unexpected_apis',
        name: 'Unexpected API/Code Patterns',
        category: 'content',
        weight: 60,
        confidence: 80,
        description: `Found ${analysis.structure.apis.length} suspicious code pattern(s) in ${analysis.fileIdentification.category} file: ${analysis.structure.apis.slice(0, 3).join(', ')}`
      });
    } else if (analysis.fileIdentification.identifiedType === 'pdf') {
      // PDFs with suspicious APIs are concerning but not uncommon
      indicators.push({
        id: 'pdf_with_scripts',
        name: 'PDF Contains Scripts/APIs',
        category: 'content',
        weight: 35,
        confidence: 75,
        description: `PDF contains: ${analysis.structure.apis.slice(0, 3).join(', ')}`
      });
    }
  }

  // 3. Abnormally high entropy for file type
  if (analysis.entropyAnalysis.hasBaseline && analysis.entropyAnalysis.status === 'high') {
    indicators.push({
      id: 'abnormal_high_entropy',
      name: 'Abnormally High Entropy',
      category: 'entropy',
      weight: 25,
      confidence: 70,
      description: analysis.entropyAnalysis.explanation
    });
  }

  // 4. Unknown file type (mild concern, not automatic threat)
  if (analysis.fileIdentification.identifiedType === 'unknown') {
    indicators.push({
      id: 'unknown_type',
      name: 'Unknown File Type',
      category: 'header',
      weight: 5, // Very low weight - unknown != dangerous
      confidence: 50,
      description: 'File type could not be identified from signature. This may be a legitimate rare format or corrupted file.'
    });
  }

  // 5. Executable file types (inherently higher risk)
  if (analysis.fileIdentification.category === 'executable') {
    indicators.push({
      id: 'executable_file',
      name: 'Executable File Type',
      category: 'header',
      weight: 30,
      confidence: 100,
      description: `File is an executable (${analysis.fileIdentification.identifiedType}). Requires scrutiny.`
    });
  }

  // 6. Double extension pattern
  const filenameParts = analysis.filename.split('.');
  if (filenameParts.length > 2) {
    const penultimateExt = filenameParts[filenameParts.length - 2].toLowerCase();
    const executableExts = ['exe', 'dll', 'com', 'bat', 'cmd', 'ps1', 'sh', 'scr'];

    if (executableExts.includes(penultimateExt)) {
      indicators.push({
        id: 'double_extension',
        name: 'Double Extension Attack Pattern',
        category: 'header',
        weight: 70,
        confidence: 90,
        description: `File uses double extension pattern (${filenameParts.slice(-2).join('.')}) commonly used to disguise executables`
      });
    }
  }

  // 7. PE sections in non-PE file
  if (analysis.structure.sections && analysis.structure.sections.length > 0) {
    if (analysis.fileIdentification.identifiedType !== 'pe') {
      indicators.push({
        id: 'unexpected_pe_sections',
        name: 'PE Sections in Non-Executable',
        category: 'structure',
        weight: 65,
        confidence: 85,
        description: 'File contains PE executable sections but is not identified as a PE file. Possible polyglot or embedded executable.'
      });
    }
  }

  // === CALCULATE FINAL SCORE ===

  // Raw score: sum of (weight * confidence / 100)
  const rawScore = indicators.reduce((sum, ind) => {
    return sum + (ind.weight * ind.confidence / 100);
  }, 0);

  // Normalize to 0-100 scale (centered at 50)
  // Positive scores push toward 100, negative toward 0
  let normalizedScore = 50 + (rawScore * 0.5);
  normalizedScore = Math.max(0, Math.min(100, normalizedScore));

  // Determine risk level
  const riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical' =
    normalizedScore < 20 ? 'safe' :
    normalizedScore < 35 ? 'low' :
    normalizedScore < 55 ? 'medium' :
    normalizedScore < 75 ? 'high' : 'critical';

  // Generate explanation
  const explanation = generateScoreExplanation(indicators, riskLevel, normalizedScore);

  return {
    rawScore,
    normalizedScore,
    riskLevel,
    indicators,
    explanation
  };
}

/**
 * Generate human-readable explanation of the score
 */
function generateScoreExplanation(
  indicators: ThreatIndicator[],
  riskLevel: string,
  score: number
): string {
  const positiveIndicators = indicators.filter(i => i.weight < 0);
  const negativeIndicators = indicators.filter(i => i.weight > 0);

  let explanation = `Threat Level: ${riskLevel.toUpperCase()} (score: ${score.toFixed(0)}/100)\n\n`;

  if (positiveIndicators.length > 0) {
    explanation += `Benign Indicators (${positiveIndicators.length}):\n`;
    positiveIndicators.forEach(ind => {
      explanation += `  • ${ind.name}\n`;
    });
    explanation += '\n';
  }

  if (negativeIndicators.length > 0) {
    explanation += `Risk Indicators (${negativeIndicators.length}):\n`;
    negativeIndicators.forEach(ind => {
      explanation += `  • ${ind.name} (weight: +${ind.weight})\n`;
    });
    explanation += '\n';
  }

  if (negativeIndicators.length === 0) {
    explanation += 'No significant risk indicators detected. File appears to be legitimate.';
  }

  return explanation;
}
