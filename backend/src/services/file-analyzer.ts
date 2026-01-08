import { extractMetadata } from '../analyzers/metadata-extractor.js';
import { calculateEntropy } from '../analyzers/entropy-analyzer.js';
import { validateHeader } from '../analyzers/header-validator.js';
import { parseStructure } from '../analyzers/structure-parser.js';
import { analyzeWithGemini } from './gemini-client.js';
import type { AnalysisResult, FileAnalysis } from '../types/index.js';

/**
 * Generate recommendations based on threat analysis
 */
function generateRecommendations(threatLevel: string, confidence: number): string[] {
  const recommendations: string[] = [];

  switch (threatLevel) {
    case 'CRITICAL':
      recommendations.push('🚨 IMMEDIATE ACTION: Quarantine this file immediately');
      recommendations.push('Do NOT execute or open this file');
      recommendations.push('Report to security team for forensic analysis');
      recommendations.push('Scan system for similar files or indicators of compromise');
      break;

    case 'HIGH':
      recommendations.push('⚠️ Quarantine file and prevent execution');
      recommendations.push('Conduct thorough investigation before any interaction');
      recommendations.push('Review file source and delivery method');
      break;

    case 'MEDIUM':
      recommendations.push('⚡ Exercise caution with this file');
      recommendations.push('Verify file source and authenticity');
      recommendations.push('Consider running in sandboxed environment if needed');
      break;

    case 'LOW':
      recommendations.push('ℹ️ Minor concerns detected');
      recommendations.push('Verify file source before use');
      recommendations.push('Monitor for unexpected behavior');
      break;

    case 'SAFE':
      recommendations.push('✅ File appears safe based on analysis');
      recommendations.push('Standard security practices still apply');
      break;

    default:
      recommendations.push('❓ Unable to determine threat level');
      recommendations.push('Manual review recommended');
      break;
  }

  if (confidence < 70) {
    recommendations.push(`⚠️ Low confidence (${confidence}%) - consider additional analysis`);
  }

  return recommendations;
}

/**
 * Main file analysis function
 */
export async function analyzeFile(file: Express.Multer.File): Promise<AnalysisResult> {
  // Extract metadata
  const metadata = await extractMetadata(file);

  // Calculate entropy
  const entropy = calculateEntropy(file.buffer);

  // Validate header
  const headerValid = validateHeader(file.originalname, file.buffer);

  // Parse structure
  const structure = parseStructure(file.originalname, file.buffer);

  // Build file analysis object
  const analysis: FileAnalysis = {
    metadata,
    entropy,
    headerValid,
    structure,
    timestamp: Date.now(),
    context: 'User upload via Sentinel web interface',
  };

  // Send to Gemini for AI analysis
  const threat = await analyzeWithGemini(analysis);

  // Generate recommendations
  const recommendations = generateRecommendations(threat.level, threat.confidence);

  return {
    file: metadata,
    analysis,
    threat,
    recommendations,
  };
}
