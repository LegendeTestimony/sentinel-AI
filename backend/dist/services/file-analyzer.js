import { extractMetadata } from '../analyzers/metadata-extractor.js';
import { calculateEntropy } from '../analyzers/entropy-analyzer.js';
import { validateHeader } from '../analyzers/header-validator.js';
import { parseStructure } from '../analyzers/structure-parser.js';
import { analyzeWithGemini } from './gemini-client.js';
import { analyzeWithMultiAgent } from './multi-agent-gemini.js';
import { identifyFile } from '../analyzers/file-identifier.js';
import { analyzeEntropyAgainstBaseline } from '../analyzers/format-baselines.js';
import { calculateThreatScore } from '../analyzers/threat-scorer.js';
import { detectSteganography } from '../analyzers/steganography-detector.js';
import { detectPolyglot } from '../analyzers/polyglot-detector.js';
import { huntPayloads } from '../analyzers/payload-hunter.js';
import { checkFileHash } from './virustotal-client.js';
import { predictSandboxBehavior } from './sandbox-predictor.js';
/**
 * Generate recommendations based on threat analysis
 */
function generateRecommendations(threatLevel, confidence) {
    const recommendations = [];
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
 * Main file analysis function - Multi-stage pipeline
 */
export async function analyzeFile(file) {
    console.log(`\n🔍 Starting multi-stage analysis for: ${file.originalname}`);
    // === STAGE 1: Multi-Layer File Identification ===
    console.log('📋 Stage 1: Multi-layer file identification...');
    const fileIdentification = identifyFile(file.originalname, file.buffer);
    console.log(`   ✓ Detected type: ${fileIdentification.identifiedType} (${fileIdentification.confidence.toFixed(0)}% confidence)`);
    console.log(`   ✓ Category: ${fileIdentification.category}`);
    if (fileIdentification.extensionMismatch) {
        console.log(`   ⚠️  Extension mismatch: ${fileIdentification.mismatchSeverity}`);
    }
    // === STAGE 2: Metadata Extraction ===
    console.log('📊 Stage 2: Metadata extraction...');
    const metadata = await extractMetadata(file);
    console.log(`   ✓ Size: ${metadata.size} bytes, Hash: ${metadata.hash ? metadata.hash.substring(0, 16) + '...' : 'N/A'}`);
    // === STAGE 3: Entropy Analysis (Baseline-Aware) ===
    console.log('🎲 Stage 3: Baseline-aware entropy analysis...');
    const entropy = calculateEntropy(file.buffer);
    const entropyAnalysis = analyzeEntropyAgainstBaseline(fileIdentification.identifiedType, entropy);
    console.log(`   ✓ Entropy: ${entropy.toFixed(2)}/8.0`);
    console.log(`   ✓ Status: ${entropyAnalysis.status}${entropyAnalysis.suspicious ? ' (SUSPICIOUS)' : ''}`);
    // === STAGE 4: Structure Parsing (Using Detected Type) ===
    console.log('🏗️  Stage 4: Structure parsing...');
    // Pass detected type to structure parser
    const structure = parseStructure(file.originalname, file.buffer, fileIdentification.identifiedType);
    console.log(`   ✓ Sections: ${structure.sections?.length || 0}, APIs: ${structure.apis?.length || 0}`);
    // === STAGE 5: Header Validation (Legacy Support) ===
    const headerValid = validateHeader(file.originalname, file.buffer);
    // === STAGE 6: Novel Detection Modules ===
    console.log('🔬 Stage 6: Novel detection modules...');
    // 6.1: Steganography Detection
    const steganography = detectSteganography(file.buffer, fileIdentification.identifiedType);
    console.log(`   ✓ Steganography: ${steganography.detected ? `DETECTED (${steganography.techniques.length} techniques)` : 'None'}`);
    // Log steganography details if detected
    if (steganography.detected) {
        console.log('\n   📝 STEGANOGRAPHY DETAILS:');
        steganography.techniques.forEach((tech, idx) => {
            console.log(`   ${idx + 1}. ${tech.name} (${tech.confidence}% confidence)`);
            console.log(`      Description: ${tech.description}`);
            if (tech.evidence && tech.evidence.length > 0) {
                console.log(`      Evidence:`);
                tech.evidence.forEach(ev => console.log(`        - ${ev}`));
            }
        });
        // Show extracted hidden messages prominently
        if (steganography.extractedData?.textMessages && steganography.extractedData.textMessages.length > 0) {
            console.log('\n   🔓 EXTRACTED HIDDEN MESSAGES:');
            steganography.extractedData.textMessages.forEach((msg, idx) => {
                console.log(`   Message ${idx + 1}: "${msg}"`);
            });
            console.log(`   Total hidden bytes: ${steganography.extractedData.totalHiddenBytes}`);
            console.log(`   Locations: ${steganography.extractedData.dataLocations.join(', ')}`);
        }
        console.log(`\n   Summary: ${steganography.analysis}\n`);
    }
    // 6.2: Polyglot Detection
    const polyglot = detectPolyglot(file.buffer);
    console.log(`   ✓ Polyglot: ${polyglot.isPolyglot ? `DETECTED (${polyglot.validFormats.join(', ')})` : 'None'}`);
    // 6.3: Embedded Payload Detection
    const payloads = huntPayloads(file.buffer, fileIdentification.identifiedType);
    console.log(`   ✓ Payloads: ${payloads.foundPayloads.length > 0 ? `${payloads.foundPayloads.length} found` : 'None'}`);
    // === STAGE 7: Local Threat Scoring ===
    console.log('⚖️  Stage 7: Evidence-based threat scoring...');
    const threatScore = calculateThreatScore({
        fileIdentification,
        entropyAnalysis,
        entropy,
        structure,
        filename: file.originalname
    });
    console.log(`   ✓ Local Score: ${threatScore.normalizedScore.toFixed(0)}/100 (${threatScore.riskLevel.toUpperCase()})`);
    console.log(`   ✓ Benign indicators: ${threatScore.indicators.filter(i => i.weight < 0).length}`);
    console.log(`   ✓ Risk indicators: ${threatScore.indicators.filter(i => i.weight > 0).length}`);
    // Build legacy file analysis object (for compatibility)
    const analysis = {
        metadata,
        entropy,
        headerValid,
        structure,
        timestamp: Date.now(),
        context: 'User upload via Sentinel web interface',
    };
    // === STAGE 8: AI Threat Analysis ===
    console.log('🤖 Stage 8: AI threat analysis with reasoning...');
    const threat = await analyzeWithGemini(analysis, fileIdentification, entropyAnalysis, threatScore, steganography);
    console.log(`   ✓ AI Analysis Complete: ${threat.level} (${threat.confidence}% confidence)`);
    // === STAGE 8.5: Multi-Agent Confidence Threshold Check ===
    // Trigger multi-agent debate for borderline cases
    const shouldTriggerMultiAgent = (threat.level === 'MEDIUM' && threat.confidence < 70) || (threat.confidence < 60 && threat.level !== 'SAFE');
    if (shouldTriggerMultiAgent) {
        console.log('🔄 Stage 8.5: Triggering multi-agent analysis (borderline case)...');
        try {
            const multiAgentResult = await analyzeWithMultiAgent(analysis, fileIdentification, entropyAnalysis, threatScore, steganography);
            // Override single-agent result with multi-agent verdict
            threat.level = multiAgentResult.finalVerdict.level;
            threat.confidence = multiAgentResult.finalVerdict.confidence;
            threat.fullAnalysis = multiAgentResult.finalVerdict.fullAnalysis;
            threat.reasoning = multiAgentResult.finalVerdict.summary;
            console.log(`   ✓ Multi-Agent Verdict: ${threat.level} (${threat.confidence}% confidence)`);
        }
        catch (error) {
            console.error('   ⚠️ Multi-agent analysis failed, using single-agent result:', error);
        }
    }
    // === STAGE 9: VirusTotal Check ===
    console.log('🦠 Stage 9: Checking VirusTotal database...');
    const virusTotalResult = await checkFileHash(file.buffer);
    if (virusTotalResult.checked && virusTotalResult.found && virusTotalResult.detections) {
        console.log(`   ✓ VirusTotal: ${virusTotalResult.detections}/${virusTotalResult.totalEngines} detections`);
    }
    // Add VirusTotal data to threat analysis
    threat.virusTotal = virusTotalResult;
    // === STAGE 10: Sandbox Behavior Prediction ===
    console.log('🧪 Stage 10: Predicting sandbox behavior...');
    const sandboxPrediction = await predictSandboxBehavior(analysis, threatScore, steganography, fileIdentification);
    console.log(`   ✓ Predicted Risk Score: ${sandboxPrediction.riskScore}/100`);
    // Add sandbox prediction to threat analysis
    threat.sandboxPrediction = sandboxPrediction;
    // === STAGE 11: Generate Recommendations ===
    console.log('📝 Stage 11: Generating recommendations...');
    const recommendations = generateRecommendations(threat.level, threat.confidence);
    // Add steganography/polyglot/payload warnings to recommendations
    if (steganography.detected) {
        recommendations.unshift(`⚠️ Hidden data detected: ${steganography.analysis}`);
    }
    if (polyglot.isPolyglot && (polyglot.securityRisk === 'high' || polyglot.securityRisk === 'critical')) {
        recommendations.unshift(`🚨 Polyglot file detected: Valid as ${polyglot.validFormats.join(', ')}`);
    }
    if (payloads.foundPayloads.length > 0) {
        recommendations.unshift(`⚠️ Embedded payloads detected: ${payloads.summary}`);
    }
    console.log(`✅ Analysis complete for ${file.originalname}\n`);
    // Return enhanced result with all analysis data
    return {
        file: metadata,
        analysis,
        threat,
        recommendations,
        // Enhanced data
        fileIdentification,
        entropyAnalysis,
        threatScore,
        steganography,
        polyglot,
        payloads
    };
}
