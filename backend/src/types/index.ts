export interface FileMetadata {
  filename: string;
  size: number;
  type: string;
  lastModified: number;
  hash?: string;
  created?: string;
  modified?: string;
  permissions?: string;
}

export interface HeaderValidation {
  claimedType: string;
  actualType: string;
  match: boolean;
  suspicious: boolean;
}

export interface FileStructure {
  preview: string;
  sections?: string[];
  apis?: string[];
}

export interface FileAnalysis {
  metadata: FileMetadata;
  entropy: number;
  headerValid: HeaderValidation;
  structure: FileStructure;
  timestamp: number;
  context?: string;
}

export type ThreatLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' | 'UNKNOWN';

export interface VirusTotalResult {
  checked: boolean;
  found: boolean;
  detections?: number;
  totalEngines?: number;
  scanDate?: string;
  permalink?: string;
  positives?: {
    [engine: string]: {
      detected: boolean;
      result: string;
    };
  };
  sha256?: string;
}

export interface SandboxPrediction {
  fileOperations: string[];
  networkActivity: string[];
  registryChanges: string[];
  processCreation: string[];
  riskScore: number;
  behaviorSummary: string;
}

export interface ThreatAnalysis {
  level: ThreatLevel;
  confidence: number;
  summary: string;
  fullAnalysis: string;
  timestamp: number;
  technicalAnalysis?: string;
  predictedAttackVector?: string;
  indicators?: string[];
  recommendation?: string;
  reasoning?: string;
  // Steganography-specific analysis
  hiddenContentAnalysis?: {
    extractedMessages: string[];
    contentThreatLevel: 'HARMLESS' | 'SUSPICIOUS' | 'MALICIOUS';
    contentAnalysis: string;
  };
  // VirusTotal integration
  virusTotal?: VirusTotalResult;
  // Sandbox behavior prediction
  sandboxPrediction?: SandboxPrediction;
}

export interface AnalysisResult {
  file: FileMetadata;
  analysis: FileAnalysis;
  threat: ThreatAnalysis;
  recommendations: string[];
}

// === NEW ENHANCED TYPES ===

// Import types from analyzers
import type { FileIdentificationResult } from '../analyzers/file-identifier.js';
import type { FormatBaseline, EntropyBaselineAnalysis } from '../analyzers/format-baselines.js';
import type { ThreatIndicator, ThreatScore, ComprehensiveAnalysis } from '../analyzers/threat-scorer.js';
import type { SteganographyAnalysis, SteganographyTechnique } from '../analyzers/steganography-detector.js';
import type { PolyglotAnalysis } from '../analyzers/polyglot-detector.js';
import type { PayloadAnalysis, EmbeddedPayload } from '../analyzers/payload-hunter.js';
import type { ISOBMFFResult } from '../analyzers/isobmff-parser.js';
import type { MagicDetectionResult } from '../analyzers/magic-bytes.js';

// Re-export for convenience
export type {
  FileIdentificationResult,
  FormatBaseline,
  EntropyBaselineAnalysis,
  ThreatIndicator,
  ThreatScore,
  ComprehensiveAnalysis,
  SteganographyAnalysis,
  SteganographyTechnique,
  PolyglotAnalysis,
  PayloadAnalysis,
  EmbeddedPayload,
  ISOBMFFResult,
  MagicDetectionResult
};

// Enhanced analysis result with all new detections
export interface EnhancedAnalysisResult extends AnalysisResult {
  fileIdentification?: FileIdentificationResult;
  entropyAnalysis?: EntropyBaselineAnalysis;
  threatScore?: ThreatScore;
  steganography?: SteganographyAnalysis;
  polyglot?: PolyglotAnalysis;
  payloads?: PayloadAnalysis;
}
