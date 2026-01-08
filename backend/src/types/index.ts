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
}

export interface AnalysisResult {
  file: FileMetadata;
  analysis: FileAnalysis;
  threat: ThreatAnalysis;
  recommendations: string[];
}
