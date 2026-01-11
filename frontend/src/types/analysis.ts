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

export interface HiddenContentAnalysis {
  extractedMessages: string[];
  contentThreatLevel: 'HARMLESS' | 'SUSPICIOUS' | 'MALICIOUS';
  contentAnalysis: string;
}

export interface SteganographyTechnique {
  name: string;
  confidence: number;
  description: string;
  evidence?: string[];
}

export interface SteganographyAnalysis {
  detected: boolean;
  confidence: number;
  techniques: SteganographyTechnique[];
  analysis: string;
  extractedData?: {
    textMessages: string[];
    rawDataSamples: string[];
    totalHiddenBytes: number;
    dataLocations: string[];
  };
}

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
  hiddenContentAnalysis?: HiddenContentAnalysis;
  virusTotal?: VirusTotalResult;
  sandboxPrediction?: SandboxPrediction;
}

export interface URLInfo {
  original: string;
  final: string;
  redirectChain: string[];
  protocol: string;
  domain: string;
}

export interface WebpageInfo {
  title?: string;
  scripts: string[];
  iframes: string[];
  forms: string[];
  externalLinks: string[];
}

export interface AnalysisResult {
  file: FileMetadata;
  analysis: FileAnalysis;
  threat: ThreatAnalysis;
  recommendations: string[];
  steganography?: SteganographyAnalysis;
  url?: URLInfo;
  webpage?: WebpageInfo;
}

export interface AnalysisPipelineStep {
  id: string;
  label: string;
  status: 'pending' | 'active' | 'complete' | 'error';
  message?: string;
}
