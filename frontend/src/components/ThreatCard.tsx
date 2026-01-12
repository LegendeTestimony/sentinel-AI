import React from 'react';
import { Shield, AlertTriangle, AlertOctagon, Info, CheckCircle, Database, Activity, ExternalLink, Eye, EyeOff } from 'lucide-react';
import type { ThreatAnalysis, ThreatLevel, SteganographyAnalysis } from '../types/analysis';

interface ThreatCardProps {
  threat: ThreatAnalysis;
  fileName: string;
  steganography?: SteganographyAnalysis;
}

export const ThreatCard: React.FC<ThreatCardProps> = ({ threat, fileName, steganography }) => {

  const getThreatConfig = (level: ThreatLevel) => {
    switch (level) {
      case 'CRITICAL':
        return {
          color: 'threat-critical',
          bgColor: 'bg-red-500/10',
          borderColor: 'border-l-threat-critical',
          icon: AlertOctagon,
          label: 'CRITICAL THREAT'
        };
      case 'HIGH':
        return {
          color: 'threat-high',
          bgColor: 'bg-orange-500/10',
          borderColor: 'border-l-threat-high',
          icon: AlertTriangle,
          label: 'HIGH THREAT'
        };
      case 'MEDIUM':
        return {
          color: 'threat-medium',
          bgColor: 'bg-yellow-500/10',
          borderColor: 'border-l-threat-medium',
          icon: AlertTriangle,
          label: 'MEDIUM THREAT'
        };
      case 'LOW':
        return {
          color: 'threat-low',
          bgColor: 'bg-green-500/10',
          borderColor: 'border-l-threat-low',
          icon: Info,
          label: 'LOW THREAT'
        };
      case 'SAFE':
        return {
          color: 'threat-safe',
          bgColor: 'bg-blue-500/10',
          borderColor: 'border-l-threat-safe',
          icon: CheckCircle,
          label: 'SAFE'
        };
      default:
        return {
          color: 'gray-500',
          bgColor: 'bg-gray-500/10',
          borderColor: 'border-l-gray-500',
          icon: Shield,
          label: 'UNKNOWN'
        };
    }
  };

  const config = getThreatConfig(threat.level);
  const Icon = config.icon;

  return (
    <div className={`w-full p-6 bg-sentinel-card rounded-lg  ${config.borderColor} ${config.bgColor}`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <Icon className={`w-6 h-6 text-${config.color}`} />
          <div>
            <h3 className={`text-lg font-bold text-${config.color}`}>
              {config.label}
            </h3>
            <p className="text-sm text-gray-400">{fileName}</p>
          </div>
        </div>

        <div className="text-right">
          <div className={`text-2xl font-bold text-${config.color}`}>
            {threat.confidence}%
          </div>
          <div className="text-xs text-gray-400">Confidence</div>
        </div>
      </div>

      {/* Summary */}
      <div className="mb-4">
        <h4 className="text-sm font-semibold text-gray-300 mb-2">SUMMARY</h4>
        <p className="text-gray-200">{threat.summary}</p>
      </div>

      {/* VirusTotal Results */}
      {threat.virusTotal?.checked && (
        <div className={`mb-4 p-4 rounded-lg border ${threat.virusTotal.found && threat.virusTotal.detections && threat.virusTotal.detections > 0
            ? 'bg-red-500/10 border-red-500/30'
            : 'bg-green-500/10 border-green-500/30'
          }`}>
          <div className="flex items-center gap-2 mb-2">
            <Database className={`w-5 h-5 ${threat.virusTotal.found && threat.virusTotal.detections && threat.virusTotal.detections > 0
                ? 'text-red-400'
                : 'text-green-400'
              }`} />
            <h4 className="text-sm font-semibold text-gray-300">VIRUSTOTAL SCAN</h4>
          </div>

          {threat.virusTotal.found ? (
            <>
              <div className="flex items-center justify-between mb-2">
                <span className="text-2xl font-bold">
                  <span className={threat.virusTotal.detections && threat.virusTotal.detections > 0 ? 'text-red-400' : 'text-green-400'}>
                    {threat.virusTotal.detections || 0}
                  </span>
                  <span className="text-gray-400">/{threat.virusTotal.totalEngines}</span>
                </span>
                <span className="text-xs text-gray-400">security vendors flagged this file</span>
              </div>
              {threat.virusTotal.permalink && (
                <a
                  href={threat.virusTotal.permalink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition"
                >
                  View full report <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </>
          ) : (
            <p className="text-sm text-gray-400">
              File not found in VirusTotal database (likely new/unique file)
            </p>
          )}
        </div>
      )}

      {/* Sandbox Prediction */}
      {threat.sandboxPrediction && (
        <div className="mb-4 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-400" />
              <h4 className="text-sm font-semibold text-blue-300">SANDBOX BEHAVIOR PREDICTION</h4>
            </div>
            <span className="text-lg font-bold text-blue-400">
              {threat.sandboxPrediction.riskScore}/100
            </span>
          </div>

          <p className="text-xs text-gray-300 mb-3">{threat.sandboxPrediction.behaviorSummary}</p>

          {threat.sandboxPrediction.fileOperations.length > 0 && (
            <div className="mb-2">
              <p className="text-xs font-semibold text-gray-400 mb-1">File Operations:</p>
              <ul className="list-disc list-inside text-xs text-gray-300 space-y-1">
                {threat.sandboxPrediction.fileOperations.slice(0, 3).map((op, idx) => (
                  <li key={idx}>{op}</li>
                ))}
              </ul>
            </div>
          )}

          {threat.sandboxPrediction.networkActivity.length > 0 && (
            <div className="mb-2">
              <p className="text-xs font-semibold text-gray-400 mb-1">Network Activity:</p>
              <ul className="list-disc list-inside text-xs text-gray-300 space-y-1">
                {threat.sandboxPrediction.networkActivity.slice(0, 3).map((activity, idx) => (
                  <li key={idx}>{activity}</li>
                ))}
              </ul>
            </div>
          )}

          {threat.sandboxPrediction.processCreation.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-400 mb-1">Process Creation:</p>
              <ul className="list-disc list-inside text-xs text-gray-300 space-y-1">
                {threat.sandboxPrediction.processCreation.slice(0, 3).map((proc, idx) => (
                  <li key={idx}>{proc}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Hidden Content Analysis (Steganography) */}
      {threat.hiddenContentAnalysis && (
        <div className="mb-4 p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
          <div className="flex items-center gap-2 mb-3">
            <Eye className="w-5 h-5 text-purple-400" />
            <h4 className="text-sm font-semibold text-purple-300">HIDDEN CONTENT DETECTED</h4>
            <span className={`ml-auto px-2 py-0.5 text-xs rounded ${threat.hiddenContentAnalysis.contentThreatLevel === 'MALICIOUS' ? 'bg-red-500/20 text-red-400' :
                threat.hiddenContentAnalysis.contentThreatLevel === 'SUSPICIOUS' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-green-500/20 text-green-400'
              }`}>
              {threat.hiddenContentAnalysis.contentThreatLevel}
            </span>
          </div>

          {threat.hiddenContentAnalysis.extractedMessages.length > 0 && (
            <div className="mb-3">
              <p className="text-xs text-gray-400 mb-1">Extracted Messages:</p>
              {threat.hiddenContentAnalysis.extractedMessages.map((msg, idx) => (
                <div key={idx} className="bg-black/30 p-2 rounded text-sm text-purple-200 font-mono mb-1">
                  "{msg}"
                </div>
              ))}
            </div>
          )}

          <p className="text-sm text-gray-300">{threat.hiddenContentAnalysis.contentAnalysis}</p>
        </div>
      )}

      {/* Steganography Details (if detected but no hidden content analysis from AI) */}
      {steganography?.detected && !threat.hiddenContentAnalysis && (
        <div className="mb-4 p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
          <div className="flex items-center gap-2 mb-3">
            <EyeOff className="w-5 h-5 text-purple-400" />
            <h4 className="text-sm font-semibold text-purple-300">STEGANOGRAPHY DETECTED</h4>
            <span className="ml-auto text-xs text-gray-400">{steganography.confidence}% confidence</span>
          </div>

          {steganography.extractedData?.textMessages && steganography.extractedData.textMessages.length > 0 && (
            <div className="mb-3">
              <p className="text-xs text-gray-400 mb-1">Hidden Messages Found:</p>
              {steganography.extractedData.textMessages.map((msg, idx) => (
                <div key={idx} className="bg-black/30 p-2 rounded text-sm text-purple-200 font-mono mb-1">
                  "{msg}"
                </div>
              ))}
            </div>
          )}

          <div className="space-y-2">
            {steganography.techniques.map((tech, idx) => (
              <div key={idx} className="text-sm">
                <span className="text-purple-300 font-medium">{tech.name}</span>
                <span className="text-gray-400"> - {tech.description}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technical Analysis */}
      {threat.technicalAnalysis && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-gray-300 mb-2">TECHNICAL ANALYSIS</h4>
          <div className="text-sm text-gray-300 whitespace-pre-wrap font-mono bg-black/30 p-3 rounded">
            {threat.technicalAnalysis}
          </div>
        </div>
      )}

      {/* Predicted Attack Vector */}
      {threat.predictedAttackVector && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-gray-300 mb-2">PREDICTED ATTACK VECTOR</h4>
          <div className="text-sm text-gray-300 whitespace-pre-wrap bg-black/30 p-3 rounded">
            {threat.predictedAttackVector}
          </div>
        </div>
      )}

      {/* Indicators */}
      {threat.indicators && threat.indicators.length > 0 && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-gray-300 mb-2">KEY INDICATORS</h4>
          <ul className="space-y-2">
            {threat.indicators.map((indicator, index) => (
              <li key={index} className="flex items-start gap-2 text-sm text-gray-300">
                <span className={`text-${config.color} mt-1`}>▪</span>
                <span>{indicator}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommendation */}
      {threat.recommendation && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-gray-300 mb-2">RECOMMENDATION</h4>
          <p className="text-sm text-gray-200 bg-black/30 p-3 rounded">
            {threat.recommendation}
          </p>
        </div>
      )}

      {/* Reasoning */}
      {threat.reasoning && (
        <div>
          <h4 className="text-sm font-semibold text-gray-300 mb-2">REASONING</h4>
          <p className="text-sm text-gray-400 italic">
            {threat.reasoning}
          </p>
        </div>
      )}

      {/* Full Analysis (collapsible) */}
      <details className="mt-4">
        <summary className="text-sm font-semibold text-gray-400 cursor-pointer hover:text-gray-300">
          View Full Analysis
        </summary>
        <div className="mt-2 text-xs text-gray-400 whitespace-pre-wrap font-mono bg-black/50 p-3 rounded max-h-64 overflow-y-auto">
          {threat.fullAnalysis}
        </div>
      </details>
    </div>
  );
};
