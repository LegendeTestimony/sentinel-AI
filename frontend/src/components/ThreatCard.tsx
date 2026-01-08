import React from 'react';
import { Shield, AlertTriangle, AlertOctagon, Info, CheckCircle } from 'lucide-react';
import type { ThreatAnalysis, ThreatLevel } from '../types/analysis';

interface ThreatCardProps {
  threat: ThreatAnalysis;
  fileName: string;
}

export const ThreatCard: React.FC<ThreatCardProps> = ({ threat, fileName }) => {
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
    <div className={`w-full p-6 bg-sentinel-card rounded-lg border-l-4 ${config.borderColor} ${config.bgColor}`}>
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
