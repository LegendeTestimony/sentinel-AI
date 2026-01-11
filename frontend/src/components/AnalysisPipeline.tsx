import React from 'react';
import { CheckCircle, Circle, Loader, XCircle } from 'lucide-react';
import type { AnalysisPipelineStep } from '../types/analysis';

interface AnalysisPipelineProps {
  steps: AnalysisPipelineStep[];
}

export const AnalysisPipeline: React.FC<AnalysisPipelineProps> = ({ steps }) => {
  if (steps.length === 0) return null;

  const getStepIcon = (status: AnalysisPipelineStep['status']) => {
    switch (status) {
      case 'complete':
        return <CheckCircle className="w-5 h-5 text-threat-safe" />;
      case 'active':
        return <Loader className="w-5 h-5 text-threat-safe animate-spin" />;
      case 'error':
        return <XCircle className="w-5 h-5 text-threat-critical" />;
      default:
        return <Circle className="w-5 h-5 text-gray-600" />;
    }
  };

  const getStepColor = (status: AnalysisPipelineStep['status']) => {
    switch (status) {
      case 'complete':
        return 'text-gray-300';
      case 'active':
        return 'text-threat-safe font-semibold';
      case 'error':
        return 'text-threat-critical';
      default:
        return 'text-gray-500';
    }
  };

  return (
    <div className="w-full p-6 bg-sentinel-card rounded-lg border border-sentinel-border">
      <h3 className="text-lg font-semibold text-gray-200 mb-4">Analysis Pipeline</h3>

      <div className="space-y-3">
        {steps.map((step) => (
          <div key={step.id} className="flex items-start gap-3">
            <div className="shrink-0 mt-0.5">
              {getStepIcon(step.status)}
            </div>

            <div className="flex-1 min-w-0">
              <p className={`text-sm ${getStepColor(step.status)}`}>
                {step.label}
              </p>

              {step.message && (
                <p className="text-xs text-gray-400 mt-1">
                  {step.message}
                </p>
              )}

              {step.status === 'active' && (
                <div className="mt-2 w-full bg-gray-700 rounded-full h-1 overflow-hidden">
                  <div className="h-full bg-threat-safe animate-pulse-glow w-[70%]" />
                </div>
              )}
            </div>


          </div>
        ))}
      </div>
    </div>
  );
};
