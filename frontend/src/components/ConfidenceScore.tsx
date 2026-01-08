import React from 'react';

interface ConfidenceScoreProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
}

export const ConfidenceScore: React.FC<ConfidenceScoreProps> = ({ score, size = 'md' }) => {
  const getColor = (score: number) => {
    if (score >= 90) return 'text-threat-safe';
    if (score >= 70) return 'text-threat-low';
    if (score >= 50) return 'text-threat-medium';
    return 'text-threat-high';
  };

  const getBarColor = (score: number) => {
    if (score >= 90) return 'bg-threat-safe';
    if (score >= 70) return 'bg-threat-low';
    if (score >= 50) return 'bg-threat-medium';
    return 'bg-threat-high';
  };

  const sizeClasses = {
    sm: 'text-lg',
    md: 'text-2xl',
    lg: 'text-4xl',
  };

  return (
    <div className="flex flex-col items-center gap-2">
      <div className={`${sizeClasses[size]} font-bold ${getColor(score)}`}>
        {score}%
      </div>
      <div className="w-full bg-gray-700 rounded-full h-2 overflow-hidden">
        <div
          className={`h-full ${getBarColor(score)} transition-all duration-500`}
          style={{ width: `${score}%` }}
        />
      </div>
      <div className="text-xs text-gray-400">Confidence</div>
    </div>
  );
};
