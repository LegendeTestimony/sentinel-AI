import { useState, useCallback } from 'react';
import { sentinelApi } from '../api/sentinelApi';
import type { AnalysisResult, AnalysisPipelineStep } from '../types/analysis';

export const useFileAnalysis = () => {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pipeline, setPipeline] = useState<AnalysisPipelineStep[]>([]);

  const initializePipeline = useCallback(() => {
    setPipeline([
      { id: 'upload', label: 'File uploaded', status: 'complete' },
      { id: 'metadata', label: 'Extracting metadata', status: 'active' },
      { id: 'entropy', label: 'Calculating entropy', status: 'pending' },
      { id: 'header', label: 'Validating headers', status: 'pending' },
      { id: 'gemini', label: 'Gemini threat analysis', status: 'pending' },
      { id: 'prediction', label: 'Predicting attack vectors', status: 'pending' },
    ]);
  }, []);

  const updatePipelineStep = useCallback((stepId: string, status: AnalysisPipelineStep['status'], message?: string) => {
    setPipeline(prev =>
      prev.map(step =>
        step.id === stepId ? { ...step, status, message } : step
      )
    );
  }, []);

  const analyzeFile = useCallback(async (file: File) => {
    setAnalyzing(true);
    setError(null);
    setResult(null);
    initializePipeline();

    try {
      // Simulate pipeline progression
      updatePipelineStep('metadata', 'complete');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('entropy', 'active');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('entropy', 'complete');
      updatePipelineStep('header', 'active');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('header', 'complete');
      updatePipelineStep('gemini', 'active');

      // Actual API call
      const analysisResult = await sentinelApi.analyzeFile(file);

      updatePipelineStep('gemini', 'complete');
      updatePipelineStep('prediction', 'active');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('prediction', 'complete');

      setResult(analysisResult);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed';
      setError(errorMessage);

      // Mark current active step as error
      setPipeline(prev =>
        prev.map(step =>
          step.status === 'active' ? { ...step, status: 'error', message: errorMessage } : step
        )
      );
    } finally {
      setAnalyzing(false);
    }
  }, [initializePipeline, updatePipelineStep]);

  const reset = useCallback(() => {
    setAnalyzing(false);
    setResult(null);
    setError(null);
    setPipeline([]);
  }, []);

  return {
    analyzing,
    result,
    error,
    pipeline,
    analyzeFile,
    reset,
  };
};
