import { useState, useCallback } from 'react';
import { sentinelApi } from '../api/sentinelApi';
import type { AnalysisResult, AnalysisPipelineStep } from '../types/analysis';

export const useFileAnalysis = () => {
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pipeline, setPipeline] = useState<AnalysisPipelineStep[]>([]);
  const [progress, setProgress] = useState(0); // 0-100

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
    setPipeline(prev => {
      const updated = prev.map(step =>
        step.id === stepId ? { ...step, status, message } : step
      );
      
      // Calculate progress
      const completed = updated.filter(s => s.status === 'complete').length;
      const total = updated.length;
      setProgress((completed / total) * 100);
      
      return updated;
    });
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

  const analyzeURL = useCallback(async (url: string) => {
    setAnalyzing(true);
    setError(null);
    setResult(null);

    setPipeline([
      { id: 'fetch', label: 'Fetching URL', status: 'active' },
      { id: 'redirect', label: 'Following redirects', status: 'pending' },
      { id: 'download', label: 'Downloading content', status: 'pending' },
      { id: 'analyze', label: 'Analyzing content', status: 'pending' },
      { id: 'gemini', label: 'AI threat analysis', status: 'pending' },
    ]);

    try {
      updatePipelineStep('fetch', 'complete');
      updatePipelineStep('redirect', 'active');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('redirect', 'complete');
      updatePipelineStep('download', 'active');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('download', 'complete');
      updatePipelineStep('analyze', 'active');

      // Actual API call
      const analysisResult = await sentinelApi.analyzeURL(url);

      updatePipelineStep('analyze', 'complete');
      updatePipelineStep('gemini', 'active');

      await new Promise(resolve => setTimeout(resolve, 300));
      updatePipelineStep('gemini', 'complete');

      setResult(analysisResult);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'URL analysis failed';
      setError(errorMessage);

      setPipeline(prev =>
        prev.map(step =>
          step.status === 'active' ? { ...step, status: 'error', message: errorMessage } : step
        )
      );
    } finally {
      setAnalyzing(false);
    }
  }, [updatePipelineStep]);

  const reset = useCallback(() => {
    setAnalyzing(false);
    setResult(null);
    setError(null);
    setPipeline([]);
    setProgress(0);
  }, []);

  return {
    analyzing,
    result,
    error,
    pipeline,
    progress,
    analyzeFile,
    analyzeURL,
    reset,
  };
};
