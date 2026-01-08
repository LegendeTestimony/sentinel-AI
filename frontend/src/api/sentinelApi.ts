import axios from 'axios';
import type { AnalysisResult } from '../types/analysis';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const sentinelApi = {
  async analyzeFile(file: File): Promise<AnalysisResult> {
    const formData = new FormData();
    formData.append('file', file);

    const response = await api.post<AnalysisResult>('/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });

    return response.data;
  },

  async healthCheck(): Promise<{ status: string; timestamp: number }> {
    const response = await api.get('/health');
    return response.data;
  },
};

export default sentinelApi;
