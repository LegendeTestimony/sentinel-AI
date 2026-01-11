import React, { useState } from 'react';
import { Link, AlertCircle } from 'lucide-react';

interface URLInputProps {
  onURLSubmit: (url: string) => void;
  disabled?: boolean;
}

export const URLInput: React.FC<URLInputProps> = ({ onURLSubmit, disabled = false }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const validateURL = (input: string): boolean => {
    try {
      const urlObj = new URL(input);
      return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
      return false;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    if (!validateURL(url)) {
      setError('Please enter a valid HTTP/HTTPS URL');
      return;
    }

    onURLSubmit(url);
    setUrl('');
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div className="relative">
          <div className="absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none">
            <Link className="w-5 h-5 text-gray-400" />
          </div>

          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setError('');
            }}
            placeholder="Enter URL to analyze (e.g., https://example.com)"
            disabled={disabled}
            className="w-full pl-12 pr-4 py-4 bg-sentinel-card border-2 border-sentinel-border rounded-lg text-gray-100 placeholder-gray-500 focus:border-threat-safe focus:outline-none transition disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4" />
            <span>{error}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={disabled || !url.trim()}
          className="px-6 py-3 bg-threat-safe hover:bg-threat-safe/90 text-black font-semibold rounded-lg transition-all transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
        >
          Analyze URL
        </button>
      </form>
    </div>
  );
};
