import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowLeft, GitCompare } from 'lucide-react';
import { FileUpload } from '../components/FileUpload';
import { ThreatCard } from '../components/ThreatCard';
import { useFileAnalysis } from '../hooks/useFileAnalysis';
import type { AnalysisResult } from '../types/analysis';

export function ComparisonPage() {
  const navigate = useNavigate();
  const [fileA, setFileA] = useState<File | null>(null);
  const [fileB, setFileB] = useState<File | null>(null);
  const [resultA, setResultA] = useState<AnalysisResult | null>(null);
  const [resultB, setResultB] = useState<AnalysisResult | null>(null);
  const [analyzingA, setAnalyzingA] = useState(false);
  const [analyzingB, setAnalyzingB] = useState(false);

  const { analyzeFile } = useFileAnalysis();

  const handleAnalyzeA = async () => {
    if (!fileA) return;
    setAnalyzingA(true);
    setResultA(null);

    try {
      const result = await analyzeFile(fileA);
      setResultA(result as any);
    } catch (error) {
      console.error('Error analyzing File A:', error);
    } finally {
      setAnalyzingA(false);
    }
  };

  const handleAnalyzeB = async () => {
    if (!fileB) return;
    setAnalyzingB(true);
    setResultB(null);

    try {
      const result = await analyzeFile(fileB);
      setResultB(result as any);
    } catch (error) {
      console.error('Error analyzing File B:', error);
    } finally {
      setAnalyzingB(false);
    }
  };

  const handleAnalyzeBoth = async () => {
    if (!fileA || !fileB) return;

    // Analyze both files in parallel
    setAnalyzingA(true);
    setAnalyzingB(true);
    setResultA(null);
    setResultB(null);

    try {
      const [resA, resB] = await Promise.all([
        analyzeFile(fileA),
        analyzeFile(fileB),
      ]);
      setResultA(resA as any);
      setResultB(resB as any);
    } catch (error) {
      console.error('Error analyzing files:', error);
    } finally {
      setAnalyzingA(false);
      setAnalyzingB(false);
    }
  };

  const getThreatLevelScore = (level: string): number => {
    switch (level) {
      case 'CRITICAL': return 5;
      case 'HIGH': return 4;
      case 'MEDIUM': return 3;
      case 'LOW': return 2;
      case 'SAFE': return 1;
      default: return 0;
    }
  };

  const renderComparison = () => {
    if (!resultA || !resultB) return null;

    const scoreA = getThreatLevelScore(resultA.threat.level);
    const scoreB = getThreatLevelScore(resultB.threat.level);

    return (
      <div className="mb-8 p-6 bg-blue-500/10 border border-blue-500/30 rounded-lg">
        <div className="flex items-center gap-2 mb-4">
          <GitCompare className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-semibold text-blue-300">Comparison Summary</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Threat Level Comparison */}
          <div>
            <p className="text-sm text-gray-400 mb-2">Threat Level</p>
            <div className="flex items-center justify-between">
              <span className={`font-bold ${
                scoreA > scoreB ? 'text-red-400' : scoreA < scoreB ? 'text-green-400' : 'text-gray-300'
              }`}>
                {resultA.threat.level}
              </span>
              <span className="text-gray-500">vs</span>
              <span className={`font-bold ${
                scoreB > scoreA ? 'text-red-400' : scoreB < scoreA ? 'text-green-400' : 'text-gray-300'
              }`}>
                {resultB.threat.level}
              </span>
            </div>
          </div>

          {/* Confidence Comparison */}
          <div>
            <p className="text-sm text-gray-400 mb-2">Confidence</p>
            <div className="flex items-center justify-between">
              <span className="font-bold text-gray-300">{resultA.threat.confidence}%</span>
              <span className="text-gray-500">vs</span>
              <span className="font-bold text-gray-300">{resultB.threat.confidence}%</span>
            </div>
          </div>

          {/* File Size Comparison */}
          <div>
            <p className="text-sm text-gray-400 mb-2">File Size</p>
            <div className="flex items-center justify-between">
              <span className="font-bold text-gray-300">{(resultA.file.size / 1024).toFixed(1)} KB</span>
              <span className="text-gray-500">vs</span>
              <span className="font-bold text-gray-300">{(resultB.file.size / 1024).toFixed(1)} KB</span>
            </div>
          </div>
        </div>

        {/* Key Differences */}
        <div className="mt-4 pt-4 border-t border-blue-500/30">
          <p className="text-sm font-semibold text-gray-300 mb-2">Key Differences:</p>
          <ul className="text-sm text-gray-400 space-y-1">
            {resultA.steganography?.detected && !resultB.steganography?.detected && (
              <li>• File A contains hidden data, File B does not</li>
            )}
            {!resultA.steganography?.detected && resultB.steganography?.detected && (
              <li>• File B contains hidden data, File A does not</li>
            )}
            {resultA.threat.virusTotal?.found && resultB.threat.virusTotal?.found && (
              <li>
                • VirusTotal: File A ({resultA.threat.virusTotal.detections}/{resultA.threat.virusTotal.totalEngines}) vs
                File B ({resultB.threat.virusTotal.detections}/{resultB.threat.virusTotal.totalEngines})
              </li>
            )}
            {scoreA !== scoreB && (
              <li>
                • {scoreA > scoreB ? 'File A is more dangerous' : 'File B is more dangerous'} ({Math.abs(scoreA - scoreB)} level{Math.abs(scoreA - scoreB) > 1 ? 's' : ''} higher)
              </li>
            )}
          </ul>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-sentinel-bg text-gray-100">
      {/* Header */}
      <header className="bg-sentinel/50 backdrop-blur-sm sticky top-0 z-10 border-b border-sentinel-border">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => navigate('/')}
                className="p-2 hover:bg-sentinel-border rounded-lg transition"
                title="Go back to home page"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <Shield className="w-8 h-8 text-threat-safe" />
              <div>
                <h1 className="text-2xl font-bold">File Comparison Mode</h1>
                <p className="text-sm text-gray-400">Analyze two files side-by-side</p>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Instructions */}
        <div className="max-w-5xl mx-auto mb-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <div className="flex items-start gap-3">
            <GitCompare className="w-5 h-5 text-blue-400 mt-1" />
            <div>
              <h3 className="font-semibold text-blue-300 mb-1">How to Use Comparison Mode</h3>
              <p className="text-sm text-gray-400">
                Upload two files to compare their threat levels, behavior predictions, and security indicators side-by-side.
                Perfect for comparing malicious samples with benign files, or analyzing different versions of the same file.
              </p>
            </div>
          </div>
        </div>

        {/* File Upload Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-6xl mx-auto mb-8">
          {/* File A */}
          <div>
            <h3 className="text-lg font-semibold mb-4 text-cyan-300">File A</h3>
            <FileUpload
              onFileSelect={setFileA}
              disabled={analyzingA || analyzingB}
            />
            {fileA && !resultA && !analyzingA && (
              <button
                type="button"
                onClick={handleAnalyzeA}
                className="mt-4 w-full px-6 py-3 bg-cyan-500 hover:bg-cyan-600 text-black font-semibold rounded-lg transition"
              >
                Analyze File A
              </button>
            )}
          </div>

          {/* File B */}
          <div>
            <h3 className="text-lg font-semibold mb-4 text-purple-300">File B</h3>
            <FileUpload
              onFileSelect={setFileB}
              disabled={analyzingA || analyzingB}
            />
            {fileB && !resultB && !analyzingB && (
              <button
                type="button"
                onClick={handleAnalyzeB}
                className="mt-4 w-full px-6 py-3 bg-purple-500 hover:bg-purple-600 text-black font-semibold rounded-lg transition"
              >
                Analyze File B
              </button>
            )}
          </div>
        </div>

        {/* Analyze Both Button */}
        {fileA && fileB && !resultA && !resultB && !analyzingA && !analyzingB && (
          <div className="max-w-6xl mx-auto mb-8 text-center">
            <button
              type="button"
              onClick={handleAnalyzeBoth}
              className="px-8 py-4 bg-threat-safe hover:bg-threat-safe/90 text-black font-bold rounded-lg transition-all transform hover:scale-105 text-lg"
            >
              Analyze Both Files
            </button>
          </div>
        )}

        {/* Results Comparison */}
        {renderComparison()}

        {/* Results Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-6xl mx-auto">
          {/* File A Results */}
          <div>
            {analyzingA && (
              <div className="mb-4 text-center text-gray-400">
                Analyzing File A...
              </div>
            )}
            {resultA && (
              <ThreatCard
                threat={resultA.threat}
                fileName={resultA.file.filename}
                steganography={resultA.steganography}
              />
            )}
          </div>

          {/* File B Results */}
          <div>
            {analyzingB && (
              <div className="mb-4 text-center text-gray-400">
                Analyzing File B...
              </div>
            )}
            {resultB && (
              <ThreatCard
                threat={resultB.threat}
                fileName={resultB.file.filename}
                steganography={resultB.steganography}
              />
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
