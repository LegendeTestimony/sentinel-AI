import { useState } from 'react';
import { Shield, Github, Terminal, AlertTriangle } from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { AnalysisPipeline } from './components/AnalysisPipeline';
import { ThreatCard } from './components/ThreatCard';
import { useFileAnalysis } from './hooks/useFileAnalysis';

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const { analyzing, result, error, pipeline, analyzeFile, reset } = useFileAnalysis();

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
  };

  const handleAnalyze = () => {
    if (selectedFile) {
      analyzeFile(selectedFile);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    reset();
  };

  return (
    <div className="min-h-screen bg-sentinel-bg text-gray-100">
      {/* Header */}
      <header className="border-b border-sentinel-border bg-sentinel-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-threat-safe" />
              <div>
                <h1 className="text-2xl font-bold">SENTINEL</h1>
                <p className="text-sm text-gray-400">AI-Powered Predictive File Security</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-400 hover:text-gray-300 transition"
              >
                <Github className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-threat-safe/10 border border-threat-safe/30 rounded-full mb-4">
            <Terminal className="w-4 h-4 text-threat-safe" />
            <span className="text-sm text-threat-safe font-mono">Powered by Google Gemini 3</span>
          </div>

          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            Security that thinks like an attacker,
            <br />
            <span className="text-threat-safe">before the attack happens</span>
          </h2>

          <p className="text-gray-400 max-w-2xl mx-auto">
            Advanced AI security analysis using behavioral reasoning and pattern detection to predict
            potential threats before they execute. Upload any file for comprehensive threat assessment.
          </p>
        </div>

        {/* Upload Section */}
        <div className="max-w-3xl mx-auto mb-8">
          <FileUpload onFileSelect={handleFileSelect} disabled={analyzing} />

          {selectedFile && !analyzing && !result && (
            <div className="mt-6 flex justify-center">
              <button
                onClick={handleAnalyze}
                className="px-8 py-3 bg-threat-safe hover:bg-threat-safe/90 text-black font-semibold rounded-lg transition-all transform hover:scale-105"
              >
                Analyze Threat
              </button>
            </div>
          )}
        </div>

        {/* Analysis Pipeline */}
        {pipeline.length > 0 && (
          <div className="max-w-3xl mx-auto mb-8">
            <AnalysisPipeline steps={pipeline} />
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="max-w-3xl mx-auto mb-8 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
            <p className="text-red-400 text-center">
              <strong>Analysis Error:</strong> {error}
            </p>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="max-w-4xl mx-auto">
            <ThreatCard threat={result.threat} fileName={result.file.filename} />

            <div className="mt-6 flex justify-center">
              <button
                onClick={handleReset}
                className="px-6 py-2 bg-sentinel-card border border-sentinel-border hover:bg-sentinel-border text-gray-300 rounded-lg transition"
              >
                Analyze Another File
              </button>
            </div>
          </div>
        )}

        {/* Features Section (shown when no analysis is running) */}
        {!analyzing && !result && (
          <div className="max-w-5xl mx-auto mt-16 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 bg-sentinel-card border border-sentinel-border rounded-lg">
              <div className="w-12 h-12 bg-threat-safe/10 rounded-lg flex items-center justify-center mb-4">
                <Shield className="w-6 h-6 text-threat-safe" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Behavioral Prediction</h3>
              <p className="text-sm text-gray-400">
                Analyzes how files interact with systems and predicts attack vectors before execution
              </p>
            </div>

            <div className="p-6 bg-sentinel-card border border-sentinel-border rounded-lg">
              <div className="w-12 h-12 bg-threat-high/10 rounded-lg flex items-center justify-center mb-4">
                <AlertTriangle className="w-6 h-6 text-threat-high" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Zero-Day Detection</h3>
              <p className="text-sm text-gray-400">
                Identifies novel exploitation techniques through reasoning, even without known signatures
              </p>
            </div>

            <div className="p-6 bg-sentinel-card border border-sentinel-border rounded-lg">
              <div className="w-12 h-12 bg-threat-medium/10 rounded-lg flex items-center justify-center mb-4">
                <Terminal className="w-6 h-6 text-threat-medium" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Explainable Security</h3>
              <p className="text-sm text-gray-400">
                Provides clear technical explanations of threats with natural language reasoning
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-sentinel-border mt-16 py-6">
        <div className="container mx-auto px-4 text-center text-sm text-gray-500">
          <p>Built with Google Gemini 3 • Predictive Security AI</p>
        </div>
      </footer>
    </div>
  );
}

export default App;
