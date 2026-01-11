import { Shield, Github, Terminal, GitCompare } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FileUpload } from '../components/FileUpload';
import { URLInput } from '../components/URLInput';
import { AnalysisHistory } from '../components/AnalysisHistory';
import { Upload, Link, AlertTriangle } from 'lucide-react';
import type { AnalysisResult } from '../types/analysis';

type AnalysisMode = 'file' | 'url';

export function HomePage() {
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [mode, setMode] = useState<AnalysisMode>('file');
    const navigate = useNavigate();

    const handleFileSelect = (file: File) => {
        setSelectedFile(file);
    };

    const handleAnalyze = () => {
        if (selectedFile) {
            // Navigate to results page with file
            navigate('/results', { state: { file: selectedFile, mode: 'file' } });
        }
    };

    const handleURLSubmit = (url: string) => {
        // Navigate to results page with URL
        navigate('/results', { state: { url, mode: 'url' } });
    };

    const handleModeChange = (newMode: AnalysisMode) => {
        setMode(newMode);
        setSelectedFile(null);
    };

    const handleSelectFromHistory = (result: AnalysisResult) => {
        // Navigate to results page with cached result
        navigate('/results', { state: { result } });
    };

    return (
        <div className="min-h-screen bg-sentinel-bg text-gray-100">
            {/* Header */}
            <header className="bg-sentinel/50 backdrop-blur-sm sticky top-0 z-10">
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
                            <button
                                type="button"
                                onClick={() => navigate('/marathon')}
                                className="flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 text-green-300 rounded-lg transition font-semibold text-sm"
                            >
                                <Terminal className="w-4 h-4" />
                                Marathon Mode
                            </button>
                            <button
                                type="button"
                                onClick={() => navigate('/compare')}
                                className="flex items-center gap-2 px-4 py-2 bg-blue-500/20 border border-blue-500/50 hover:bg-blue-500/30 text-blue-300 rounded-lg transition font-semibold text-sm"
                            >
                                <GitCompare className="w-4 h-4" />
                                Compare Files
                            </button>
                            <a
                                href="https://github.com"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-gray-400 hover:text-gray-300 transition"
                                aria-label="View on GitHub"
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
                    {/* Mode Tabs */}
                    <div className="flex gap-2 mb-6 bg-sentinel-card border border-sentinel-border rounded-full p-3">
                        <button
                            type="button"
                            onClick={() => handleModeChange('file')}
                            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-full font-semibold transition cursor-pointer  ${mode === 'file'
                                ? 'bg-threat-safe text-black'
                                : 'text-gray-400 hover:text-gray-300'
                                }`}
                        >
                            <Upload className="w-4 h-4" />
                            Upload File
                        </button>
                        <button
                            type="button"
                            onClick={() => handleModeChange('url')}
                            className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-full font-semibold transition cursor-pointer ${mode === 'url'
                                ? 'bg-threat-safe text-black'
                                : 'text-gray-400 hover:text-gray-300'
                                }`}
                        >
                            <Link className="w-4 h-4" />
                            Analyze URL
                        </button>
                    </div>

                    {/* File Upload Mode */}
                    {mode === 'file' && (
                        <>
                            <FileUpload onFileSelect={handleFileSelect} disabled={false} />

                            {selectedFile && (
                                <div className="mt-6 flex justify-center">
                                    <button
                                        type="button"
                                        onClick={handleAnalyze}
                                        className="px-8 py-3 bg-threat-safe hover:bg-threat-safe/90 text-black font-semibold rounded-full transition-all transform hover:scale-105"
                                    >
                                        Analyze Threat
                                    </button>
                                </div>
                            )}
                        </>
                    )}

                    {/* URL Analysis Mode */}
                    {mode === 'url' && (
                        <URLInput onURLSubmit={handleURLSubmit} disabled={false} />
                    )}
                </div>

                {/* Analysis History */}
                <AnalysisHistory onSelectAnalysis={handleSelectFromHistory} />

                {/* Features Section */}
                <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="max-w-5xl mx-auto mt-16 grid grid-cols-1 md:grid-cols-3 gap-6"
                >
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
                </motion.div>
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
