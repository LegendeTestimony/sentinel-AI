import { useState, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import { Shield, ArrowLeft, FileCode } from 'lucide-react';
import { motion } from 'framer-motion';
import { Toaster, toast } from 'react-hot-toast';
import { AnalysisPipeline } from '../components/AnalysisPipeline';
import { ThreatCard } from '../components/ThreatCard';
import { AnalysisSidePanel } from '../components/AnalysisSidePanel';
import { ProgressBar } from '../components/ProgressBar';
import { ExportReport } from '../components/ExportReport';
import { saveToHistory } from '../components/AnalysisHistory';
import { useFileAnalysis } from '../hooks/useFileAnalysis';

export function ResultsPage() {
    const location = useLocation();
    const navigate = useNavigate();
    const [sidePanelOpen, setSidePanelOpen] = useState(false);
    const { analyzing, result, error, pipeline, progress, analyzeFile, analyzeURL } = useFileAnalysis();

    useEffect(() => {
        // Get data from navigation state
        const state = location.state as { file?: File; url?: string; mode?: 'file' | 'url' } | null;

        if (!state) {
            // No data, redirect to home
            navigate('/');
            return;
        }

        // Start analysis based on mode
        if (state.mode === 'file' && state.file) {
            analyzeFile(state.file);
        } else if (state.mode === 'url' && state.url) {
            analyzeURL(state.url);
        }
    }, [location.state, navigate, analyzeFile, analyzeURL]);

    // Save to history when analysis completes
    useEffect(() => {
        if (result && !analyzing) {
            saveToHistory(result);
            toast.success('Analysis complete!');
        }
    }, [result, analyzing]);

    const handleAnalyzeAnother = () => {
        navigate('/');
    };

    return (
        <div className="min-h-screen bg-sentinel-bg text-gray-100">
            <Toaster
                position="top-right"
                toastOptions={{
                    style: {
                        background: '#1e293b',
                        color: '#f8fafc',
                        border: '1px solid #334155',
                    },
                }}
            />

            {/* Header */}
            <motion.header
                initial={{ y: -20, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                className="bg-sentinel/50 backdrop-blur-sm sticky top-0 z-10 border-b border-sentinel-border"
            >
                <div className="container mx-auto px-4 py-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <Shield className="w-8 h-8 text-threat-safe" />
                            <div>
                                <h1 className="text-2xl font-bold">SENTINEL</h1>
                                <p className="text-sm text-gray-400">AI-Powered Predictive File Security</p>
                            </div>
                        </div>

                        <Link
                            to="/"
                            className="flex items-center gap-2 px-4 py-2 bg-sentinel-card border border-sentinel-border hover:bg-sentinel-border text-gray-300 rounded-full transition"
                        >
                            <ArrowLeft className="w-4 h-4" />
                            Back to Home
                        </Link>
                    </div>
                </div>
            </motion.header>

            {/* Main Content */}
            <main className="container mx-auto px-4 py-8">
                {/* Progress Bar */}
                {analyzing && progress > 0 && (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mb-8"
                    >
                        <ProgressBar
                            progress={progress}
                            status={pipeline.find(s => s.status === 'active')?.label || 'Analyzing...'}
                        />
                    </motion.div>
                )}

                {/* Analysis Pipeline */}
                {pipeline.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="max-w-3xl mx-auto mb-8"
                    >
                        <AnalysisPipeline steps={pipeline} />
                    </motion.div>
                )}

                {/* Loading State */}
                {analyzing && (
                    <motion.div
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        className="max-w-3xl mx-auto text-center py-12"
                    >
                        <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-threat-safe mb-4"></div>
                        <p className="text-gray-400">Analyzing file with Gemini AI...</p>
                        <p className="text-sm text-gray-500 mt-2">This may take a few moments</p>
                    </motion.div>
                )}

                {/* Error Display */}
                {error && (
                    <motion.div
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        className="max-w-3xl mx-auto mb-8 p-4 bg-red-500/10 border border-red-500/30 rounded-lg"
                    >
                        <p className="text-red-400 text-center">
                            <strong>Analysis Error:</strong> {error}
                        </p>
                        <div className="mt-4 flex justify-center">
                            <button
                                onClick={handleAnalyzeAnother}
                                className="px-6 py-2 bg-sentinel-card border border-sentinel-border hover:bg-sentinel-border text-gray-300 rounded-full transition"
                            >
                                Try Another File
                            </button>
                        </div>
                    </motion.div>
                )}

                {/* Results */}
                {result && !analyzing && (
                    <motion.div
                        initial={{ scale: 0.95, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ delay: 0.2 }}
                        className="max-w-4xl mx-auto"
                    >
                        <ThreatCard
                            threat={result.threat}
                            fileName={result.file.filename}
                            steganography={result.steganography}
                        />

                        <div className="mt-6 flex flex-wrap justify-center gap-4">
                            <button
                                onClick={() => setSidePanelOpen(true)}
                                className="flex items-center gap-2 px-6 py-2 bg-threat-safe/20 border border-threat-safe/50 hover:bg-threat-safe/30 text-threat-safe font-semibold rounded-full transition"
                            >
                                <FileCode className="w-4 h-4" />
                                View Technical Details
                            </button>

                            <ExportReport result={result} />

                            <button
                                onClick={handleAnalyzeAnother}
                                className="px-6 py-2 bg-sentinel-card border border-sentinel-border hover:bg-sentinel-border text-gray-300 rounded-full transition"
                            >
                                Analyze Another File
                            </button>
                        </div>
                    </motion.div>
                )}
            </main>

            {/* Side Panel */}
            <AnalysisSidePanel
                result={result}
                isOpen={sidePanelOpen}
                onClose={() => setSidePanelOpen(false)}
            />
        </div>
    );
}
