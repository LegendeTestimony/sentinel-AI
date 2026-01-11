import { useState, useEffect } from 'react';
import { Shield, Play, Square, Activity, Clock, FileWarning, Lock, Brain, ArrowLeft, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import toast, { Toaster } from 'react-hot-toast';
import sentinelApi from '../api/sentinelApi';

interface MarathonMetrics {
    startTime: string;
    filesAnalyzed: number;
    threatsDetected: number;
    falsePositives: number;
    quarantined: number;
    uptime: number;
    learningIterations: number;
}

interface MarathonStatus {
    running: boolean;
    metrics?: MarathonMetrics;
    message?: string;
}

interface FileAnalysisSummary {
    id: string;
    filename: string;
    threatLevel: string;
    confidence: number;
    timestamp: Date;
    quarantined: boolean;
}

export function MarathonPage() {
    const navigate = useNavigate();
    const [watchPath, setWatchPath] = useState('');
    const [duration, setDuration] = useState(3600000); // 1 hour default
    const [status, setStatus] = useState<MarathonStatus>({ running: false });
    const [loading, setLoading] = useState(false);
    const [analyzedFiles, setAnalyzedFiles] = useState<FileAnalysisSummary[]>([]);

    // Poll status every 2 seconds when running
    useEffect(() => {
        let interval: NodeJS.Timeout;

        if (status.running) {
            interval = setInterval(async () => {
                try {
                    const data = await sentinelApi.getMarathonStatus();
                    setStatus(data);

                    // Update analyzed files from recent analyses
                    if (data.metrics?.recentAnalyses) {
                        setAnalyzedFiles(data.metrics.recentAnalyses);
                    }
                } catch (error) {
                    console.error('Failed to fetch status:', error);
                }
            }, 2000);
        }

        return () => {
            if (interval) clearInterval(interval);
        };
    }, [status.running]);

    const handleStart = async () => {
        if (!watchPath.trim()) {
            toast.error('Please enter a directory path to monitor');
            return;
        }

        setLoading(true);

        try {
            const data = await sentinelApi.startMarathon(watchPath.trim(), duration);

            if (data.success) {
                toast.success('Marathon Agent started! 🏃');
                setStatus({ running: true });
            } else {
                toast.error(data.message || 'Failed to start marathon');
            }
        } catch (error: any) {
            toast.error(error.response?.data?.error || 'Failed to connect to backend');
            console.error('Start error:', error);
        } finally {
            setLoading(false);
        }
    };

    const handleStop = async () => {
        setLoading(true);

        try {
            const data = await sentinelApi.stopMarathon();

            if (data.success) {
                toast.success('Marathon Agent stopped');
                setStatus({ running: false, metrics: data.finalMetrics });
            } else {
                toast.error('Failed to stop marathon');
            }
        } catch (error: any) {
            toast.error(error.response?.data?.error || 'Failed to connect to backend');
            console.error('Stop error:', error);
        } finally {
            setLoading(false);
        }
    };

    const formatUptime = (seconds: number): string => {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    };

    return (
        <div className="min-h-screen bg-sentinel-bg text-gray-100 flex flex-col">
            <Toaster position="top-right" />

            {/* Header */}
            <header className="bg-sentinel/50 backdrop-blur-sm sticky top-0 z-10 border-b border-sentinel-border">
                <div className="container mx-auto px-4 py-4">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <button
                                onClick={() => navigate('/')}
                                className="p-2 hover:bg-sentinel-border rounded-lg transition"
                                title="Go back to home"
                            >
                                <ArrowLeft className="w-5 h-5" />
                            </button>
                            <Activity className="w-8 h-8 text-threat-safe" />
                            <div>
                                <h1 className="text-2xl font-bold">Marathon Mode</h1>
                                <p className="text-sm text-gray-400">Continuous Autonomous Security Monitoring</p>
                            </div>
                        </div>

                        {status.running && (
                            <div className="flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500/50 rounded-full">
                                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                                <span className="text-sm font-semibold text-green-300">ACTIVE</span>
                            </div>
                        )}
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="flex-1 flex overflow-hidden">
                <div className="flex-1 overflow-y-auto">
                    <div className="container mx-auto px-4 py-8">
                        {/* Info Banner */}
                        <div className="max-w-4xl mx-auto mb-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                            <div className="flex items-start gap-3">
                                <Activity className="w-5 h-5 text-blue-400 mt-1 flex-shrink-0" />
                                <div>
                                    <h3 className="font-semibold text-blue-300 mb-1">What is Marathon Mode?</h3>
                                    <p className="text-sm text-gray-400 mb-2">
                                        Marathon Mode continuously monitors a directory (like Downloads) and automatically analyzes <strong>new files</strong> as they appear.
                                        Perfect for real-time download protection.
                                    </p>
                                    <p className="text-xs text-blue-300">
                                        💡 Token-saving: Only NEW files are analyzed. Existing files are ignored.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Control Panel */}
                        <div className="max-w-4xl mx-auto">
                            <motion.div
                                initial={{ opacity: 0, y: 20 }}
                                animate={{ opacity: 1, y: 0 }}
                                className="bg-sentinel-card border border-sentinel-border rounded-lg p-6 mb-8"
                            >
                                <h2 className="text-xl font-bold mb-6">Control Panel</h2>

                                {!status.running ? (
                                    <div className="space-y-6">
                                        {/* Directory Input */}
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                                Directory to Monitor
                                            </label>
                                            <input
                                                type="text"
                                                value={watchPath}
                                                onChange={(e) => setWatchPath(e.target.value)}
                                                placeholder="C:/Users/YourName/Downloads"
                                                className="w-full px-4 py-3 bg-sentinel-bg border border-sentinel-border rounded-lg text-gray-100 placeholder-gray-500 focus:border-threat-safe focus:outline-none"
                                                disabled={loading}
                                            />
                                            <p className="text-xs text-gray-500 mt-2">
                                                💡 Only NEW files will be analyzed (existing files ignored to save tokens)
                                            </p>
                                        </div>

                                        {/* Duration Input */}
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-2">
                                                Duration (optional)
                                            </label>
                                            <select
                                                value={duration}
                                                onChange={(e) => setDuration(Number(e.target.value))}
                                                className="w-full px-4 py-3 bg-sentinel-bg border border-sentinel-border rounded-lg text-gray-100 focus:border-threat-safe focus:outline-none"
                                                disabled={loading}
                                                title="Select the duration for marathon monitoring"
                                            >
                                                <option value={300000}>5 minutes (demo)</option>
                                                <option value={900000}>15 minutes</option>
                                                <option value={1800000}>30 minutes</option>
                                                <option value={3600000}>1 hour</option>
                                                <option value={7200000}>2 hours</option>
                                                <option value={86400000}>24 hours</option>
                                                <option value={0}>Run indefinitely</option>
                                            </select>
                                        </div>

                                        {/* Start Button */}
                                        <button
                                            onClick={handleStart}
                                            disabled={loading || !watchPath.trim()}
                                            className="w-full flex items-center justify-center gap-2 px-6 py-4 bg-threat-safe hover:bg-threat-safe/90 text-black font-bold rounded-lg transition-all transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                                        >
                                            <Play className="w-5 h-5" />
                                            {loading ? 'Starting...' : 'Start Marathon Agent'}
                                        </button>
                                    </div>
                                ) : (
                                    <div className="space-y-4">
                                        {/* Running Info */}
                                        <div className="p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
                                            <div className="flex items-center gap-2 mb-2">
                                                <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse" />
                                                <span className="font-semibold text-green-300">Marathon Agent is Running</span>
                                            </div>
                                            <p className="text-sm text-gray-400">
                                                Monitoring: <span className="font-mono text-gray-300">{watchPath}</span>
                                            </p>
                                        </div>

                                        {/* Stop Button */}
                                        <button
                                            onClick={handleStop}
                                            disabled={loading}
                                            className="w-full flex items-center justify-center gap-2 px-6 py-4 bg-red-500 hover:bg-red-600 text-white font-bold rounded-lg transition-all"
                                        >
                                            <Square className="w-5 h-5" />
                                            {loading ? 'Stopping...' : 'Stop Marathon Agent'}
                                        </button>
                                    </div>
                                )}
                            </motion.div>

                            {/* Metrics Dashboard */}
                            {status.metrics && (
                                <motion.div
                                    initial={{ opacity: 0, y: 20 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: 0.2 }}
                                    className="bg-sentinel-card border border-sentinel-border rounded-lg p-6"
                                >
                                    <h2 className="text-xl font-bold mb-6">Real-Time Metrics</h2>

                                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                                        {/* Uptime */}
                                        <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4">
                                            <div className="flex items-center gap-2 mb-2">
                                                <Clock className="w-5 h-5 text-blue-400" />
                                                <span className="text-sm text-gray-400">Uptime</span>
                                            </div>
                                            <p className="text-2xl font-bold text-blue-300">
                                                {formatUptime(status.metrics.uptime)}
                                            </p>
                                        </div>

                                        {/* Files Analyzed */}
                                        <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4">
                                            <div className="flex items-center gap-2 mb-2">
                                                <Shield className="w-5 h-5 text-green-400" />
                                                <span className="text-sm text-gray-400">Files Analyzed</span>
                                            </div>
                                            <p className="text-2xl font-bold text-green-300">
                                                {status.metrics.filesAnalyzed}
                                            </p>
                                        </div>

                                        {/* Threats Detected */}
                                        <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4">
                                            <div className="flex items-center gap-2 mb-2">
                                                <FileWarning className="w-5 h-5 text-red-400" />
                                                <span className="text-sm text-gray-400">Threats</span>
                                            </div>
                                            <p className="text-2xl font-bold text-red-300">
                                                {status.metrics.threatsDetected}
                                            </p>
                                        </div>

                                        {/* Quarantined */}
                                        <div className="bg-sentinel-bg border border-sentinel-border rounded-lg p-4">
                                            <div className="flex items-center gap-2 mb-2">
                                                <Lock className="w-5 h-5 text-yellow-400" />
                                                <span className="text-sm text-gray-400">Quarantined</span>
                                            </div>
                                            <p className="text-2xl font-bold text-yellow-300">
                                                {status.metrics.quarantined}
                                            </p>
                                        </div>
                                    </div>

                                    {/* Learning Stats */}
                                    <div className="mt-6 p-4 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                                        <div className="flex items-center gap-2 mb-2">
                                            <Brain className="w-5 h-5 text-purple-400" />
                                            <span className="font-semibold text-purple-300">Learning Progress</span>
                                        </div>
                                        <p className="text-sm text-gray-400">
                                            {status.metrics.learningIterations} baseline adjustments made
                                        </p>
                                    </div>

                                    {/* Auto-refresh indicator */}
                                    <div className="mt-4 text-center">
                                        <p className="text-xs text-gray-500">
                                            📊 Metrics update every 2 seconds
                                        </p>
                                    </div>
                                </motion.div>
                            )}

                            {/* Instructions */}
                            {!status.running && (
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 0.3 }}
                                    className="mt-8 max-w-4xl mx-auto"
                                >
                                    <h3 className="text-lg font-semibold mb-4">How to Use</h3>
                                    <div className="space-y-3 text-sm text-gray-400">
                                        <div className="flex items-start gap-2">
                                            <span className="text-threat-safe font-bold">1.</span>
                                            <p>Enter the full path to a directory you want to monitor (e.g., your Downloads folder)</p>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <span className="text-threat-safe font-bold">2.</span>
                                            <p>Choose how long you want the agent to run (or select "indefinitely")</p>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <span className="text-threat-safe font-bold">3.</span>
                                            <p>Click "Start Marathon Agent" - it will wait for NEW files only</p>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <span className="text-threat-safe font-bold">4.</span>
                                            <p><strong>Download or add NEW files</strong> to the monitored directory</p>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <span className="text-threat-safe font-bold">5.</span>
                                            <p>Watch instant analysis - suspicious files auto-quarantined</p>
                                        </div>
                                        <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                                            <p className="text-xs text-yellow-300">
                                                ⚠️ Existing files are NOT scanned (saves tokens). Only files added AFTER starting will be analyzed.
                                            </p>
                                        </div>
                                    </div>
                                </motion.div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Side Panel - Recent Analyses */}
                <AnimatePresence>
                    {status.running && analyzedFiles.length > 0 && (
                        <motion.aside
                            initial={{ x: 400, opacity: 0 }}
                            animate={{ x: 0, opacity: 1 }}
                            exit={{ x: 400, opacity: 0 }}
                            transition={{ duration: 0.3 }}
                            className="w-96 bg-dark-800/90 border-l border-dark-700 overflow-y-auto"
                        >
                            <div className="sticky top-0 bg-dark-800/95 backdrop-blur-sm border-b border-dark-700 p-4 z-10">
                                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                                    <Activity className="w-5 h-5 text-primary-cyan" />
                                    Recent Analyses
                                </h3>
                                <p className="text-xs text-dark-300 mt-1">
                                    Live feed of scanned files
                                </p>
                            </div>

                            <div className="p-4 space-y-3">
                                {analyzedFiles.map((file) => {
                                    const getThreatIcon = () => {
                                        switch (file.threatLevel) {
                                            case 'CRITICAL':
                                            case 'HIGH':
                                                return <XCircle className="w-5 h-5 text-threat-critical" />;
                                            case 'MEDIUM':
                                                return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
                                            default:
                                                return <CheckCircle className="w-5 h-5 text-threat-safe" />;
                                        }
                                    };

                                    const getThreatColor = () => {
                                        switch (file.threatLevel) {
                                            case 'CRITICAL':
                                                return 'border-threat-critical bg-red-950/30';
                                            case 'HIGH':
                                                return 'border-red-600/60 bg-red-950/20';
                                            case 'MEDIUM':
                                                return 'border-yellow-600/60 bg-yellow-950/20';
                                            default:
                                                return 'border-dark-600 bg-dark-750/50';
                                        }
                                    };

                                    return (
                                        <motion.div
                                            key={file.id}
                                            initial={{ y: -20, opacity: 0 }}
                                            animate={{ y: 0, opacity: 1 }}
                                            className={`p-3 border rounded-lg ${getThreatColor()} transition-colors`}
                                        >
                                            <div className="flex items-start justify-between gap-2 mb-2">
                                                <div className="flex items-center gap-2 flex-1 min-w-0">
                                                    {getThreatIcon()}
                                                    <span className="text-sm font-medium text-white truncate">
                                                        {file.filename}
                                                    </span>
                                                </div>
                                                {file.quarantined && (
                                                    <Lock className="w-4 h-4 text-yellow-500 flex-shrink-0" />
                                                )}
                                            </div>

                                            <div className="space-y-1 text-xs">
                                                <div className="flex justify-between">
                                                    <span className="text-dark-300">Threat:</span>
                                                    <span className={`font-semibold ${file.threatLevel === 'CRITICAL' ? 'text-threat-critical' :
                                                        file.threatLevel === 'HIGH' ? 'text-red-400' :
                                                            file.threatLevel === 'MEDIUM' ? 'text-yellow-400' :
                                                                'text-threat-safe'
                                                        }`}>
                                                        {file.threatLevel}
                                                    </span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-dark-300">Confidence:</span>
                                                    <span className="text-white font-medium">
                                                        {(file.confidence * 100).toFixed(0)}%
                                                    </span>
                                                </div>
                                                <div className="flex justify-between">
                                                    <span className="text-dark-300">Time:</span>
                                                    <span className="text-white">
                                                        {new Date(file.timestamp).toLocaleTimeString()}
                                                    </span>
                                                </div>
                                                {file.quarantined && (
                                                    <div className="mt-2 pt-2 border-t border-yellow-500/30">
                                                        <span className="text-yellow-400 font-medium">🔒 Quarantined</span>
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    );
                                })}
                            </div>
                        </motion.aside>
                    )}
                </AnimatePresence>
            </main>
        </div>
    );
}
