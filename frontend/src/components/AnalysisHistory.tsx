import { Clock, FileText, AlertTriangle, Shield } from 'lucide-react';
import { motion } from 'framer-motion';
import { AnalysisResult } from '../types/analysis';

interface AnalysisHistoryProps {
    onSelectAnalysis: (result: AnalysisResult) => void;
}

interface HistoryItem {
    id: string;
    filename: string;
    threatLevel: string; // Stored as simple string in localStorage
    timestamp: string;
    result: AnalysisResult;
}

export function AnalysisHistory({ onSelectAnalysis }: AnalysisHistoryProps) {
    const getHistory = (): HistoryItem[] => {
        const stored = localStorage.getItem('sentinel_history');
        return stored ? JSON.parse(stored) : [];
    };

    const history = getHistory().slice(0, 5); // Show last 5

    if (history.length === 0) {
        return null;
    }

    const getThreatIcon = (level: string) => {
        switch (level.toLowerCase()) {
            case 'safe':
                return <Shield className="w-4 h-4 text-threat-safe" />;
            case 'critical':
            case 'high':
                return <AlertTriangle className="w-4 h-4 text-threat-critical" />;
            default:
                return <FileText className="w-4 h-4 text-threat-medium" />;
        }
    };

    const getThreatColor = (level: string) => {
        switch (level.toLowerCase()) {
            case 'safe':
                return 'border-threat-safe/30 bg-threat-safe/5 hover:bg-threat-safe/10';
            case 'critical':
                return 'border-threat-critical/30 bg-threat-critical/5 hover:bg-threat-critical/10';
            case 'high':
                return 'border-threat-high/30 bg-threat-high/5 hover:bg-threat-high/10';
            default:
                return 'border-threat-medium/30 bg-threat-medium/5 hover:bg-threat-medium/10';
        }
    };

    return (
        <div className="max-w-3xl mx-auto mb-8">
            <div className="flex items-center gap-2 mb-4">
                <Clock className="w-5 h-5 text-gray-400" />
                <h3 className="text-lg font-semibold">Recent Analyses</h3>
            </div>

            <div className="space-y-2">
                {history.map((item, index) => (
                    <motion.button
                        key={item.id}
                        type="button"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: index * 0.1 }}
                        onClick={() => onSelectAnalysis(item.result)}
                        className={`w-full p-3 border rounded-lg transition-all text-left ${getThreatColor(item.threatLevel)}`}
                    >
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                {getThreatIcon(item.threatLevel)}
                                <div>
                                    <p className="text-sm font-medium text-gray-200">{item.filename}</p>
                                    <p className="text-xs text-gray-500">{new Date(item.timestamp).toLocaleString()}</p>
                                </div>
                            </div>
                            <span className={`text-xs font-semibold uppercase`}>
                                {item.threatLevel}
                            </span>
                        </div>
                    </motion.button>
                ))}
            </div>
        </div>
    );
}

// Helper function to save to history
export function saveToHistory(result: AnalysisResult) {
    const history = localStorage.getItem('sentinel_history');
    const historyArray: HistoryItem[] = history ? JSON.parse(history) : [];

    const newItem: HistoryItem = {
        id: crypto.randomUUID(),
        filename: result.file.filename,
        threatLevel: result.threat.level, // Use 'level' from ThreatAnalysis
        timestamp: new Date().toISOString(),
        result: result,
    };

    // Add to beginning, keep last 10
    const updated = [newItem, ...historyArray].slice(0, 10);
    localStorage.setItem('sentinel_history', JSON.stringify(updated));
}
