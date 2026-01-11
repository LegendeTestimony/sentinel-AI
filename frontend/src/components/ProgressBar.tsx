import { motion } from 'framer-motion';

interface ProgressBarProps {
    progress: number; // 0-100
    status?: string;
}

export function ProgressBar({ progress, status }: ProgressBarProps) {
    return (
        <div className="w-full max-w-3xl mx-auto">
            <div className="mb-2 flex justify-between items-center">
                <span className="text-sm font-medium text-gray-300">
                    {status || 'Analyzing...'}
                </span>
                <span className="text-sm font-mono text-threat-safe">
                    {Math.round(progress)}%
                </span>
            </div>

            <div className="w-full h-2 bg-sentinel-card rounded-full overflow-hidden border border-sentinel-border">
                <motion.div
                    className="h-full bg-gradient-to-r from-threat-safe to-blue-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${progress}%` }}
                    transition={{ duration: 0.3, ease: 'easeOut' }}
                />
            </div>
        </div>
    );
}
