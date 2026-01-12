import React from 'react';
import { X, FileCode, Activity, Eye, Layers, BarChart3, Shield, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import type { AnalysisResult } from '../types/analysis';

interface AnalysisSidePanelProps {
  result: AnalysisResult | null;
  isOpen: boolean;
  onClose: () => void;
}

export const AnalysisSidePanel: React.FC<AnalysisSidePanelProps> = ({ result, isOpen, onClose }) => {
  if (!result) return null;

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return <AlertTriangle className="w-5 h-5 text-red-400" />;
      case 'MEDIUM':
        return <Info className="w-5 h-5 text-yellow-400" />;
      case 'LOW':
        return <CheckCircle className="w-5 h-5 text-blue-400" />;
      case 'SAFE':
        return <Shield className="w-5 h-5 text-green-400" />;
      default:
        return <Shield className="w-5 h-5 text-gray-400" />;
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className={`fixed inset-0 bg-black/50 backdrop-blur-sm z-40 transition-opacity duration-300 ${
          isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
        }`}
        onClick={onClose}
      />

      {/* Side Panel */}
      <div
        className={`fixed right-0 top-0 h-full w-full md:w-150 lg:w-175 bg-sentinel-bg border-l border-sentinel-border z-50 transform transition-transform duration-300 ease-in-out ${
          isOpen ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        {/* Header */}
        <div className="sticky top-0 bg-sentinel-card border-b border-sentinel-border p-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileCode className="w-6 h-6 text-threat-safe" />
            <div>
              <h2 className="text-xl font-bold">Technical Analysis</h2>
              <p className="text-sm text-gray-400">{result.file.filename}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-sentinel-border rounded-lg transition"
            aria-label="Close panel"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="h-[calc(100%-88px)] overflow-y-auto p-6 space-y-6">
          {/* Threat Overview */}
          <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
            <div className="flex items-center gap-2 mb-4">
              {getThreatIcon(result.threat.level)}
              <h3 className="text-lg font-semibold">Threat Overview</h3>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-gray-400 mb-1">Threat Level</p>
                <p className={`text-lg font-bold ${
                  result.threat.level === 'CRITICAL' || result.threat.level === 'HIGH' ? 'text-red-400' :
                  result.threat.level === 'MEDIUM' ? 'text-yellow-400' :
                  result.threat.level === 'LOW' ? 'text-blue-400' : 'text-green-400'
                }`}>
                  {result.threat.level}
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400 mb-1">Confidence</p>
                <p className="text-lg font-bold">{result.threat.confidence}%</p>
              </div>
            </div>
          </section>

          {/* URL Information (if URL analysis) */}
          {result.url && (
            <section className="bg-sentinel-card border border-blue-500/30 rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <FileCode className="w-5 h-5 text-blue-400" />
                <h3 className="text-lg font-semibold text-blue-300">URL Analysis</h3>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-sm text-gray-400 mb-1">Original URL</p>
                  <p className="text-xs font-mono text-blue-300 break-all">{result.url.original}</p>
                </div>
                {result.url.final !== result.url.original && (
                  <div>
                    <p className="text-sm text-gray-400 mb-1">Final URL (after redirects)</p>
                    <p className="text-xs font-mono text-blue-300 break-all">{result.url.final}</p>
                  </div>
                )}
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Protocol</span>
                  <span className="text-sm font-mono">{result.url.protocol}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Domain</span>
                  <span className="text-sm font-mono">{result.url.domain}</span>
                </div>
                {result.url.redirectChain.length > 1 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Redirect Chain ({result.url.redirectChain.length} hops)</p>
                    <div className="space-y-1">
                      {result.url.redirectChain.map((redirect, idx) => (
                        <div key={idx} className="bg-black/40 p-2 rounded">
                          <p className="text-xs font-mono text-gray-400">
                            {idx + 1}. {redirect}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Webpage Information (if HTML page) */}
          {result.webpage && (
            <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <Eye className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-semibold">Webpage Details</h3>
              </div>
              <div className="space-y-3">
                {result.webpage.title && (
                  <div>
                    <p className="text-sm text-gray-400 mb-1">Page Title</p>
                    <p className="text-sm">{result.webpage.title}</p>
                  </div>
                )}
                {result.webpage.scripts.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Scripts Detected ({result.webpage.scripts.length})</p>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {result.webpage.scripts.slice(0, 10).map((script, idx) => (
                        <div key={idx} className={`bg-black/40 p-2 rounded ${script.includes('SUSPICIOUS') ? 'border border-red-500/50' : ''}`}>
                          <p className={`text-xs font-mono ${script.includes('SUSPICIOUS') ? 'text-red-400' : 'text-gray-400'}`}>
                            {script}
                          </p>
                        </div>
                      ))}
                      {result.webpage.scripts.length > 10 && (
                        <p className="text-xs text-gray-500 italic">... and {result.webpage.scripts.length - 10} more</p>
                      )}
                    </div>
                  </div>
                )}
                {result.webpage.iframes.length > 0 && (
                  <div>
                    <p className="text-sm text-yellow-400 mb-2">⚠️ Iframes Detected ({result.webpage.iframes.length})</p>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {result.webpage.iframes.slice(0, 5).map((iframe, idx) => (
                        <div key={idx} className="bg-black/40 p-2 rounded border border-yellow-500/30">
                          <p className="text-xs font-mono text-yellow-300 break-all">{iframe}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {result.webpage.forms.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Forms Detected ({result.webpage.forms.length})</p>
                    <div className="space-y-1">
                      {result.webpage.forms.map((form, idx) => (
                        <div key={idx} className="bg-black/40 p-2 rounded">
                          <p className="text-xs font-mono text-gray-400 break-all">{form}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {result.webpage.externalLinks.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">External Links ({result.webpage.externalLinks.length})</p>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {result.webpage.externalLinks.slice(0, 10).map((link, idx) => (
                        <div key={idx} className="bg-black/40 p-2 rounded">
                          <p className="text-xs font-mono text-gray-400 break-all">{link}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* File Metadata */}
          <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
            <div className="flex items-center gap-2 mb-4">
              <Layers className="w-5 h-5 text-blue-400" />
              <h3 className="text-lg font-semibold">
                {result.url ? 'Downloaded Content' : 'File Metadata'}
              </h3>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-400">Size</span>
                <span className="text-sm font-mono">{(result.file.size / 1024).toFixed(2)} KB</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-400">Type</span>
                <span className="text-sm font-mono">{result.file.type}</span>
              </div>
              {result.file.hash && (
                <div className="flex justify-between items-start">
                  <span className="text-sm text-gray-400">Hash (SHA-256)</span>
                  <span className="text-xs font-mono text-gray-500 max-w-75 break-all">
                    {result.file.hash}
                  </span>
                </div>
              )}
              {!result.url && (
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Last Modified</span>
                  <span className="text-sm">
                    {new Date(result.file.lastModified).toLocaleString()}
                  </span>
                </div>
              )}
            </div>
          </section>

          {/* Entropy Analysis */}
          <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
            <div className="flex items-center gap-2 mb-4">
              <Activity className="w-5 h-5 text-purple-400" />
              <h3 className="text-lg font-semibold">Entropy Analysis</h3>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-400">Measured Entropy</span>
                <span className="text-sm font-mono">{result.analysis.entropy.toFixed(2)} / 8.0</span>
              </div>
              <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-purple-400 h-2 rounded-full transition-all"
                  style={{ width: `${(result.analysis.entropy / 8.0) * 100}%` }}
                />
              </div>
              <p className="text-xs text-gray-400">
                Higher entropy indicates more randomness (compression/encryption).
                Typical range for compressed files: 6.5-8.0
              </p>
            </div>
          </section>

          {/* Header Validation */}
          <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
            <div className="flex items-center gap-2 mb-4">
              <BarChart3 className="w-5 h-5 text-yellow-400" />
              <h3 className="text-lg font-semibold">Header Validation</h3>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-400">Claimed Type</span>
                <span className="text-sm font-mono">{result.analysis.headerValid.claimedType}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-400">Actual Type</span>
                <span className="text-sm font-mono">{result.analysis.headerValid.actualType}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-400">Match Status</span>
                <span className={`text-sm font-semibold ${
                  result.analysis.headerValid.match ? 'text-green-400' : 'text-red-400'
                }`}>
                  {result.analysis.headerValid.match ? 'MATCH' : 'MISMATCH'}
                </span>
              </div>
              {result.analysis.headerValid.suspicious && (
                <div className="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded">
                  <p className="text-sm text-yellow-400">⚠️ Extension/content mismatch detected</p>
                </div>
              )}
            </div>
          </section>

          {/* Steganography Detection */}
          {result.steganography?.detected && (
            <section className="bg-sentinel-card border border-purple-500/30 rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <Eye className="w-5 h-5 text-purple-400" />
                <h3 className="text-lg font-semibold text-purple-300">Hidden Data Detected</h3>
              </div>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-400">Detection Confidence</span>
                  <span className="text-sm font-mono text-purple-300">{result.steganography.confidence}%</span>
                </div>

                {result.steganography.extractedData?.textMessages && result.steganography.extractedData.textMessages.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-400 mb-2">Extracted Messages:</p>
                    <div className="space-y-2">
                      {result.steganography.extractedData.textMessages.map((msg, idx) => (
                        <div key={idx} className="bg-black/40 p-3 rounded border border-purple-500/30">
                          <p className="text-sm font-mono text-purple-200">"{msg}"</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <p className="text-sm text-gray-400 mb-2">Detection Techniques:</p>
                  <div className="space-y-2">
                    {result.steganography.techniques.map((tech, idx) => (
                      <div key={idx} className="bg-black/40 p-3 rounded">
                        <div className="flex justify-between items-start mb-1">
                          <span className="text-sm font-semibold text-purple-300">{tech.name}</span>
                          <span className="text-xs text-gray-400">{tech.confidence}%</span>
                        </div>
                        <p className="text-xs text-gray-400">{tech.description}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {result.steganography.extractedData && (
                  <div className="mt-3 p-3 bg-purple-500/10 border border-purple-500/30 rounded">
                    <p className="text-xs text-purple-300">
                      Total hidden bytes: {result.steganography.extractedData.totalHiddenBytes} |
                      Locations: {result.steganography.extractedData.dataLocations.join(', ')}
                    </p>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* File Structure */}
          {result.analysis.structure.sections && result.analysis.structure.sections.length > 0 && (
            <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <Layers className="w-5 h-5 text-cyan-400" />
                <h3 className="text-lg font-semibold">File Structure</h3>
              </div>
              <div className="space-y-2">
                {result.analysis.structure.sections.map((section, idx) => (
                  <div key={idx} className="bg-black/40 p-3 rounded">
                    <p className="text-sm font-mono text-cyan-300">{section}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Suspicious APIs */}
          {result.analysis.structure.apis && result.analysis.structure.apis.length > 0 && (
            <section className="bg-sentinel-card border border-red-500/30 rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <h3 className="text-lg font-semibold text-red-300">Suspicious APIs Detected</h3>
              </div>
              <div className="space-y-2">
                {result.analysis.structure.apis.map((api, idx) => (
                  <div key={idx} className="bg-black/40 p-2 rounded">
                    <p className="text-sm font-mono text-red-300">{api}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Preview */}
          {result.analysis.structure.preview && (
            <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <FileCode className="w-5 h-5 text-gray-400" />
                <h3 className="text-lg font-semibold">File Preview</h3>
              </div>
              <div className="bg-black/40 p-4 rounded font-mono text-xs text-gray-400 overflow-x-auto">
                <pre className="whitespace-pre-wrap wrap-break-word">{result.analysis.structure.preview}</pre>
              </div>
            </section>
          )}

          {/* Recommendations */}
          {result.recommendations && result.recommendations.length > 0 && (
            <section className="bg-sentinel-card border border-sentinel-border rounded-lg p-5">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-green-400" />
                <h3 className="text-lg font-semibold">Recommendations</h3>
              </div>
              <ul className="space-y-2">
                {result.recommendations.map((rec, idx) => (
                  <li key={idx} className="text-sm text-gray-300 flex items-start gap-2">
                    <span className="text-threat-safe mt-1">▪</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>
    </>
  );
};
