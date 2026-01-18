import React, { useCallback, useState } from 'react';
import { Upload, File, AlertCircle } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  disabled?: boolean;
  id?: string;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onFileSelect, disabled, id = 'file-upload' }) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (disabled) return;

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      onFileSelect(file);
    }
  }, [disabled, onFileSelect]);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (disabled) return;

    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      onFileSelect(file);
    }
  }, [disabled, onFileSelect]);

  return (
    <div className="w-full">
      <form
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className="relative"
      >
        <input
          type="file"
          id={id}
          className="hidden"
          onChange={handleChange}
          disabled={disabled}
        />

        <label
          htmlFor={id}
          className={`
            flex flex-col items-center justify-center
            w-full h-64 px-4 py-6
            border-2 border-dashed rounded-lg
            cursor-pointer transition-all
            ${dragActive
              ? 'border-threat-safe bg-sentinel-card/50'
              : 'border-sentinel-border bg-sentinel-card/30 hover:bg-sentinel-card/50'
            }
            ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
          `}
        >
          <div className="flex flex-col items-center justify-center pt-5 pb-6">
            {selectedFile ? (
              <>
                <File className="w-12 h-12 mb-4 text-threat-safe" />
                <p className="mb-2 text-sm text-gray-300">
                  <span className="font-semibold">{selectedFile.name}</span>
                </p>
                <p className="text-xs text-gray-400">
                  {(selectedFile.size / 1024).toFixed(2)} KB
                </p>
              </>
            ) : (
              <>
                <Upload className="w-12 h-12 mb-4 text-gray-400" />
                <p className="mb-2 text-sm text-gray-300">
                  <span className="font-semibold">Click to upload</span> or drag and drop
                </p>
                <p className="text-xs text-gray-400">
                  Any file type accepted for analysis
                </p>
              </>
            )}
          </div>

          {dragActive && (
            <div className="absolute inset-0 bg-threat-safe/10 rounded-lg pointer-events-none" />
          )}
        </label>
      </form>

      {selectedFile && !disabled && (
        <div className="mt-4 p-4 bg-sentinel-card rounded-lg border border-sentinel-border">
          <div className="flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-gray-300">
              <p className="font-semibold mb-1">Ready for analysis</p>
              <p className="text-gray-400">
                Sentinel will examine this file for potential security threats using AI-powered behavioral prediction.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
