import React, { useRef, useState } from 'react';
import { AlertTriangle, FileCode, FileUp, ShieldCheck, X } from 'lucide-react';
import { Button } from '@/components/ui/Button';

interface FileScannerProps {
  onSubmit: (file: File) => void;
  isPending: boolean;
}

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB

export function FileScanner({ onSubmit, isPending }: FileScannerProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const handleValidateAndSet = (file: File) => {
    setError('');
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setError(`File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds the 5 MB limit.`);
      return;
    }
    if (file.size === 0) {
      setError('File is empty.');
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleValidateAndSet(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select or drop a file to analyze.');
      return;
    }
    onSubmit(selectedFile);
  };

  return (
    <div className="file-scanner-wrap">
      <div className="scanner-header" style={{ marginBottom: 20 }}>
        <FileCode size={40} style={{ color: 'var(--color-cyan)' }} className="float-glow" />
        <h2 className="scanner-title">Static File & Artifact Analyzer</h2>
        <p className="scanner-subtitle">
          Safe, non-executing static analysis of binaries, documents, and archives. Sniffs magic byte headers, double extensions, and archive anomalies.
        </p>
      </div>

      <div className="privacy-badge" style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        background: 'rgba(0, 245, 255, 0.04)',
        border: '1px solid rgba(0, 245, 255, 0.15)',
        borderRadius: 8,
        padding: '10px 14px',
        fontSize: '0.78rem',
        color: 'var(--color-text-secondary)',
        marginBottom: 20,
      }}>
        <ShieldCheck size={16} style={{ color: 'var(--color-green)', flexShrink: 0 }} />
        <span>
          <strong>Zero-Execution Guarantee:</strong> Files are never executed or saved to disk. Inspected strictly in memory up to 5 MB.
        </span>
      </div>

      <form onSubmit={handleSubmit} noValidate className="scanner-form">
        <input
          ref={inputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleValidateAndSet(e.target.files[0]);
            }
          }}
          disabled={isPending}
        />

        <div
          className={`dropzone-box ${dragActive ? 'dropzone-active' : ''} ${error ? 'scanner-input-error' : ''}`}
          style={{
            border: `2px dashed ${dragActive ? 'var(--color-cyan)' : 'var(--color-border)'}`,
            borderRadius: 12,
            padding: '36px 20px',
            textAlign: 'center',
            background: dragActive ? 'rgba(0, 245, 255, 0.05)' : 'rgba(255, 255, 255, 0.02)',
            cursor: isPending ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s ease',
          }}
          onClick={() => !isPending && inputRef.current?.click()}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
        >
          <FileUp size={44} style={{ color: dragActive ? 'var(--color-cyan)' : 'var(--color-text-muted)', margin: '0 auto 12px' }} />
          <p style={{ fontSize: '0.95rem', fontWeight: 500, color: 'var(--color-text)', marginBottom: 4 }}>
            {selectedFile ? selectedFile.name : 'Click to upload or drag & drop a file'}
          </p>
          <p style={{ fontSize: '0.78rem', color: 'var(--color-text-muted)', margin: 0 }}>
            Executables, Office docs, PDFs, ZIP archives (up to 5 MB)
          </p>
        </div>

        {selectedFile && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--color-border)',
            borderRadius: 8,
            padding: '10px 14px',
            marginTop: 12,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}>
              <FileCode size={18} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 500 }}>{selectedFile.name}</span>
                <span style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginLeft: 8 }}>
                  ({(selectedFile.size / 1024).toFixed(1)} KB)
                </span>
              </div>
            </div>
            {!isPending && (
              <button
                type="button"
                className="scanner-clear"
                style={{ position: 'static' }}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedFile(null);
                  setError('');
                }}
                aria-label="Remove file"
              >
                <X size={16} />
              </button>
            )}
          </div>
        )}

        {error && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--color-red)', fontSize: '0.8rem', marginTop: 10 }}>
            <AlertTriangle size={14} />
            <span>{error}</span>
          </div>
        )}

        <Button
          type="submit"
          variant="primary"
          size="lg"
          loading={isPending}
          disabled={!selectedFile}
          icon={<FileUp size={18} />}
          style={{ alignSelf: 'center', minWidth: 200, marginTop: 16 }}
        >
          Analyze File
        </Button>
      </form>
    </div>
  );
}
