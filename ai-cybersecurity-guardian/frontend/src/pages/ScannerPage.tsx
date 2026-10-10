import { AnimatePresence, motion } from 'framer-motion';
import { FileCode, Globe, Mail, ScanLine, Send, X } from 'lucide-react';
import { useState } from 'react';
import { useFileScan, useMessageScan, useScan } from '@/hooks/useScan';
import { useQueryClient } from '@tanstack/react-query';
import { ScanResult } from '@/components/scanner/ScanResult';
import { MessageScanner } from '@/components/scanner/MessageScanner';
import { MessageScanResult } from '@/components/scanner/MessageScanResult';
import { FileScanner } from '@/components/scanner/FileScanner';
import { FileScanResult } from '@/components/scanner/FileScanResult';
import { Button } from '@/components/ui/Button';
import { ErrorState } from '@/components/ui/EmptyState';
import { Spinner } from '@/components/ui/Spinner';
import { getErrorMessage } from '@/lib/api';
import type { FileScanResponse, MessageScanRequest, MessageScanResponse, URLScanResponse } from '@/types/api';

type ScanVector = 'url' | 'message' | 'file';

function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function ScanningAnimation({ label }: { label: string }) {
  return (
    <motion.div
      className="scanning-state"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
    >
      <div className="scanning-beam-wrap">
        <p className="scanning-url">{label}</p>
        <div className="scan-beam" aria-hidden="true" />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center' }}>
        <Spinner size="sm" />
        <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.9rem' }}>
          Analyzing multi-vector risk indicators...
        </span>
      </div>
    </motion.div>
  );
}

export default function ScannerPage() {
  const [activeVector, setActiveVector] = useState<ScanVector>('url');

  // URL scanner state
  const [url, setUrl] = useState('');
  const [inputError, setInputError] = useState('');
  const [lastUrlResult, setLastUrlResult] = useState<URLScanResponse | null>(null);

  // Message scanner state
  const [lastMessageResult, setLastMessageResult] = useState<MessageScanResponse | null>(null);

  // File scanner state
  const [lastFileResult, setLastFileResult] = useState<FileScanResponse | null>(null);

  const queryClient = useQueryClient();

  // Mutations
  const urlMutation = useScan();
  const messageMutation = useMessageScan();
  const fileMutation = useFileScan();

  const isPending = urlMutation.isPending || messageMutation.isPending || fileMutation.isPending;
  const isError = urlMutation.isError || messageMutation.isError || fileMutation.isError;
  const currentError = urlMutation.error || messageMutation.error || fileMutation.error;

  const handleUrlSubmit = (e?: React.FormEvent) => {
    e?.preventDefault();
    setInputError('');
    const trimmed = url.trim();

    if (!trimmed) { setInputError('Please enter a URL to analyze.'); return; }
    if (!isValidUrl(trimmed)) { setInputError('Please enter a valid http:// or https:// URL.'); return; }

    urlMutation.mutate(
      { url: trimmed },
      {
        onSuccess: (data) => {
          setLastUrlResult(data);
          void queryClient.invalidateQueries({ queryKey: ['history'] });
        },
      },
    );
  };

  const handleMessageSubmit = (data: MessageScanRequest) => {
    messageMutation.mutate(data, {
      onSuccess: (res) => {
        setLastMessageResult(res);
        void queryClient.invalidateQueries({ queryKey: ['history'] });
      },
    });
  };

  const handleFileSubmit = (file: File) => {
    fileMutation.mutate(file, {
      onSuccess: (res) => {
        setLastFileResult(res);
        void queryClient.invalidateQueries({ queryKey: ['history'] });
      },
    });
  };

  const handleReset = () => {
    urlMutation.reset();
    messageMutation.reset();
    fileMutation.reset();
    setLastUrlResult(null);
    setLastMessageResult(null);
    setLastFileResult(null);
    setUrl('');
    setInputError('');
  };

  const handleSwitchVector = (vector: ScanVector) => {
    handleReset();
    setActiveVector(vector);
  };

  const hasResult = !!(lastUrlResult || lastMessageResult || lastFileResult);
  const errorMessage = isError ? getErrorMessage(currentError) : '';

  return (
    <div className="page-container scanner-page">
      {/* Vector Selector Tabs */}
      {!hasResult && !isPending && (
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          marginBottom: 24,
        }}>
          <div style={{
            display: 'inline-flex',
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--color-border)',
            borderRadius: 10,
            padding: 4,
            gap: 4,
          }}>
            <button
              type="button"
              onClick={() => handleSwitchVector('url')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 18px',
                borderRadius: 8,
                border: 'none',
                background: activeVector === 'url' ? 'var(--color-cyan-glow)' : 'transparent',
                color: activeVector === 'url' ? 'var(--color-cyan)' : 'var(--color-text-secondary)',
                fontWeight: activeVector === 'url' ? 600 : 400,
                fontSize: '0.85rem',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <Globe size={16} />
              URL Scanner
            </button>

            <button
              type="button"
              onClick={() => handleSwitchVector('message')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 18px',
                borderRadius: 8,
                border: 'none',
                background: activeVector === 'message' ? 'rgba(0, 245, 255, 0.12)' : 'transparent',
                color: activeVector === 'message' ? 'var(--color-cyan)' : 'var(--color-text-secondary)',
                fontWeight: activeVector === 'message' ? 600 : 400,
                fontSize: '0.85rem',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <Mail size={16} />
              Message / Text
            </button>

            <button
              type="button"
              onClick={() => handleSwitchVector('file')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 18px',
                borderRadius: 8,
                border: 'none',
                background: activeVector === 'file' ? 'rgba(0, 245, 255, 0.12)' : 'transparent',
                color: activeVector === 'file' ? 'var(--color-cyan)' : 'var(--color-text-secondary)',
                fontWeight: activeVector === 'file' ? 600 : 400,
                fontSize: '0.85rem',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <FileCode size={16} />
              Static File
            </button>
          </div>
        </div>
      )}

      <AnimatePresence mode="wait">
        {/* URL Result */}
        {lastUrlResult && !isPending && (
          <ScanResult key="url-result" result={lastUrlResult} onScanAnother={handleReset} />
        )}

        {/* Message Result */}
        {lastMessageResult && !isPending && (
          <MessageScanResult key="message-result" result={lastMessageResult} onScanAnother={handleReset} />
        )}

        {/* File Result */}
        {lastFileResult && !isPending && (
          <FileScanResult key="file-result" result={lastFileResult} onScanAnother={handleReset} />
        )}

        {/* Input Forms */}
        {!hasResult && (
          <motion.div
            key={`form-${activeVector}`}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
            className="scanner-form-wrap"
          >
            {activeVector === 'url' && (
              <>
                <div className="scanner-header">
                  <ScanLine size={40} style={{ color: 'var(--color-cyan)' }} className="float-glow" />
                  <h2 className="scanner-title">URL Threat Analyzer</h2>
                  <p className="scanner-subtitle">
                    Submit any URL to analyze structural, lexical, and threat-intelligence risk indicators.
                    No network request is made to the target URL.
                  </p>
                </div>

                <form onSubmit={handleUrlSubmit} noValidate className="scanner-form">
                  <div className="scanner-input-wrap">
                    <input
                      className={`scanner-input ${inputError ? 'scanner-input-error' : ''}`}
                      type="url"
                      value={url}
                      onChange={(e) => { setUrl(e.target.value); setInputError(''); urlMutation.reset(); }}
                      placeholder="https://example.com/login"
                      disabled={isPending}
                      autoFocus
                      autoComplete="url"
                      aria-label="URL to analyze"
                      aria-invalid={!!inputError}
                      aria-describedby={inputError ? 'url-error' : undefined}
                      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleUrlSubmit(); } }}
                    />
                    {url && (
                      <button
                        type="button"
                        className="scanner-clear"
                        onClick={() => { setUrl(''); setInputError(''); urlMutation.reset(); }}
                        aria-label="Clear URL"
                      >
                        <X size={16} />
                      </button>
                    )}
                  </div>

                  {inputError && (
                    <p id="url-error" className="scanner-field-error" role="alert">
                      {inputError}
                    </p>
                  )}

                  <Button
                    type="submit"
                    variant="primary"
                    size="lg"
                    loading={isPending}
                    icon={<Send size={18} />}
                    style={{ alignSelf: 'center', minWidth: 180 }}
                  >
                    Analyze URL
                  </Button>
                </form>

                {/* Example URLs */}
                {!isPending && !isError && (
                  <div className="scanner-examples">
                    <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 8 }}>
                      Try an example URL:
                    </p>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {[
                        'https://google.com',
                        'http://paypa1-secure.ru/login?auth=xyz&key=abc',
                        'https://bit.ly/3xAb192',
                        'https://192.168.1.1/admin',
                      ].map((ex) => (
                        <button
                          key={ex}
                          className="scanner-example-btn"
                          onClick={() => { setUrl(ex); setInputError(''); urlMutation.reset(); }}
                          type="button"
                        >
                          {ex.length > 40 ? ex.slice(0, 40) + '…' : ex}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}

            {activeVector === 'message' && (
              <MessageScanner onSubmit={handleMessageSubmit} isPending={isPending} />
            )}

            {activeVector === 'file' && (
              <FileScanner onSubmit={handleFileSubmit} isPending={isPending} />
            )}

            {/* Scanning animation */}
            <AnimatePresence>
              {isPending && (
                <ScanningAnimation
                  label={
                    activeVector === 'url'
                      ? url.trim()
                      : activeVector === 'message'
                        ? 'Analyzing message heuristics & embedded links...'
                        : 'Inspecting static file signatures & headers...'
                  }
                />
              )}
            </AnimatePresence>

            {/* Error state */}
            {isError && !isPending && (
              <div className="scanner-error-wrap">
                <ErrorState
                  icon={<ScanLine size={36} />}
                  title="Analysis failed"
                  description={errorMessage}
                  action={{ label: 'Try again', onClick: handleReset }}
                />
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

