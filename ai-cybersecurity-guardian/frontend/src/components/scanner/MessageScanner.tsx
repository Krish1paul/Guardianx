import { useState } from 'react';
import { Mail, Send, ShieldAlert, Sparkles, X } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import type { MessageScanRequest } from '@/types/api';

interface MessageScannerProps {
  onSubmit: (data: MessageScanRequest) => void;
  isPending: boolean;
}

const SAMPLE_MESSAGES = [
  {
    title: 'Urgent Bank Alert',
    subject: 'URGENT: Suspicious activity on your checking account',
    sender: 'security-alert@secure-bank-update.xyz',
    body: 'Dear Customer, We detected an unauthorized login attempt to your banking portal from an unknown IP address. Your account will be permanently suspended within 24 hours unless you verify your identity immediately: http://paypa1-secure-verify.ru/login?token=urgent-action-req',
  },
  {
    title: 'Payroll / Tax Action',
    subject: 'ACTION REQUIRED: Pending W2 Tax Document Confirmation',
    sender: 'hr-portal@corporate-payroll-support.com',
    body: 'Hello Team, our HR department has released the updated direct deposit forms. Please confirm your banking routing number and credentials at your earliest convenience to avoid payroll interruption: https://hr-payroll-update.com/verify-credentials',
  },
  {
    title: 'Clean Notification',
    subject: 'Antigravity Weekly Sprint Planning',
    sender: 'product-lead@company.internal',
    body: 'Hi team, please find the agenda for tomorrow morning sprint review meeting. Let me know if you have any questions or items to add to the queue.',
  },
];

export function MessageScanner({ onSubmit, isPending }: MessageScannerProps) {
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const trimmed = body.trim();
    if (!trimmed) {
      setError('Please provide the email or message body to analyze.');
      return;
    }
    onSubmit({
      message: trimmed,
      body: trimmed,
      subject: subject.trim() || undefined,
      sender: sender.trim() || undefined,
    });

  };

  const handleApplySample = (sample: typeof SAMPLE_MESSAGES[0]) => {
    setSubject(sample.subject);
    setSender(sample.sender);
    setBody(sample.body);
    setError('');
  };

  const handleClear = () => {
    setSubject('');
    setSender('');
    setBody('');
    setError('');
  };

  return (
    <div className="message-scanner-wrap">
      <div className="scanner-header" style={{ marginBottom: 20 }}>
        <Mail size={40} style={{ color: 'var(--color-cyan)' }} className="float-glow" />
        <h2 className="scanner-title">Message & Phishing Analyzer</h2>
        <p className="scanner-subtitle">
          Detect social engineering, credential harvesting lures, urgency tactics, and malicious embedded links.
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
        <ShieldAlert size={16} style={{ color: 'var(--color-cyan)', flexShrink: 0 }} />
        <span>
          <strong>Privacy Guard:</strong> Raw text is processed in-memory and <em>never stored</em>. Only SHA-256 hash and risk signals are persisted.
        </span>
      </div>

      <form onSubmit={handleSubmit} noValidate className="scanner-form">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginBottom: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>
              Sender (Optional)
            </label>
            <input
              type="text"
              className="scanner-input"
              style={{ fontSize: '0.85rem', padding: '8px 14px', height: 'auto' }}
              placeholder="e.g. security-team@paypal.com"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              disabled={isPending}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>
              Subject Line (Optional)
            </label>
            <input
              type="text"
              className="scanner-input"
              style={{ fontSize: '0.85rem', padding: '8px 14px', height: 'auto' }}
              placeholder="e.g. URGENT: Verify your account immediately"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              disabled={isPending}
            />
          </div>
        </div>

        <div style={{ position: 'relative' }}>
          <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 4 }}>
            Message / Email Body <span style={{ color: 'var(--color-red)' }}>*</span>
          </label>
          <textarea
            className={`scanner-input ${error ? 'scanner-input-error' : ''}`}
            style={{
              width: '100%',
              minHeight: 140,
              resize: 'vertical',
              padding: '12px 14px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
              lineHeight: 1.5,
              borderRadius: 8,
            }}
            placeholder="Paste suspicious message, SMS, or email contents here..."
            value={body}
            onChange={(e) => {
              setBody(e.target.value);
              setError('');
            }}
            disabled={isPending}
          />
          {body && (
            <button
              type="button"
              className="scanner-clear"
              style={{ top: 32, right: 12 }}
              onClick={handleClear}
              aria-label="Clear message"
            >
              <X size={16} />
            </button>
          )}
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4, marginBottom: 16 }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--color-text-muted)' }}>
            {body.length} characters
          </span>
          {error && (
            <p className="scanner-field-error" role="alert" style={{ margin: 0 }}>
              {error}
            </p>
          )}
        </div>

        <Button
          type="submit"
          variant="primary"
          size="lg"
          loading={isPending}
          icon={<Send size={18} />}
          style={{ alignSelf: 'center', minWidth: 200 }}
        >
          Analyze Message
        </Button>
      </form>

      {!isPending && (
        <div className="scanner-examples" style={{ marginTop: 24 }}>
          <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Sparkles size={14} style={{ color: 'var(--color-cyan)' }} />
            Try sample message templates:
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {SAMPLE_MESSAGES.map((s) => (
              <button
                key={s.title}
                type="button"
                className="scanner-example-btn"
                onClick={() => handleApplySample(s)}
              >
                {s.title}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
