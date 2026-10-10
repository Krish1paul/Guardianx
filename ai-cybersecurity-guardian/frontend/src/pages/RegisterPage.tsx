import { motion } from 'framer-motion';
import { Shield, UserPlus } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth, getErrorMessage } from '@/providers/AuthProvider';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';

function PasswordStrength({ password }: { password: string }) {
  const checks = [
    password.length >= 8,
    /[A-Z]/.test(password),
    /[a-z]/.test(password),
    /\d/.test(password),
  ];
  const score = checks.filter(Boolean).length;

  const colors = ['var(--color-critical)', 'var(--color-danger)', 'var(--color-warning)', 'var(--color-safe)'];
  const labels = ['Weak', 'Fair', 'Good', 'Strong'];

  if (!password) return null;

  return (
    <div style={{ marginTop: -8 }}>
      <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
        {[0, 1, 2, 3].map((i) => (
          <motion.div
            key={i}
            style={{ flex: 1, height: 3, borderRadius: 2, background: i < score ? colors[score - 1] : 'var(--color-border)' }}
            animate={{ background: i < score ? colors[score - 1] : 'rgba(255,255,255,0.06)' }}
            transition={{ duration: 0.2 }}
          />
        ))}
      </div>
      <p style={{ fontSize: '0.7rem', color: score > 0 ? colors[score - 1] : 'var(--color-text-muted)' }}>
        {score > 0 ? labels[score - 1] : ''}
      </p>
    </div>
  );
}

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await register({ email, password });
      navigate('/login', { state: { registered: true } });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="cyber-bg" aria-hidden="true" />

      <motion.div
        className="auth-card glass-card"
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="auth-logo">
          <Shield size={36} style={{ color: 'var(--color-cyan)' }} className="float-glow" />
          <div>
            <h1 className="auth-title">Guardianx</h1>
            <p className="auth-subtitle">AI-powered threat intelligence</p>
          </div>
        </div>

        <div className="auth-section-title">
          <UserPlus size={15} aria-hidden="true" />
          Create your account
        </div>

        <form onSubmit={handleSubmit} noValidate style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Input
            label="Email address"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            required
            placeholder="analyst@example.com"
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <Input
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
              required
              hint="Min 8 chars, uppercase, lowercase, and digit required"
            />
            <PasswordStrength password={password} />
          </div>

          {error && (
            <div className="auth-error" role="alert" aria-live="assertive">
              {error}
            </div>
          )}

          <Button type="submit" variant="primary" size="lg" loading={loading} style={{ marginTop: 4, width: '100%' }}>
            Create Account
          </Button>
        </form>

        <p className="auth-footer">
          Already have an account?{' '}
          <Link to="/login">Sign in</Link>
        </p>
      </motion.div>
    </div>
  );
}
