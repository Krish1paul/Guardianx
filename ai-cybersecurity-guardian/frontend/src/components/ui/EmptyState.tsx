import type { ReactNode } from 'react';
import { Button } from './Button';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        gap: 16,
        textAlign: 'center',
      }}
    >
      {icon && (
        <div style={{ color: 'var(--color-text-muted)', marginBottom: 8 }}>
          {icon}
        </div>
      )}
      <h3 style={{ color: 'var(--color-text-secondary)', fontWeight: 600, fontSize: '1rem' }}>
        {title}
      </h3>
      {description && (
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', maxWidth: 320 }}>
          {description}
        </p>
      )}
      {action && (
        <Button variant="secondary" size="sm" onClick={action.onClick} style={{ marginTop: 8 }}>
          {action.label}
        </Button>
      )}
    </div>
  );
}

interface ErrorStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: { label: string; onClick: () => void };
}

export function ErrorState({ icon, title, description, action }: ErrorStateProps) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        gap: 16,
        textAlign: 'center',
      }}
    >
      {icon && (
        <div style={{ color: 'var(--color-critical)', marginBottom: 8 }}>
          {icon}
        </div>
      )}
      <h3 style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
        {title}
      </h3>
      {description && (
        <p style={{ color: 'var(--color-text-muted)', fontSize: '0.875rem', maxWidth: 360 }}>
          {description}
        </p>
      )}
      {action && (
        <Button variant="ghost" size="sm" onClick={action.onClick} style={{ marginTop: 8 }}>
          {action.label}
        </Button>
      )}
    </div>
  );
}
