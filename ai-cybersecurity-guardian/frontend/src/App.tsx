import { Toaster } from 'react-hot-toast';
import { AuthProvider } from '@/providers/AuthProvider';
import { QueryProvider } from '@/providers/QueryProvider';
import { UIProvider } from '@/providers/UIProvider';
import { AppRouter } from '@/router';

export default function App() {
  return (
    <QueryProvider>
      <AuthProvider>
        <UIProvider>
          <AppRouter />
        </UIProvider>
        <Toaster
          position="bottom-right"
          toastOptions={{
            style: {
              background: '#1a2235',
              color: 'rgba(255,255,255,0.9)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '10px',
              fontSize: '0.875rem',
              fontFamily: "'Inter', sans-serif",
            },
            success: { iconTheme: { primary: 'var(--color-safe)', secondary: '#0d1426' } },
            error:   { iconTheme: { primary: 'var(--color-critical)', secondary: '#0d1426' } },
          }}
        />
      </AuthProvider>
    </QueryProvider>
  );
}
