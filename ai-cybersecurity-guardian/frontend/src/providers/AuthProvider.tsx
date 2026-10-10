import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { authAPI, getErrorMessage } from '@/lib/api';
import { clearTokens, getRefreshToken, setTokens } from '@/lib/auth-store';
import type { LoginRequest, RegisterRequest, UserMeResponse } from '@/types/api';
import { queryClient } from '@/providers/QueryProvider';

interface AuthContextValue {
  user: UserMeResponse | null;
  isLoading: boolean;
  login: (data: LoginRequest) => Promise<void>;
  register: (data: RegisterRequest) => Promise<UserMeResponse>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserMeResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // On mount — try to restore session from stored refresh token
  useEffect(() => {
    const restore = async () => {
      const rt = getRefreshToken();
      if (!rt) { setIsLoading(false); return; }
      try {
        const tokens = await authAPI.refresh({ refresh_token: rt });
        setTokens(tokens.access_token, tokens.refresh_token);
        const me = await authAPI.me();
        setUser(me);
      } catch {
        clearTokens();
      } finally {
        setIsLoading(false);
      }
    };
    void restore();
  }, []);

  const login = useCallback(async (data: LoginRequest) => {
    const tokens = await authAPI.login(data);
    setTokens(tokens.access_token, tokens.refresh_token);
    const me = await authAPI.me();
    setUser(me);
  }, []);

  const register = useCallback(async (data: RegisterRequest) => {
    return authAPI.register(data);
  }, []);

  const logout = useCallback(async () => {
    const rt = getRefreshToken();
    if (rt) {
      try {
        await authAPI.logout({ refresh_token: rt });
      } catch {
        // Best-effort — always clear local state
      }
    }
    clearTokens();
    setUser(null);
    queryClient.clear();
  }, []);

  return (
    <AuthContext.Provider value={{ user, isLoading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}

// Re-export for convenience in auth forms
export { getErrorMessage };
