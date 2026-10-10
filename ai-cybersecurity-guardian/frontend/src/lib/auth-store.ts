/**
 * Auth token store — secure in-memory + sessionStorage storage.
 *
 * Security model:
 * - Access token: held in module-level variable (memory only). Cleared on page reload.
 *   This prevents XSS from reading the access token via localStorage.
 * - Refresh token: stored in sessionStorage. This is NOT fully XSS-safe
 *   (any injected script can read sessionStorage), but is preferred over localStorage
 *   because it is tab-isolated and clears on tab close.
 *   For production hardening, HttpOnly cookie delivery of the refresh token
 *   would eliminate this risk entirely.
 *
 * Tokens are NEVER logged, never surfaced in errors, and never passed to
 * analytics, console.log, or any third-party service.
 */

const REFRESH_TOKEN_KEY = 'cg_rt'; // intentionally non-descriptive key

// Access token lives only in memory — cleared on any page reload
let _accessToken: string | null = null;

export function getAccessToken(): string | null {
  return _accessToken;
}

export function getRefreshToken(): string | null {
  try {
    return sessionStorage.getItem(REFRESH_TOKEN_KEY);
  } catch {
    // sessionStorage blocked (e.g. incognito with storage blocked)
    return null;
  }
}

export function setTokens(accessToken: string, refreshToken: string): void {
  _accessToken = accessToken;
  try {
    sessionStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  } catch {
    // Silently fail — access token still works for the current session
  }
}

export function clearTokens(): void {
  _accessToken = null;
  try {
    sessionStorage.removeItem(REFRESH_TOKEN_KEY);
  } catch {
    // Silently fail
  }
}
