import { useReducedMotion as useFramerReducedMotion } from 'framer-motion';

/**
 * Returns true when the user has requested reduced motion via OS/browser settings.
 * Use this to conditionally disable non-essential animations.
 */
export function useReducedMotion(): boolean {
  return useFramerReducedMotion() ?? false;
}
