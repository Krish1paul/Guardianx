/**
 * Shared Framer Motion transition presets.
 *
 * Using named easing strings instead of number-array beziers avoids
 * the TypeScript `Easing` type mismatch introduced in framer-motion v11+.
 */
import type { Transition, Variants } from 'framer-motion';

/** Standard spring-like ease. */
export const EASE_OUT_EXPO = 'easeOut' as const;

/** Fast micro-interaction. */
export const transition = {
  fast:   { duration: 0.15, ease: EASE_OUT_EXPO } satisfies Transition,
  normal: { duration: 0.25, ease: EASE_OUT_EXPO } satisfies Transition,
  slow:   { duration: 0.4,  ease: EASE_OUT_EXPO } satisfies Transition,
};

/** Stagger parent. */
export const staggerParent = (stagger = 0.07): Variants => ({
  initial: { opacity: 0 },
  enter:   { opacity: 1, transition: { staggerChildren: stagger } },
});

/** Standard fade-up child. */
export const fadeUpChild = (delay = 0): Variants => ({
  initial: { opacity: 0, y: 16 },
  enter:   { opacity: 1, y: 0, transition: { delay, ...transition.normal } },
});

/** Page transition variants. */
export const pageVariants: Variants = {
  initial: { opacity: 0, y: 12 },
  enter:   { opacity: 1, y: 0, transition: transition.normal },
  exit:    { opacity: 0, y: -8, transition: { duration: 0.15, ease: EASE_OUT_EXPO } },
};

/** Result stagger container. */
export const resultVariants: Variants = {
  initial: { opacity: 0 },
  enter:   { opacity: 1, transition: { staggerChildren: 0.1 } },
};

/** Result stagger item. */
export const resultItemVariant: Variants = {
  initial: { opacity: 0, y: 16 },
  enter:   { opacity: 1, y: 0, transition: transition.normal },
};

/** List stagger container. */
export const listVariants: Variants = {
  enter: { transition: { staggerChildren: 0.06 } },
};

/** List item. */
export const listItemVariant: Variants = {
  initial: { opacity: 0, x: -12 },
  enter:   { opacity: 1, x: 0, transition: transition.normal },
};
