import { motion } from 'framer-motion';
import type { HTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  hover?: boolean;
  glow?: 'cyan' | 'red' | 'green' | 'none';
  padding?: 'sm' | 'md' | 'lg' | 'none';
}

const glowInline: Record<string, React.CSSProperties> = {
  cyan:  { borderColor: 'rgba(0,212,255,0.2)', boxShadow: '0 0 24px rgba(0,212,255,0.08)' },
  red:   { borderColor: 'rgba(255,45,85,0.25)', boxShadow: '0 0 24px rgba(255,45,85,0.1)' },
  green: { borderColor: 'rgba(0,230,118,0.2)', boxShadow: '0 0 24px rgba(0,230,118,0.08)' },
  none:  {},
};

const paddingPx: Record<string, number | undefined> = {
  sm:   16,
  md:   24,
  lg:   32,
  none: undefined,
};

export function Card({
  children,
  hover = false,
  glow = 'none',
  padding = 'md',
  className,
  style,
  ...props
}: CardProps) {
  const inlineStyle: React.CSSProperties = {
    padding: paddingPx[padding],
    ...glowInline[glow],
    ...style,
  };

  if (hover) {
    return (
      <motion.div
        className={cn('glass-card', className)}
        style={inlineStyle}
        whileHover={{ y: -2, borderColor: 'rgba(0,212,255,0.18)' }}
        transition={{ duration: 0.2, ease: 'easeOut' }}
        {...(props as object)}
      >
        {children}
      </motion.div>
    );
  }

  return (
    <div className={cn('glass-card', className)} style={inlineStyle} {...props}>
      {children}
    </div>
  );
}
