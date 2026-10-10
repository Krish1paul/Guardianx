import { motion } from 'framer-motion';
import { useEffect, useRef } from 'react';
import { useCountUp } from '@/hooks/useCountUp';
import { useReducedMotion } from '@/hooks/useReducedMotion';
import { scoreToColor } from '@/lib/utils';

interface ThreatGaugeProps {
  score: number;
  size?: number;
  active?: boolean;
}

const RADIUS = 80;
const STROKE = 10;
const ARC_DEGREES = 240; // gauge spans 240° (120° gap at bottom)
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const ARC_LENGTH = (ARC_DEGREES / 360) * CIRCUMFERENCE;

function degreesToOffset(pct: number): number {
  // Full arc = offset 0; empty arc = offset = ARC_LENGTH
  return ARC_LENGTH - (ARC_LENGTH * pct) / 100;
}

export function ThreatGauge({ score, size = 200, active = true }: ThreatGaugeProps) {
  const reduced = useReducedMotion();
  const displayScore = useCountUp(score, 1200, active);
  const progressRef = useRef<SVGCircleElement>(null);
  const color = scoreToColor(score);

  const cx = size / 2;
  const cy = size / 2 + size * 0.05; // slight vertical offset

  // SVG arc transform — rotate so the gap is at the bottom
  const startAngle = 150; // degrees from positive x-axis

  useEffect(() => {
    if (!progressRef.current) return;
    if (reduced) {
      progressRef.current.style.strokeDashoffset = String(degreesToOffset(score));
      return;
    }
    // Animate from full offset (empty) to target
    progressRef.current.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.16, 1, 0.3, 1)';
    progressRef.current.style.strokeDashoffset = String(degreesToOffset(score));
  }, [score, reduced]);

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      {/* Ambient pulse ring */}
      {!reduced && active && (
        <div
          className="pulse-ring"
          style={{
            position: 'absolute',
            inset: size * 0.18,
            borderRadius: '50%',
            border: `2px solid ${color}`,
            opacity: 0.15,
            pointerEvents: 'none',
          }}
          aria-hidden="true"
        />
      )}

      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label={`Threat gauge: ${score} out of 100`}
      >
        {/* Track */}
        <circle
          cx={cx} cy={cy} r={RADIUS}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={STROKE}
          strokeDasharray={`${ARC_LENGTH} ${CIRCUMFERENCE}`}
          strokeLinecap="round"
          transform={`rotate(${startAngle}, ${cx}, ${cy})`}
        />

        {/* Progress arc */}
        <circle
          ref={progressRef}
          cx={cx} cy={cy} r={RADIUS}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeDasharray={`${ARC_LENGTH} ${CIRCUMFERENCE}`}
          strokeDashoffset={ARC_LENGTH} // starts empty, animated via useEffect
          strokeLinecap="round"
          transform={`rotate(${startAngle}, ${cx}, ${cy})`}
          style={{ filter: `drop-shadow(0 0 8px ${color}88)` }}
        />

        {/* Center score */}
        <text
          x={cx} y={cy - 8}
          textAnchor="middle"
          fill={color}
          fontSize={size * 0.22}
          fontFamily="'JetBrains Mono', monospace"
          fontWeight="700"
          aria-hidden="true"
        >
          {displayScore}
        </text>
        <text
          x={cx} y={cy + size * 0.1}
          textAnchor="middle"
          fill="rgba(255,255,255,0.4)"
          fontSize={size * 0.07}
          fontFamily="Inter, sans-serif"
          fontWeight="500"
          aria-hidden="true"
        >
          RISK SCORE
        </text>

        {/* Scale labels */}
        <text x={cx - RADIUS * 0.72 + cx * 0.06} y={cy + RADIUS * 0.58}
          textAnchor="middle" fill="rgba(255,255,255,0.25)"
          fontSize={size * 0.055} fontFamily="'JetBrains Mono', monospace" aria-hidden="true">0</text>
        <text x={cx + RADIUS * 0.72 + cx * -0.06 + 4} y={cy + RADIUS * 0.58}
          textAnchor="middle" fill="rgba(255,255,255,0.25)"
          fontSize={size * 0.055} fontFamily="'JetBrains Mono', monospace" aria-hidden="true">100</text>
      </svg>
    </div>
  );
}

// Mini inline version for cards/rows
export function MiniRiskMeter({ score, width = 120 }: { score: number; width?: number }) {
  const color = scoreToColor(score);
  return (
    <div style={{ width, height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden' }}>
      <motion.div
        style={{ height: '100%', background: color, borderRadius: 2 }}
        initial={{ width: 0 }}
        animate={{ width: `${score}%` }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
        aria-hidden="true"
      />
    </div>
  );
}
