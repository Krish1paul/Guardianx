import { useEffect, useRef } from 'react';

export function MotionCursor() {
  const containerRef = useRef<HTMLDivElement>(null);
  const dotRef = useRef<HTMLDivElement>(null);
  const ringRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Disable on touch devices or if user prefers reduced motion
    const isTouch = window.matchMedia('(pointer: coarse)').matches;
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (isTouch || prefersReducedMotion) return;

    let targetX = -100;
    let targetY = -100;
    let dotX = -100;
    let dotY = -100;
    let ringX = -100;
    let ringY = -100;
    let isVisible = false;
    let animFrameId: number;

    const onMouseMove = (e: MouseEvent) => {
      targetX = e.clientX;
      targetY = e.clientY;

      if (!isVisible) {
        isVisible = true;
        dotX = targetX;
        dotY = targetY;
        ringX = targetX;
        ringY = targetY;
        if (containerRef.current) containerRef.current.style.opacity = '1';
      }

      // Card ambient illumination: update --mouse-x and --mouse-y on hovered cards
      const target = e.target as HTMLElement | null;
      if (target) {
        const card = target.closest('.glow-card, .glass-card, .metric-card') as HTMLElement | null;
        if (card) {
          const rect = card.getBoundingClientRect();
          card.style.setProperty('--mouse-x', `${e.clientX - rect.left}px`);
          card.style.setProperty('--mouse-y', `${e.clientY - rect.top}px`);
        }
      }
    };

    const onMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (!target || !containerRef.current) return;

      // Check for threat level element
      const threatCritical = target.closest('.metric-card-critical, [data-threat="CRITICAL"], [data-threat="HIGH_RISK"], .badge-critical');
      const threatSafe = target.closest('[data-threat="LOW_RISK"], .badge-safe, .metric-icon-safe');
      const interactive = target.closest('button, a, input, textarea, select, [role="button"], [data-cursor="pointer"], .sidebar-link, .recent-item, .history-row, .glow-card-interactive');

      // Reset classes
      containerRef.current.classList.remove('cursor-hover', 'cursor-critical', 'cursor-safe');

      if (threatCritical) {
        containerRef.current.classList.add('cursor-critical');
      } else if (threatSafe) {
        containerRef.current.classList.add('cursor-safe');
      } else if (interactive) {
        containerRef.current.classList.add('cursor-hover');
      }
    };

    const onMouseLeave = () => {
      isVisible = false;
      if (containerRef.current) containerRef.current.style.opacity = '0';
    };

    const onMouseEnter = () => {
      isVisible = true;
      if (containerRef.current) containerRef.current.style.opacity = '1';
    };

    // Smooth lerp animation loop
    const render = () => {
      if (isVisible) {
        // Fast follower for central dot
        dotX += (targetX - dotX) * 0.7;
        dotY += (targetY - dotY) * 0.7;

        // Smooth trailing lag for the glowing ring
        ringX += (targetX - ringX) * 0.18;
        ringY += (targetY - ringY) * 0.18;

        if (dotRef.current) {
          dotRef.current.style.transform = `translate3d(${dotX}px, ${dotY}px, 0)`;
        }
        if (ringRef.current) {
          ringRef.current.style.transform = `translate3d(${ringX}px, ${ringY}px, 0)`;
        }
      }
      animFrameId = requestAnimationFrame(render);
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('mouseover', onMouseOver, { passive: true });
    document.addEventListener('mouseleave', onMouseLeave);
    document.addEventListener('mouseenter', onMouseEnter);

    animFrameId = requestAnimationFrame(render);

    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('mouseover', onMouseOver);
      document.removeEventListener('mouseleave', onMouseLeave);
      document.removeEventListener('mouseenter', onMouseEnter);
      cancelAnimationFrame(animFrameId);
    };
  }, []);

  return (
    <div ref={containerRef} className="motion-cursor-container" style={{ opacity: 0 }} aria-hidden="true">
      <div ref={ringRef} className="cursor-ring" />
      <div ref={dotRef} className="cursor-dot" />
    </div>
  );
}
