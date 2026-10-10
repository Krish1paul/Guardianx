import { AnimatePresence, motion, type Variants } from 'framer-motion';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { MotionCursor } from '@/components/ui/MotionCursor';
import { QuickScanModal } from '@/components/ui/QuickScanModal';

const pageVariants: Variants = {
  initial: { opacity: 0, y: 10 },
  enter:   { opacity: 1, y: 0, transition: { duration: 0.22, ease: 'easeOut' } },
  exit:    { opacity: 0, y: -6, transition: { duration: 0.12, ease: 'easeOut' } },
};

export function AppShell() {
  const location = useLocation();

  return (
    <div className="app-shell">
      {/* Subtle Motion Cursor (desktop only) */}
      <MotionCursor />

      {/* Global Quick Scan Modal */}
      <QuickScanModal />

      {/* Navigation Sidebar */}
      <Sidebar />

      {/* Main Command Center Area */}
      <div className="app-main">
        <Topbar />
        <main className="app-content" id="main-content">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={location.pathname}
              variants={pageVariants}
              initial="initial"
              animate="enter"
              exit="exit"
              style={{ height: '100%' }}
            >
              <Outlet />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
