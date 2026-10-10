import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

interface UIContextValue {
  mobileSidebarOpen: boolean;
  setMobileSidebarOpen: (open: boolean | ((prev: boolean) => boolean)) => void;
  quickScanOpen: boolean;
  setQuickScanOpen: (open: boolean | ((prev: boolean) => boolean)) => void;
}

const UIContext = createContext<UIContextValue | undefined>(undefined);

export function UIProvider({ children }: { children: ReactNode }) {
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [quickScanOpen, setQuickScanOpen] = useState(false);

  // Global keyboard shortcut for Quick Scan (⌘K or Ctrl+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setQuickScanOpen((prev) => !prev);
      }
      if (e.key === 'Escape') {
        setQuickScanOpen(false);
        setMobileSidebarOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <UIContext.Provider
      value={{
        mobileSidebarOpen,
        setMobileSidebarOpen,
        quickScanOpen,
        setQuickScanOpen,
      }}
    >
      {children}
    </UIContext.Provider>
  );
}

export function useUI() {
  const context = useContext(UIContext);
  if (!context) {
    throw new Error('useUI must be used within a UIProvider');
  }
  return context;
}
