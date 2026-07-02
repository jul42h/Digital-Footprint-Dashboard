import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

const SIDEBAR_KEY = "df-sidebar-collapsed";
export const MOBILE_BREAKPOINT_PX = 900;

type LayoutContextValue = {
  sidebarCollapsed: boolean;
  isMobile: boolean;
  sidebarOverlayOpen: boolean;
  toggleSidebar: () => void;
  closeSidebarOverlay: () => void;
  setSidebarCollapsed: (value: boolean) => void;
};

const LayoutContext = createContext<LayoutContextValue | null>(null);

export function LayoutProvider({ children }: { children: ReactNode }) {
  const [isMobile, setIsMobile] = useState(
    () => window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT_PX}px)`).matches,
  );
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const stored = localStorage.getItem(SIDEBAR_KEY);
    if (stored === "true" || stored === "false") return stored === "true";
    return window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT_PX}px)`).matches;
  });

  const sidebarOverlayOpen = isMobile && !sidebarCollapsed;

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((c) => !c);
  }, []);

  const closeSidebarOverlay = useCallback(() => {
    if (isMobile) setSidebarCollapsed(true);
  }, [isMobile]);

  useEffect(() => {
    localStorage.setItem(SIDEBAR_KEY, String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  useEffect(() => {
    const mq = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT_PX}px)`);
    const onChange = () => {
      const mobile = mq.matches;
      setIsMobile(mobile);
      if (mobile) setSidebarCollapsed(true);
    };
    onChange();
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    if (!sidebarOverlayOpen) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [sidebarOverlayOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "[" || e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      e.preventDefault();
      toggleSidebar();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleSidebar]);

  const value = useMemo(
    () => ({
      sidebarCollapsed,
      isMobile,
      sidebarOverlayOpen,
      toggleSidebar,
      closeSidebarOverlay,
      setSidebarCollapsed,
    }),
    [sidebarCollapsed, isMobile, sidebarOverlayOpen, toggleSidebar, closeSidebarOverlay],
  );

  return <LayoutContext.Provider value={value}>{children}</LayoutContext.Provider>;
}

export function useLayout() {
  const ctx = useContext(LayoutContext);
  if (!ctx) throw new Error("useLayout must be used within LayoutProvider");
  return ctx;
}
