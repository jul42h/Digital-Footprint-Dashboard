import type { ReactNode } from "react";
import { Outlet } from "react-router-dom";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { LayoutProvider, useLayout } from "@/context/LayoutContext";
import { BackToTop } from "./BackToTop";
import { ScrollToTop } from "./ScrollToTop";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

function AppShell() {
  const { sidebarOverlayOpen, closeSidebarOverlay } = useLayout();

  return (
    <div className="app-shell">
      <div className="app-shell__ambient" aria-hidden />
      {sidebarOverlayOpen && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close navigation menu"
          onClick={closeSidebarOverlay}
        />
      )}
      <Sidebar />
      <div className="app-shell__main">
        <TopBar />
        <ScrollToTop />
        <main className="main">
          <Outlet />
        </main>
        <BackToTop />
      </div>
      <KeyboardShortcutsHelp />
    </div>
  );
}

export function AppLayout({ children }: { children?: ReactNode }) {
  return (
    <LayoutProvider>
      {children ? (
        <div className="app-shell">
          <div className="app-shell__ambient" aria-hidden />
          <Sidebar />
          <div className="app-shell__main">
            <TopBar />
            <main className="main">{children}</main>
          </div>
        </div>
      ) : (
        <AppShell />
      )}
    </LayoutProvider>
  );
}
