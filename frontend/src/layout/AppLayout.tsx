import { LayoutProvider, useLayout } from "@/context/LayoutContext";
import { Outlet } from "react-router-dom";
import { DataStatusBanner } from "@/components/DataStatusBanner";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { AskAiProvider } from "@/features/ask-ai/AskAiContext";
import { AskAiWidget } from "@/features/ask-ai/AskAiWidget";
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
        <DataStatusBanner />
        <ScrollToTop />
        <main className="main">
          <Outlet />
        </main>
        <BackToTop />
      </div>
      <AskAiWidget />
      <KeyboardShortcutsHelp />
    </div>
  );
}

export function AppLayout() {
  return (
    <LayoutProvider>
      <AskAiProvider>
        <AppShell />
      </AskAiProvider>
    </LayoutProvider>
  );
}
