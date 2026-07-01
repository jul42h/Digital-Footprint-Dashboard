import type { ReactNode } from "react";
import { Outlet } from "react-router-dom";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsHelp";
import { LayoutProvider } from "@/context/LayoutContext";
import { BackToTop } from "./BackToTop";
import { ScrollToTop } from "./ScrollToTop";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export function AppLayout({ children }: { children?: ReactNode }) {
  return (
    <LayoutProvider>
      <div className="app-shell">
        <div className="app-shell__ambient" aria-hidden />
        <Sidebar />
        <div className="app-shell__main">
          <TopBar />
          <ScrollToTop />
          <main className="main">{children ?? <Outlet />}</main>
          <BackToTop />
        </div>
        <KeyboardShortcutsHelp />
      </div>
    </LayoutProvider>
  );
}
