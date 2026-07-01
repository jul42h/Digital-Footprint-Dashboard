import type { ReactNode } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { ScrollToTop } from "./ScrollToTop";

export function AppLayout({ children }: { children?: ReactNode }) {
  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden" }}>
      <Sidebar />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <TopBar />
        <ScrollToTop />
        <main className="main">{children ?? <Outlet />}</main>
      </div>
    </div>
  );
}
