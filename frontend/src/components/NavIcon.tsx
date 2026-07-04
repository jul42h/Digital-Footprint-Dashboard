type IconName =
  | "home"
  | "issues"
  | "threats"
  | "systems"
  | "fixes"
  | "providers"
  | "analytics"
  | "settings"
  | "collapse"
  | "expand";

const PATHS: Record<IconName, string> = {
  home: "M4 10.5L12 4l8 6.5V19a1 1 0 01-1 1h-5v-6H10v6H5a1 1 0 01-1-1v-8.5z",
  issues:
    "M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z",
  threats:
    "M12 2l7 4v6c0 5-3 9-7 10-4-1-7-5-7-10V6l7-4zm0 7v4m0 3h.01",
  systems:
    "M4 7a2 2 0 012-2h2v2H6v2H4V7zm12 0v2h-2V5h2a2 2 0 012 2v0zm-8 8H6v-2h2v2zm8 0h-2v-2h2v2zm-4 4h-2v-2h2v2z",
  fixes:
    "M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z",
  providers: "M4 19h16M6 16l6-12 6 12M9 16h6",
  analytics: "M4 19V5m6 14V9m6 10V3m6 16v-7",
  settings:
    "M12 15a3 3 0 100-6 3 3 0 000 6zm8.66-3a7.97 7.97 0 01-.17 1l2.09 1.63-2 3.46-2.52-1a8.06 8.06 0 01-1.73 1l-.38 2.7H9.05l-.38-2.7a8.06 8.06 0 01-1.73-1l-2.52 1-2-3.46L4.51 13a7.97 7.97 0 010-2l-2.09-1.63 2-3.46 2.52 1a8.06 8.06 0 011.73-1l.38-2.7h4.92l.38 2.7a8.06 8.06 0 011.73 1l2.52-1 2 3.46L19.49 11c.11.33.17.66.17 1z",
  collapse: "M15 18l-6-6 6-6",
  expand: "M9 18l6-6-6-6",
};

export function NavIcon({ name }: { name: IconName }) {
  return (
    <svg
      className="nav-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      aria-hidden
    >
      <path d={PATHS[name]} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
