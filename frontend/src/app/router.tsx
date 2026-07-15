import { lazy, Suspense } from "react";
import { createBrowserRouter } from "react-router-dom";
import { AppLayout } from "@/layout/AppLayout";
import { OverviewPage } from "@/features/overview/OverviewPage";

const InsightsPage = lazy(() =>
  import("@/features/insights/InsightsPage").then((m) => ({ default: m.InsightsPage })),
);
const ThreatTypesPage = lazy(() =>
  import("@/features/threats/ThreatTypesPage").then((m) => ({ default: m.ThreatTypesPage })),
);
const ThreatTypePage = lazy(() =>
  import("@/features/threats/ThreatTypePage").then((m) => ({ default: m.ThreatTypePage })),
);
const CvesPage = lazy(() =>
  import("@/features/cves/CvesPage").then((m) => ({ default: m.CvesPage })),
);
const CveDetailPage = lazy(() =>
  import("@/features/cves/CveDetailPage").then((m) => ({ default: m.CveDetailPage })),
);
const IpsPage = lazy(() =>
  import("@/features/ips/IpsPage").then((m) => ({ default: m.IpsPage })),
);
const IpDetailPage = lazy(() =>
  import("@/features/ips/IpDetailPage").then((m) => ({ default: m.IpDetailPage })),
);
const SolutionsPage = lazy(() =>
  import("@/features/solutions/SolutionsPage").then((m) => ({ default: m.SolutionsPage })),
);
const VendorsPage = lazy(() =>
  import("@/features/vendors/VendorsPage").then((m) => ({ default: m.VendorsPage })),
);
const VendorDetailPage = lazy(() =>
  import("@/features/vendors/VendorDetailPage").then((m) => ({ default: m.VendorDetailPage })),
);
const AnalyticsPage = lazy(() =>
  import("@/features/analytics/AnalyticsPage").then((m) => ({ default: m.AnalyticsPage })),
);
const AskAiPage = lazy(() =>
  import("@/features/ask-ai/AskAiPage").then((m) => ({ default: m.AskAiPage })),
);
const GuidePage = lazy(() =>
  import("@/features/guide/GuidePage").then((m) => ({ default: m.GuidePage })),
);
const SettingsPage = lazy(() =>
  import("@/features/settings/SettingsPage").then((m) => ({ default: m.SettingsPage })),
);

function LazyPage({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<div className="page-loading">Loading…</div>}>{children}</Suspense>;
}

export const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      { path: "/", element: <OverviewPage /> },
      {
        path: "/insights",
        element: (
          <LazyPage>
            <InsightsPage />
          </LazyPage>
        ),
      },
      {
        path: "/threats",
        element: (
          <LazyPage>
            <ThreatTypesPage />
          </LazyPage>
        ),
      },
      {
        path: "/threats/:type",
        element: (
          <LazyPage>
            <ThreatTypePage />
          </LazyPage>
        ),
      },
      {
        path: "/cves",
        element: (
          <LazyPage>
            <CvesPage />
          </LazyPage>
        ),
      },
      {
        path: "/cves/:id",
        element: (
          <LazyPage>
            <CveDetailPage />
          </LazyPage>
        ),
      },
      {
        path: "/ips",
        element: (
          <LazyPage>
            <IpsPage />
          </LazyPage>
        ),
      },
      {
        path: "/ips/:address",
        element: (
          <LazyPage>
            <IpDetailPage />
          </LazyPage>
        ),
      },
      {
        path: "/solutions",
        element: (
          <LazyPage>
            <SolutionsPage />
          </LazyPage>
        ),
      },
      {
        path: "/vendors",
        element: (
          <LazyPage>
            <VendorsPage />
          </LazyPage>
        ),
      },
      {
        path: "/vendors/:id",
        element: (
          <LazyPage>
            <VendorDetailPage />
          </LazyPage>
        ),
      },
      {
        path: "/analytics",
        element: (
          <LazyPage>
            <AnalyticsPage />
          </LazyPage>
        ),
      },
      {
        path: "/ask",
        element: (
          <LazyPage>
            <AskAiPage />
          </LazyPage>
        ),
      },
      {
        path: "/guide",
        element: (
          <LazyPage>
            <GuidePage />
          </LazyPage>
        ),
      },
      {
        path: "/settings",
        element: (
          <LazyPage>
            <SettingsPage />
          </LazyPage>
        ),
      },
    ],
  },
]);
