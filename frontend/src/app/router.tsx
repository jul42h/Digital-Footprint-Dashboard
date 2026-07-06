import { createBrowserRouter } from "react-router-dom";
import { AppLayout } from "@/layout/AppLayout";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { ThreatTypesPage } from "@/features/threats/ThreatTypesPage";
import { ThreatTypePage } from "@/features/threats/ThreatTypePage";
import { CvesPage } from "@/features/cves/CvesPage";
import { CveDetailPage } from "@/features/cves/CveDetailPage";
import { IpsPage } from "@/features/ips/IpsPage";
import { IpDetailPage } from "@/features/ips/IpDetailPage";
import { SolutionsPage } from "@/features/solutions/SolutionsPage";
import { VendorsPage } from "@/features/vendors/VendorsPage";
import { VendorDetailPage } from "@/features/vendors/VendorDetailPage";
import { AnalyticsPage } from "@/features/analytics/AnalyticsPage";
import { GuidePage } from "@/features/guide/GuidePage";
import { SettingsPage } from "@/features/settings/SettingsPage";

export const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      { path: "/", element: <OverviewPage /> },
      { path: "/threats", element: <ThreatTypesPage /> },
      { path: "/threats/:type", element: <ThreatTypePage /> },
      { path: "/cves", element: <CvesPage /> },
      { path: "/cves/:id", element: <CveDetailPage /> },
      { path: "/ips", element: <IpsPage /> },
      { path: "/ips/:address", element: <IpDetailPage /> },
      { path: "/solutions", element: <SolutionsPage /> },
      { path: "/vendors", element: <VendorsPage /> },
      { path: "/vendors/:id", element: <VendorDetailPage /> },
      { path: "/analytics", element: <AnalyticsPage /> },
      { path: "/guide", element: <GuidePage /> },
      { path: "/settings", element: <SettingsPage /> },
    ],
  },
]);
