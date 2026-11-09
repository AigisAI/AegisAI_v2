import { createBrowserRouter, Navigate, type RouteObject } from "react-router-dom";

import { AppShell } from "./components/layout/AppShell";
import { ProtectedRoute } from "./components/layout/ProtectedRoute";
import { LocalDemoAuthRedirect } from "./components/auth/LocalDemoAuthRedirect";
import { DashboardPage } from "./pages/DashboardPage";
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { PricingPage } from "./pages/PricingPage";
import { ReportPage } from "./pages/ReportPage";
import { ReposPage } from "./pages/ReposPage";
import { ScanPage } from "./pages/ScanPage";
import { VulnerabilityReviewPage } from "./pages/VulnerabilityReviewPage";

export const routes: RouteObject[] = [
  {
    path: "/",
    element: <LandingPage />,
  },
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/pricing",
    element: <PricingPage />,
  },
  {
    path: "/demo",
    element: <Navigate replace to="/login?demo=1" />,
  },
  {
    path: "/api/auth/github",
    element: <LocalDemoAuthRedirect provider="github" />,
  },
  {
    path: "/api/auth/gitlab",
    element: <LocalDemoAuthRedirect provider="gitlab" />,
  },
  {
    element: (
      <ProtectedRoute>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      {
        path: "/dashboard",
        element: <DashboardPage />,
      },
      {
        path: "/repos",
        element: <ReposPage />,
      },
      {
        path: "/scan",
        element: <ScanPage />,
      },
      {
        path: "/scan/:scanId/review",
        element: <VulnerabilityReviewPage />,
      },
      {
        path: "/reports/:reportId",
        element: <ReportPage />,
      },
    ],
  },
];

export const router = createBrowserRouter(routes);
