import { createBrowserRouter, type RouteObject } from "react-router-dom";

import { AppShell } from "./components/layout/AppShell";
import { ProtectedRoute } from "./components/layout/ProtectedRoute";
import { DashboardPage } from "./pages/DashboardPage";
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { ReposPage } from "./pages/ReposPage";
import { ScanPage } from "./pages/ScanPage";

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
    ],
  },
];

export const router = createBrowserRouter(routes);
