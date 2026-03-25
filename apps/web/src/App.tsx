import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";

import { AppErrorBoundary } from "./components/common/AppErrorBoundary";
import { appQueryClient } from "./query-client";
import { router } from "./router";

export default function App() {
  return (
    <AppErrorBoundary>
      <QueryClientProvider client={appQueryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </AppErrorBoundary>
  );
}
