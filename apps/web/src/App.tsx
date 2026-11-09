import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";

import { AppErrorBoundary } from "./components/common/AppErrorBoundary";
import { appQueryClient } from "./query-client";
import { router } from "./router";
import RuntimeApp from "./runtime/RuntimeApp";

export default function App() {
  return (
    <AppErrorBoundary>
      <QueryClientProvider client={appQueryClient}>
        {import.meta.env.VITE_PRODUCTION_RUNTIME === "true" ? <RuntimeApp /> : <RouterProvider router={router} />}
      </QueryClientProvider>
    </AppErrorBoundary>
  );
}

