import { QueryClientProvider } from "@tanstack/react-query";
import { AppErrorBoundary } from "./components/common/AppErrorBoundary";
import { appQueryClient } from "./query-client";
import RuntimeApp from "./runtime/RuntimeApp";
export default function App() {
  return <AppErrorBoundary><QueryClientProvider client={appQueryClient}><RuntimeApp /></QueryClientProvider></AppErrorBoundary>;
}
