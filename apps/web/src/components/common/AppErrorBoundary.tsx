import type { ErrorInfo, ReactNode } from "react";
import { Component } from "react";

interface AppErrorBoundaryProps {
  children: ReactNode;
}

interface AppErrorBoundaryState {
  hasError: boolean;
}

export class AppErrorBoundary extends Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  public state: AppErrorBoundaryState = {
    hasError: false,
  };

  public static getDerivedStateFromError(): AppErrorBoundaryState {
    return {
      hasError: true,
    };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    void error;
    void errorInfo;
  }

  public render() {
    if (this.state.hasError) {
      return (
        <main className="standalone-page">
          <div className="placeholder-card">
            <p className="eyebrow">Application error</p>
            <h1>Something went wrong.</h1>
            <p>Reload the page and try again.</p>
          </div>
        </main>
      );
    }

    return this.props.children;
  }
}
