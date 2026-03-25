import { Navigate, useSearchParams } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";
import { useAuth } from "../hooks/useAuth";

const providerActions = [
  {
    provider: "github",
    label: "Continue with GitHub",
    eyebrow: "OAuth provider",
    description: "Connect your GitHub repositories and start the first Java security scan.",
  },
  {
    provider: "gitlab",
    label: "Continue with GitLab",
    eyebrow: "Self-managed friendly",
    description: "Use the same session flow for GitLab-hosted repositories and branch scans.",
  },
] as const;

function getAuthErrorMessage(errorCode: string | null): string | null {
  if (!errorCode) {
    return null;
  }

  if (errorCode === "oauth_failed") {
    return "Login did not complete successfully. Please choose a provider and try again.";
  }

  return "We could not complete sign-in. Please try again.";
}

export function LoginPage() {
  const { user, isLoading, bootstrapState } = useAuth();
  const [searchParams] = useSearchParams();

  if (user) {
    return <Navigate replace to="/dashboard" />;
  }

  const errorMessage = getAuthErrorMessage(searchParams.get("error"));
  const bootstrapErrorMessage =
    bootstrapState === "error"
      ? "We could not verify your existing session. You can still choose a provider and try again."
      : null;

  return (
    <main className="login-page">
      <section className="login-hero">
        <div className="login-copy">
          <p className="eyebrow">AegisAI MVP</p>
          <h1>Secure Java repository scanning without leaving your provider flow.</h1>
          <p className="login-lead">
            Start with GitHub or GitLab, keep session-based access, and move straight into
            repository connection and queued scanning once authentication completes.
          </p>

          <div className="login-trust-strip" aria-label="Session and repository access notes">
            <span>Session-based auth</span>
            <span>Provider OAuth only</span>
            <span>Java-first MVP</span>
          </div>
        </div>

        <div className="login-card">
          <p className="eyebrow">Sign in to continue</p>
          <h2>Choose your repository provider</h2>
          <p className="login-card-copy">
            AegisAI uses your provider session only to discover repositories, branches, and
            scan context.
          </p>

          {errorMessage ? (
            <div className="login-alert" role="alert">
              {errorMessage}
            </div>
          ) : null}

          {!errorMessage && bootstrapErrorMessage ? (
            <div className="login-alert" role="alert">
              {bootstrapErrorMessage}
            </div>
          ) : null}

          {isLoading ? (
            <div className="login-loading" role="status">
              <strong>Checking your session...</strong>
              <p>If you already signed in, we will take you back to the workspace.</p>
            </div>
          ) : (
            <div className="provider-actions">
              {providerActions.map((action) => (
                <a
                  key={action.provider}
                  className="provider-button"
                  href={getProviderLoginUrl(action.provider)}
                >
                  <span className="provider-button-eyebrow">{action.eyebrow}</span>
                  <strong>{action.label}</strong>
                  <span className="provider-button-copy">{action.description}</span>
                </a>
              ))}
            </div>
          )}
        </div>
      </section>
    </main>
  );
}
