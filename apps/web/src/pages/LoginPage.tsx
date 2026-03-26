import { Link, Navigate, useSearchParams } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";
import { useAuth } from "../hooks/useAuth";

const providerActions = [
  {
    provider: "github",
    label: "Continue with GitHub",
    eyebrow: "Repository provider",
    description: "Authorize GitHub access and move directly into secure repository orchestration.",
    glyph: "GH",
  },
  {
    provider: "gitlab",
    label: "Continue with GitLab",
    eyebrow: "Self-managed friendly",
    description: "Use the same controlled access flow for GitLab-hosted repositories and scans.",
    glyph: "GL",
  },
] as const;

const trustSignals = [
  "Session-based access",
  "Provider OAuth only",
  "Java-first analysis",
] as const;

function getAuthErrorMessage(errorCode: string | null): string | null {
  if (!errorCode) {
    return null;
  }

  if (errorCode === "oauth_failed") {
    return "Authentication could not be completed. Please choose a provider and try again.";
  }

  return "We could not complete secure sign-in. Please try again.";
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
      <div className="login-shell">
        <header className="login-topbar" aria-label="AegisAI sign-in header">
          <div>
            <p className="eyebrow">AegisAI</p>
            <p className="login-header-title">Secure login for repository-scoped analysis</p>
          </div>
          <Link className="login-back-link" to="/">
            Back to overview
          </Link>
        </header>

        <section className="login-access-layout">
          <div className="login-access-copy">
            <p className="eyebrow">Step two</p>
            <h1>Secure access for repository scanning.</h1>
            <p className="login-lead">
              Continue with the provider that owns your repositories and keep access explicit from
              session bootstrap through scan initiation.
            </p>

            <div className="login-trust-strip" aria-label="Session and repository access notes">
              {trustSignals.map((signal) => (
                <span key={signal}>{signal}</span>
              ))}
            </div>
          </div>

          <section className="login-access-card" aria-label="AegisAI provider access">
            <div className="login-card-header">
              <p className="eyebrow">Access portal</p>
              <h2>Continue with your provider</h2>
              <p className="login-card-copy">
                Authorize once, then move directly into protected repository management and scan
                orchestration.
              </p>
            </div>

            {errorMessage ? (
              <div className="login-alert" role="alert">
                <strong>Authentication could not be completed.</strong>
                <p>{errorMessage}</p>
              </div>
            ) : null}

            {!errorMessage && bootstrapErrorMessage ? (
              <div className="login-alert" role="alert">
                <strong>Existing session unavailable.</strong>
                <p>{bootstrapErrorMessage}</p>
              </div>
            ) : null}

            {isLoading ? (
              <div className="login-loading" role="status">
                <strong>Checking your session...</strong>
                <p>If an active session exists, we will route you back into the protected workspace.</p>
              </div>
            ) : (
              <div className="provider-actions">
                {providerActions.map((action) => (
                  <a
                    key={action.provider}
                    className="provider-button"
                    href={getProviderLoginUrl(action.provider)}
                  >
                    <span className="provider-button-topline">
                      <span className="provider-glyph" aria-hidden="true">
                        {action.glyph}
                      </span>
                      <span className="provider-button-eyebrow">{action.eyebrow}</span>
                    </span>
                    <strong>{action.label}</strong>
                    <span className="provider-button-copy">{action.description}</span>
                  </a>
                ))}
              </div>
            )}

            <div className="login-footer-note">
              <p>Session-controlled entry stays aligned with provider authorization from the first action.</p>
            </div>
          </section>
        </section>
      </div>
    </main>
  );
}
