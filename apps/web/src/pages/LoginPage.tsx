import { Navigate, useSearchParams } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";
import { useAuth } from "../hooks/useAuth";

const providerActions = [
  {
    provider: "github",
    label: "Continue with GitHub",
    eyebrow: "Repository provider",
    description: "Authorize GitHub repositories and step directly into branch-aware scan setup.",
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
    <main className="login-page premium-login-page">
      <div className="premium-login-shell">
        <header className="premium-login-header" aria-label="AegisAI sign-in header">
          <div className="premium-brand-lockup">
            <p className="eyebrow">AegisAI</p>
            <p className="premium-brand-copy">Protected repository scanning workspace</p>
          </div>
          <p className="premium-header-meta">Session-controlled entry for provider-scoped access</p>
        </header>

        <section className="premium-login-grid">
          <div className="premium-login-hero">
            <p className="eyebrow">Secure workspace access</p>
            <h1>Secure Repository Access.</h1>
            <p className="premium-login-lead">
              Enter the AegisAI workspace through GitHub or GitLab and keep repository access
              explicit from the first session.
            </p>

            <div className="premium-trust-strip" aria-label="Session and repository access notes">
              {trustSignals.map((signal) => (
                <span key={signal}>{signal}</span>
              ))}
            </div>

            <div className="premium-login-summary">
              <div className="premium-summary-card">
                <p className="eyebrow">Controlled by design</p>
                <p>
                  Provider-scoped authorization, branch-aware handoff, and scan initiation stay
                  inside one guarded flow.
                </p>
              </div>
              <div className="premium-summary-metrics" aria-label="Security-first access highlights">
                <div>
                  <strong>01</strong>
                  <span>Session-gated entry</span>
                </div>
                <div>
                  <strong>02</strong>
                  <span>Repository trust context</span>
                </div>
                <div>
                  <strong>03</strong>
                  <span>Java-first scan setup</span>
                </div>
              </div>
            </div>
          </div>

          <section className="premium-login-card" aria-label="AegisAI provider access">
            <div className="premium-login-card-header">
              <p className="eyebrow">Premium access</p>
              <h2>Continue with your provider</h2>
              <p className="premium-login-card-copy">
                Authorize a provider once and move straight into protected repository management
                and scan orchestration.
              </p>
            </div>

            {errorMessage ? (
              <div className="premium-status-panel is-error" role="alert">
                <strong>Authentication could not be completed.</strong>
                <p>{errorMessage}</p>
              </div>
            ) : null}

            {!errorMessage && bootstrapErrorMessage ? (
              <div className="premium-status-panel is-error" role="alert">
                <strong>Existing session unavailable.</strong>
                <p>{bootstrapErrorMessage}</p>
              </div>
            ) : null}

            {isLoading ? (
              <div className="premium-status-panel is-loading" role="status">
                <strong>Checking your session...</strong>
                <p>If an active session exists, we will route you back into the protected workspace.</p>
              </div>
            ) : (
              <div className="premium-provider-actions">
                {providerActions.map((action) => (
                  <a
                    key={action.provider}
                    className="premium-provider-button"
                    href={getProviderLoginUrl(action.provider)}
                  >
                    <span className="premium-provider-button-topline">
                      <span className="premium-provider-glyph" aria-hidden="true">
                        {action.glyph}
                      </span>
                      <span className="premium-provider-button-eyebrow">{action.eyebrow}</span>
                    </span>
                    <strong>{action.label}</strong>
                    <span className="premium-provider-button-copy">{action.description}</span>
                  </a>
                ))}
              </div>
            )}

            <div className="premium-login-card-footer">
              <div className="premium-card-signal-row">
                <span>Session protected</span>
                <span>Provider scoped</span>
                <span>Scan ready</span>
              </div>
              <p>Choose the provider that owns the repositories you want to evaluate.</p>
            </div>
          </section>
        </section>
      </div>
    </main>
  );
}
