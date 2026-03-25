import { Navigate, useSearchParams } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";
import { useAuth } from "../hooks/useAuth";

const providerActions = [
  {
    provider: "github",
    label: "Continue with GitHub",
    eyebrow: "Repository provider",
    description: "Connect GitHub repositories and move directly into branch-aware Java scanning.",
    glyph: "GH",
  },
  {
    provider: "gitlab",
    label: "Continue with GitLab",
    eyebrow: "Self-managed friendly",
    description: "Use the same session flow for GitLab-hosted repositories and queued scans.",
    glyph: "GL",
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
      <header className="login-header" aria-label="AegisAI sign-in header">
        <div>
          <p className="eyebrow">AegisAI</p>
          <p className="login-header-title">Security workspace for repository trust decisions</p>
        </div>
        <p className="login-header-meta">Session-first access for Java repository scanning</p>
      </header>

      <section className="login-hero">
        <div className="login-copy">
          <p className="eyebrow">Editorial security login</p>
          <h1>Secure Java scanning that stays in your provider flow.</h1>
          <p className="login-lead">
            Authenticate with GitHub or GitLab, keep session-based control, and move straight
            into repository connection and queued branch scans once sign-in completes.
          </p>
          <p className="login-support-copy">
            AegisAI only uses provider-authorized repository, branch, and scan context. Your
            access stays explicit from the first screen.
          </p>

          <div className="login-trust-strip" aria-label="Session and repository access notes">
            <span>Session-based auth</span>
            <span>Provider OAuth only</span>
            <span>Java-first MVP</span>
          </div>

          <dl className="login-facts" aria-label="Security-first access highlights">
            <div>
              <dt>01</dt>
              <dd>Authenticate once, then continue into repository selection without a detached auth silo.</dd>
            </div>
            <div>
              <dt>02</dt>
              <dd>OAuth tokens are scoped to repository discovery, branch context, and scan execution.</dd>
            </div>
          </dl>
        </div>

        <div className="login-card">
          <div className="login-card-header">
            <p className="eyebrow">Access portal</p>
            <h2>Choose a provider and enter the workspace.</h2>
            <p className="login-card-copy">
              Use the same session flow for repository discovery, branch validation, and scan
              kickoff. Nothing starts until you authorize the provider you trust.
            </p>
          </div>

          {errorMessage ? (
            <div className="login-alert" role="alert">
              <strong>Authentication did not complete.</strong>
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
              <p>If you already signed in, we will route you back to the protected workspace.</p>
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
            <p>Security architecture remains session-aware and provider-scoped from first login.</p>
            <p>Continue with the provider that owns the repositories you want to scan.</p>
          </div>
        </div>
      </section>
    </main>
  );
}
