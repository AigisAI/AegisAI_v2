import { Link, Navigate, useSearchParams } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";
import { useAuth } from "../hooks/useAuth";

const providerActions = [
  {
    provider: "github",
    label: "Continue with GitHub",
    description:
      "Authorize repository access through GitHub and move directly into secure orchestration.",
    glyph: "GH",
  },
  {
    provider: "gitlab",
    label: "Continue with GitLab",
    description:
      "Use the same controlled access flow for GitLab-hosted repositories and scan entry.",
    glyph: "GL",
  },
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
      ? "We could not verify your existing session. You can still continue with a provider."
      : null;

  return (
    <main className="login-page-v2">
      <header className="login-topbar-v2">
        <div className="login-topbar-inner-v2">
          <div className="login-brand-group-v2">
            <span className="login-wordmark-v2">AegisAI</span>

            <nav className="login-topnav-v2" aria-label="Public login navigation">
              <a href="/#security">Security</a>
              <a href="/#resources">Support</a>
            </nav>
          </div>

          <div className="login-topbar-actions-v2">
            <a className="landing-inline-link" href="/#pricing">
              Enterprise
            </a>
          </div>
        </div>
      </header>

      <div className="login-shell-v2">
        <section className="login-intro-v2">
          <h1>Authenticate Your Security</h1>
          <p>
            AegisAI uses provider-scoped, session-controlled access to preserve trust from sign-in
            through repository-scoped Java analysis.
          </p>
        </section>

        <section className="login-card-v2" aria-label="Secure provider access">
          <div className="login-card-accent" aria-hidden="true" />

          {(errorMessage || bootstrapErrorMessage) && !isLoading ? (
            <div className="login-alert-v2" role="alert">
              <strong>
                {errorMessage ? "Authentication unavailable" : "Existing session unavailable"}
              </strong>
              <p>{errorMessage ?? bootstrapErrorMessage}</p>
            </div>
          ) : null}

          <div className="login-provider-actions-v2">
            {providerActions.map((action) => (
              <a
                key={action.provider}
                className="login-provider-button-v2"
                href={getProviderLoginUrl(action.provider)}
              >
                <div className="login-provider-copy-v2">
                  <span className="login-provider-glyph-v2" aria-hidden="true">
                    {action.glyph}
                  </span>
                  <span>{action.label}</span>
                </div>
                <span className="login-provider-arrow-v2" aria-hidden="true">
                  -&gt;
                </span>
                <p>{action.description}</p>
              </a>
            ))}
          </div>

          <div className="login-status-block-v2">
            {isLoading ? (
              <div className="login-loading-row-v2" role="status">
                <span className="login-loading-spinner-v2" aria-hidden="true" />
                <span>Awaiting Provider Response</span>
              </div>
            ) : null}

            <div className="login-trust-grid-v2">
              <div className="login-trust-chip-v2 login-trust-chip-strong-v2">SOC2 Compliant</div>
              <div className="login-trust-chip-v2">Encrypted Sessions</div>
            </div>
          </div>
        </section>

        <div className="login-backlink-wrap-v2">
          <Link className="login-back-link-v2" to="/">
            Back to overview
          </Link>
        </div>
      </div>
    </main>
  );
}
