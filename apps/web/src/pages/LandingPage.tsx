import { Link } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";

const trustSignals = [
  "Provider-scoped access",
  "Session-first orchestration",
  "Java-first analysis",
] as const;

const workflowSteps = [
  {
    step: "01",
    title: "Connect provider",
    description:
      "Authenticate through GitHub or GitLab and keep repository access explicit from the start.",
  },
  {
    step: "02",
    title: "Choose repository and branch",
    description:
      "Move into repository context, validate branch scope, and keep the scan handoff controlled.",
  },
  {
    step: "03",
    title: "Run scan",
    description:
      "Queue repository analysis and review structured findings without breaking provider trust boundaries.",
  },
] as const;

const assurancePoints = [
  "Sessions stay controlled from first entry to scan execution.",
  "Provider OAuth keeps repository authorization explicit and revocable.",
  "Branch-aware handoff reduces noise before scan orchestration begins.",
] as const;

const footerColumns = [
  {
    title: "Product",
    links: ["Methodology", "Security posture", "Support"],
  },
  {
    title: "Access",
    links: ["GitHub start", "GitLab start", "Login"],
  },
  {
    title: "Company",
    links: ["Privacy", "Terms", "Contact"],
  },
] as const;

export function LandingPage() {
  return (
    <main className="landing-page">
      <div className="landing-shell">
        <header className="landing-nav" aria-label="AegisAI public navigation">
          <div className="landing-brand-lockup">
            <p className="eyebrow">AegisAI</p>
            <p className="landing-brand-copy">Repository security scanning for engineering teams</p>
          </div>

          <nav className="landing-nav-links" aria-label="Public">
            <a href="#workflow">Workflow</a>
            <a href="#trust">Trust</a>
            <a href="#start">Get started</a>
            <Link to="/login">Log in</Link>
          </nav>
        </header>

        <section className="landing-hero">
          <div className="landing-hero-copy">
            <p className="eyebrow">Java-first repository security</p>
            <h1>Precision Security for Java Ecosystems.</h1>
            <p className="landing-lead">
              AegisAI helps engineering teams move from provider-authenticated repository access to
              branch-aware Java scanning with a controlled, trust-first workflow.
            </p>

            <div className="landing-cta-row">
              <a className="landing-primary-cta" href={getProviderLoginUrl("github")}>
                Start with GitHub
              </a>
              <a className="landing-secondary-cta" href={getProviderLoginUrl("gitlab")}>
                Start with GitLab
              </a>
              <Link className="landing-text-cta" to="/login">
                View access portal
              </Link>
            </div>

            <div className="landing-trust-strip" aria-label="Trust signals">
              {trustSignals.map((signal) => (
                <span key={signal}>{signal}</span>
              ))}
            </div>
          </div>

          <aside className="landing-hero-panel" aria-label="AegisAI trust summary">
            <div className="landing-panel-card">
              <p className="eyebrow">Operational clarity</p>
              <h2>Repository trust, branch intent, and scan initiation stay inside one calm flow.</h2>
              <p>
                Designed for teams who want secure access control without dropping into a noisy
                security dashboard on first contact.
              </p>
            </div>

            <div className="landing-panel-metrics">
              <div>
                <strong>01</strong>
                <span>Controlled provider entry</span>
              </div>
              <div>
                <strong>02</strong>
                <span>Branch-aware setup</span>
              </div>
              <div>
                <strong>03</strong>
                <span>Scan-ready workspace</span>
              </div>
            </div>
          </aside>
        </section>

        <section className="landing-logo-strip" aria-label="Trusted by security-first teams">
          <span>Vantage</span>
          <span>Oracle</span>
          <span>Lumina</span>
          <span>Kinetic</span>
          <span>Zenith</span>
        </section>

        <section className="landing-workflow" id="workflow">
          <div className="landing-section-heading">
            <p className="eyebrow">How it works</p>
            <h2>Designed for the secure path from access to scan.</h2>
          </div>

          <div className="landing-step-grid">
            {workflowSteps.map((step) => (
              <article key={step.step} className="landing-step-card">
                <p className="landing-step-index">{step.step}</p>
                <h3>{step.title}</h3>
                <p>{step.description}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="landing-assurance" id="trust">
          <div className="landing-section-heading">
            <p className="eyebrow">Why teams trust this flow</p>
            <h2>Low-friction entry, explicit authorization, and a cleaner handoff into real work.</h2>
          </div>

          <div className="landing-assurance-grid">
            {assurancePoints.map((point) => (
              <article key={point} className="landing-assurance-card">
                <p>{point}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="landing-final-cta" id="start">
          <div>
            <p className="eyebrow">Start your secure workflow</p>
            <h2>Open a repository-scoped path into AegisAI.</h2>
            <p>
              Pick the provider that owns your repositories and move straight into the controlled
              access flow.
            </p>
          </div>

          <div className="landing-final-actions">
            <a className="landing-primary-cta" href={getProviderLoginUrl("github")}>
              Begin with GitHub access
            </a>
            <Link className="landing-text-cta" to="/login">
              Open secure portal
            </Link>
          </div>
        </section>

        <footer className="landing-footer">
          {footerColumns.map((column) => (
            <div key={column.title} className="landing-footer-column">
              <p className="eyebrow">{column.title}</p>
              <ul>
                {column.links.map((link) => (
                  <li key={link}>{link}</li>
                ))}
              </ul>
            </div>
          ))}
        </footer>
      </div>
    </main>
  );
}
