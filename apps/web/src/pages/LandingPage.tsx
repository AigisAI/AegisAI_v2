import { Link } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";

const workflowSteps = [
  {
    step: "Step 01",
    title: "Scan repositories",
    description:
      "Automatic indexing of your Java ecosystem without manual setup, whether your team runs Maven, Gradle, or legacy build conventions.",
  },
  {
    step: "Step 02",
    title: "Identify vulnerabilities",
    description:
      "Context-aware analysis follows risky paths through your codebase so teams can focus on security issues that are actually actionable.",
  },
  {
    step: "Step 03",
    title: "Streamline fixes",
    description:
      "Move from validated findings to remediation guidance that fits the structure and standards of your existing Java platform.",
  },
] as const;

const trustLogos = ["VANTAGE", "ORACLE", "LUMINA", "KINETIC", "ZENITH"] as const;

const featureBullets = [
  "JVM-specific bytecode analysis",
  "Dependency shadowing detection",
  "Compliance-ready audit logs",
] as const;

const footerLinks = [
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

const heroImageUrl =
  "https://lh3.googleusercontent.com/aida-public/AB6AXuAZ1hd_z7bTBFzFWtvKq_jVE7nv_FKB76TDC9uGH0bv-HFmIYjaXq3JbrrRXAez6jsxv-X3KVRFdb6SbPj2OtjTlIGTgF_n-Vi9t9v-OlvLH56JifHNIqbTr2ic1hnmPjJvDLxzh_UTYZST9RGO_8FfT8ZffnB7lOddlKd1OllTMy43mKC0gSEOriKdfqDDuNXPYb0EJ3u5ziKKLmI-Q_-sbvAo88XM3DybZSX8rg4N_cAxk-VXmPJkEAPUtziHXSLnIrCSbdR4SBWK";

export function LandingPage() {
  return (
    <main className="landing-page">
      <header className="landing-topbar">
        <div className="landing-topbar-inner">
          <div className="landing-brand-group">
            <span className="landing-wordmark">AegisAI</span>

            <nav className="landing-topnav" aria-label="Public">
              <a href="#product">Product</a>
              <a href="#security">Security</a>
              <a href="#pricing">Pricing</a>
              <a href="#resources">Resources</a>
            </nav>
          </div>

          <div className="landing-topbar-actions">
            <Link className="landing-inline-link" to="/login">
              Log in
            </Link>
            <a className="landing-topbar-cta" href={getProviderLoginUrl("github")}>
              Connect GitHub
            </a>
          </div>
        </div>
      </header>

      <div className="landing-shell">
        <section className="landing-hero-v2" id="product">
          <div className="landing-hero-copy-v2">
            <div className="landing-badge">Precision Java Scanning</div>
            <h1>
              Security for Java,
              <br />
              <span>Built by Engineers.</span>
            </h1>
            <p className="landing-lead-v2">
              AegisAI provides deep, context-aware static analysis specifically architected for the
              complexity of Java ecosystems. No noise, just actionable remediation.
            </p>

            <div className="landing-cta-row-v2">
              <a className="landing-primary-cta-v2" href={getProviderLoginUrl("github")}>
                Connect GitHub
              </a>
              <a className="landing-secondary-cta-v2" href={getProviderLoginUrl("gitlab")}>
                Connect GitLab
              </a>
            </div>
          </div>

          <aside className="landing-hero-art">
            <div className="landing-hero-figure">
              <img
                alt="Abstract architectural composition in warm neutral tones"
                src={heroImageUrl}
              />

              <div className="landing-pullquote-card">
                <p>
                  &quot;AegisAI caught dependency vulnerabilities that generic scanners missed
                  during our legacy migration.&quot;
                </p>
                <span>Chief Architect, FinTech Global</span>
              </div>
            </div>
          </aside>
        </section>

        <section className="landing-trust-band">
          <p>Trusted by security-first teams</p>
          <div className="landing-logo-row">
            {trustLogos.map((logo) => (
              <span key={logo}>{logo}</span>
            ))}
          </div>
        </section>

        <section className="landing-section-v2 landing-workflow-v2">
          <div className="landing-section-heading-v2">
            <h2>Designed for the Modern Pipeline</h2>
            <div className="landing-accent-line" aria-hidden="true" />
          </div>

          <div className="landing-step-grid-v2">
            {workflowSteps.map((step) => (
              <article key={step.title} className="landing-step-card-v2">
                <div className="landing-step-icon" aria-hidden="true">
                  <span />
                </div>
                <p className="landing-step-kicker">{step.step}</p>
                <h3>{step.title}</h3>
                <p>{step.description}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="landing-security-story" id="security">
          <div className="landing-security-copy">
            <div className="landing-security-quote-mark" aria-hidden="true">
              "
            </div>
            <div className="landing-security-copy-inner">
              <h2>
                We don&apos;t just look for matches. We understand the
                <span> semantic intent </span>
                of your Java code.
              </h2>
              <p>
                Traditional scanners treat code like text. AegisAI treats code like logic. By
                building a comprehensive control-flow model of your application, teams can separate
                dangerous execution paths from safely handled data.
              </p>

              <ul className="landing-feature-list">
                {featureBullets.map((feature) => (
                  <li key={feature}>{feature}</li>
                ))}
              </ul>
            </div>
          </div>

          <div className="landing-code-panel">
            <div className="landing-code-window">
              <div className="landing-code-window-bar" aria-hidden="true">
                <span />
                <span />
                <span />
              </div>

              <pre>
                <code>
                  <span className="code-comment">// AegisAI Static Analysis</span>
                  {"\n"}
                  <span className="code-highlight">Scanning Module: OrderService.java</span>
                  {"\n\n"}
                  <span className="code-keyword">public void</span>{" "}
                  <span className="code-method">processOrder</span>(Request req) {"{"}
                  {"\n"}
                  <span className="code-danger">  ! High-Risk Data Flow Detected</span>
                  {"\n"}
                  {"  "}String input = req.getQueryParam("id");
                  {"\n"}
                  {"  "}db.execute("SELECT * FROM orders WHERE id=" + input);
                  {"\n\n"}
                  <span className="code-note">  // Remediation Suggested:</span>
                  {"\n"}
                  <span className="code-note">
                    {"  "}
                    // Use PreparedStatements or JPA Criteria API.
                  </span>
                  {"\n"}
                  {"}"}
                </code>
              </pre>
            </div>
          </div>
        </section>

        <section className="landing-final-cta-v2" id="pricing">
          <h2>Secure Your Codebase Today</h2>
          <p>
            Join security-first engineering teams that trust AegisAI to safeguard the Java systems
            they cannot afford to get wrong.
          </p>
          <a className="landing-primary-cta-v2" href={getProviderLoginUrl("github")}>
            Connect GitHub
          </a>
          <span className="landing-pricing-note">Free tier available for Open Source</span>
        </section>

        <footer className="landing-footer-v2" id="resources">
          <span className="landing-footer-meta">
            Copyright 2026 AegisAI Security. All rights reserved.
          </span>

          <div className="landing-footer-links">
            {footerLinks.map((column) => (
              <div key={column.title} className="landing-footer-column-v2">
                <p>{column.title}</p>
                <ul>
                  {column.links.map((link) => (
                    <li key={link}>{link}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </footer>
      </div>
    </main>
  );
}
