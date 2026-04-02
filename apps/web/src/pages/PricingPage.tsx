import { Link } from "react-router-dom";

import { getProviderLoginUrl } from "../api/auth";

interface PricingPlan {
  name: string;
  price: string;
  cadence: string;
  description: string;
  highlights: string[];
  featured?: boolean;
}

const plans: PricingPlan[] = [
  {
    name: "Starter",
    price: "$79",
    cadence: "per month",
    description:
      "For solo reviewers and small Java services that need a dependable security pass before every release.",
    highlights: [
      "Up to 5 connected repositories",
      "50 scan runs each month",
      "Vulnerability review workspace",
      "Exportable PDF reports",
    ],
  },
  {
    name: "Team",
    price: "$329",
    cadence: "per month",
    featured: true,
    description:
      "For product teams that want shared triage, higher scan velocity, and polished reporting for every sprint.",
    highlights: [
      "Up to 20 connected repositories",
      "300 scan runs each month",
      "Shared reviewer workspace",
      "Priority report generation and support",
    ],
  },
  {
    name: "Enterprise",
    price: "Talk to us",
    cadence: "custom rollout",
    description:
      "For security programs that need rollout guidance, tailored retention, and controlled onboarding across many repos.",
    highlights: [
      "Unlimited repository onboarding",
      "Custom scan throughput",
      "Dedicated onboarding lane",
      "Security review and procurement support",
    ],
  },
];

const comparisonRows = [
  {
    label: "Repository scope",
    starter: "Focused coverage for a small set of production repos.",
    team: "Shared coverage for multiple squads and release branches.",
    enterprise: "Portfolio-level onboarding with policy review.",
  },
  {
    label: "Review rhythm",
    starter: "Manual scans before release windows.",
    team: "Recurring sprint and pre-merge review cycles.",
    enterprise: "Structured rollout plans with queue tuning.",
  },
  {
    label: "Report flow",
    starter: "PDF exports for handoff and audit notes.",
    team: "Fast report generation for security and engineering syncs.",
    enterprise: "Extended retention and guided stakeholder distribution.",
  },
  {
    label: "Support posture",
    starter: "Core documentation and email support.",
    team: "Faster response and rollout guidance.",
    enterprise: "Dedicated onboarding and operating reviews.",
  },
] as const;

const faqItems = [
  {
    question: "Is there a trial before we commit to a paid plan?",
    answer:
      "Yes. Teams can begin in the secure review workspace, connect a repository, and validate the flow before choosing a paid operating model.",
  },
  {
    question: "Do all plans support private repositories?",
    answer:
      "Yes. Pricing assumes private Java repositories and keeps code handling inside the same authenticated review path.",
  },
  {
    question: "What happens to PDF reports after generation?",
    answer:
      "Reports are generated inside the secured workspace and follow the same lifecycle controls as the rest of the review flow, including expiry handling.",
  },
  {
    question: "Can we move to annual billing later?",
    answer:
      "Yes. Team and Enterprise rollouts can move to annual agreements once scan cadence and repository scope are stable.",
  },
  {
    question: "What does Enterprise onboarding include?",
    answer:
      "Enterprise onboarding covers repository rollout planning, scan capacity calibration, report delivery expectations, and stakeholder handoff.",
  },
] as const;

const trustSignals = [
  {
    title: "Same-origin secure access",
    body: "Authentication, review, and report delivery stay within the same public entry and protected workspace flow.",
  },
  {
    title: "Private code handling",
    body: "Pricing is built around private repository review, not public showcase scanning.",
  },
  {
    title: "Reviewable evidence",
    body: "Each tier keeps the vulnerability review workspace, evidence trails, and PDF handoff artifacts in reach.",
  },
] as const;

export function PricingPage() {
  return (
    <main className="pricing-page-v2">
      <header className="pricing-topbar-v2">
        <div className="pricing-topbar-inner-v2">
          <div className="pricing-brand-group-v2">
            <Link className="pricing-wordmark-v2" to="/">
              AegisAI
            </Link>

            <nav className="pricing-topnav-v2" aria-label="Public pricing navigation">
              <Link to="/">Overview</Link>
              <a href="#plans">Plans</a>
              <a href="#assurance">Assurance</a>
              <a href="#faq">FAQ</a>
            </nav>
          </div>

          <div className="pricing-topbar-actions-v2">
            <Link className="landing-inline-link" to="/login">
              Log in
            </Link>
            <a className="landing-topbar-cta" href={getProviderLoginUrl("github")}>
              Connect GitHub
            </a>
          </div>
        </div>
      </header>

      <div className="pricing-shell-v2">
        <section className="pricing-hero-v2">
          <div className="pricing-hero-copy-v2">
            <p className="pricing-eyebrow-v2">Pricing for deliberate security review</p>
            <h1>
              Choose a review cadence that fits how your Java repositories
              <span> actually ship.</span>
            </h1>
            <p className="pricing-lead-v2">
              AegisAI combines scan orchestration, evidence-backed vulnerability review,
              and polished PDF reporting in a quieter security workspace built for teams
              that prefer signal over noise.
            </p>

            <div className="pricing-cta-row-v2">
              <Link className="landing-primary-cta-v2" to="/login">
                Start secure review
              </Link>
              <a className="landing-secondary-cta-v2" href="#plans">
                Compare plans
              </a>
            </div>

            <ul className="pricing-summary-list-v2" aria-label="Pricing summary">
              <li>Java-first review flow</li>
              <li>Private repository access</li>
              <li>PDF handoff included</li>
            </ul>
          </div>

          <aside className="pricing-hero-panel-v2" aria-label="Pricing philosophy">
            <span className="pricing-panel-badge-v2">Editorial pricing philosophy</span>
            <h2>Pay for a calmer review loop, not a louder dashboard.</h2>
            <p>
              Every tier keeps the vulnerability review workspace, report generation,
              and evidence-led triage visible. Higher plans widen repository scope,
              scan throughput, and rollout support rather than hiding core review tools.
            </p>

            <dl className="pricing-metrics-v2">
              <div>
                <dt>3</dt>
                <dd>clear tiers</dd>
              </div>
              <div>
                <dt>1</dt>
                <dd>same-origin entry flow</dd>
              </div>
              <div>
                <dt>100%</dt>
                <dd>private repo focus</dd>
              </div>
            </dl>
          </aside>
        </section>

        <section
          className="pricing-assurance-band-v2"
          id="assurance"
          aria-labelledby="pricing-assurance-heading"
        >
          <div className="pricing-section-heading-v2">
            <p className="pricing-eyebrow-v2">Assurance built into every tier</p>
            <h2 id="pricing-assurance-heading">
              Security pricing should explain how code is handled, not leave it implied.
            </h2>
          </div>

          <div className="pricing-trust-grid-v2">
            {trustSignals.map((signal) => (
              <article className="pricing-trust-card-v2" key={signal.title}>
                <h3>{signal.title}</h3>
                <p>{signal.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="pricing-plans-v2" id="plans" aria-labelledby="pricing-plans-heading">
          <div className="pricing-section-heading-v2">
            <p className="pricing-eyebrow-v2">Plans</p>
            <h2 id="pricing-plans-heading">
              Three operating shapes, each built around review clarity.
            </h2>
          </div>

          <div className="pricing-plan-grid-v2">
            {plans.map((plan) => (
              <article
                key={plan.name}
                className={`pricing-plan-card-v2${plan.featured ? " is-featured" : ""}`}
              >
                <div className="pricing-plan-header-v2">
                  <div>
                    <h3>{plan.name}</h3>
                    <p>{plan.description}</p>
                  </div>
                  {plan.featured ? <span className="pricing-plan-badge-v2">Recommended</span> : null}
                </div>

                <p className="pricing-plan-price-v2">
                  <span>{plan.price}</span>
                  <small>{plan.cadence}</small>
                </p>

                <ul className="pricing-plan-list-v2">
                  {plan.highlights.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>

                <Link
                  className={plan.featured ? "landing-primary-cta-v2" : "landing-secondary-cta-v2"}
                  to="/login"
                >
                  {plan.name === "Enterprise" ? "Plan enterprise rollout" : `Choose ${plan.name}`}
                </Link>
              </article>
            ))}
          </div>
        </section>

        <section
          className="pricing-comparison-v2"
          aria-labelledby="pricing-comparison-heading"
        >
          <div className="pricing-section-heading-v2">
            <p className="pricing-eyebrow-v2">What changes as you grow</p>
            <h2 id="pricing-comparison-heading">
              An editorial comparison instead of a spreadsheet wall.
            </h2>
          </div>

          <div className="pricing-comparison-table-v2" role="table" aria-label="Plan comparison">
            <div className="pricing-comparison-head-v2" role="rowgroup">
              <div role="row">
                <span role="columnheader">Focus area</span>
                <span role="columnheader">Starter</span>
                <span role="columnheader">Team</span>
                <span role="columnheader">Enterprise</span>
              </div>
            </div>

            <div className="pricing-comparison-body-v2" role="rowgroup">
              {comparisonRows.map((row) => (
                <div className="pricing-comparison-row-v2" role="row" key={row.label}>
                  <span role="rowheader">{row.label}</span>
                  <p role="cell">{row.starter}</p>
                  <p role="cell">{row.team}</p>
                  <p role="cell">{row.enterprise}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="pricing-faq-v2" id="faq" aria-labelledby="pricing-faq-heading">
          <div className="pricing-section-heading-v2">
            <p className="pricing-eyebrow-v2">FAQ</p>
            <h2 id="pricing-faq-heading">Questions teams usually ask before rollout.</h2>
          </div>

          <div className="pricing-faq-grid-v2">
            {faqItems.map((item) => (
              <article className="pricing-faq-card-v2" key={item.question}>
                <h3>{item.question}</h3>
                <p>{item.answer}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="pricing-final-cta-v2" aria-labelledby="pricing-final-heading">
          <div>
            <p className="pricing-eyebrow-v2">Ready to set the review pace?</p>
            <h2 id="pricing-final-heading">
              Move from repository connection to reviewable evidence without changing
              tools halfway through.
            </h2>
          </div>

          <div className="pricing-final-actions-v2">
            <Link className="landing-primary-cta-v2" to="/login">
              Open secure access
            </Link>
            <Link className="landing-secondary-cta-v2" to="/">
              Return to overview
            </Link>
          </div>
        </section>
      </div>
    </main>
  );
}
