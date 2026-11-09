import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { DEMO_REPORT_ID, DEMO_SCAN_ID } from "../demo/demoData";
import { buildDemoPath, isDemoMode } from "../demo/demoMode";

type ReportSectionId = "executive" | "critical" | "remediation" | "plan";

interface ReportSection {
  id: ReportSectionId;
  label: string;
  kicker: string;
  title: string;
  content: ReactNode;
}

const originalCode = `String query = "SELECT * FROM orders WHERE id = " + orderId;
return jdbcTemplate.queryForObject(query, orderMapper);`;

const proposedCode = `private static final String ORDER_BY_ID =
    "SELECT * FROM orders WHERE id = ?";

return jdbcTemplate.queryForObject(
    ORDER_BY_ID,
    orderMapper,
    orderId
);`;

const reportSections: ReportSection[] = [
  {
    id: "executive",
    label: "Executive summary",
    kicker: "Decision brief",
    title: "One critical issue should be resolved before payment-api is merged",
    content: (
      <div className="report-prose">
        <p>
          AegisAI reviewed commit <code>8f3a21c</code> on the <code>main</code> branch of
          <strong> acme-payments/payment-api</strong>. The deterministic scanner set completed
          successfully across Opengrep, Trivy, and Syft, producing seven normalized findings:
          one critical, two high, three medium, and one low.
        </p>
        <p>
          The immediate release concern is a SQL injection path in the order lookup flow.
          Request-controlled data is concatenated into a database query, which could allow an
          attacker to read or modify order data outside the intended authorization boundary.
          Policy therefore recommends holding the merge until the query is parameterized and the
          fixed commit passes a clean deterministic re-scan.
        </p>
        <div className="report-decision-callout">
          <span>Recommended release decision</span>
          <strong>Hold merge · remediate critical finding · re-scan</strong>
          <p>
            AI guidance below is advisory. It cannot close the finding or change policy status.
          </p>
        </div>
      </div>
    ),
  },
  {
    id: "critical",
    label: "Critical finding",
    kicker: "Deterministic evidence",
    title: "The order identifier can alter the SQL statement itself",
    content: (
      <div className="report-prose">
        <p>
          Opengrep traced the order identifier from an HTTP request boundary into
          <code> OrderRepository.java:87-92</code>. Because the value is appended to the SQL text
          before execution, quote characters and SQL operators are interpreted as command syntax
          rather than data.
        </p>
        <div className="report-impact-grid">
          <article>
            <span>Confidentiality</span>
            <strong>Order and customer records may be exposed across tenant boundaries.</strong>
          </article>
          <article>
            <span>Integrity</span>
            <strong>Crafted input may modify or delete records if the DB role permits it.</strong>
          </article>
          <article>
            <span>Policy</span>
            <strong>Critical injection on a payment path blocks merge without a waiver.</strong>
          </article>
        </div>
        <div className="report-lineage">
          <span>Finding FND-2041</span>
          <span>CWE-89</span>
          <span>Opengrep 1.4.2</span>
          <span>Policy v3.7</span>
        </div>
      </div>
    ),
  },
  {
    id: "remediation",
    label: "AI remediation",
    kicker: "Advisory code change",
    title: "Bind the identifier separately from the SQL command text",
    content: (
      <div className="report-prose">
        <p>
          The AI planner recommends replacing string concatenation with a parameterized query.
          This is a bounded proposal derived from the normalized finding and redacted evidence;
          it has not been written to the repository and has not been compiled or tested.
        </p>
        <div className="ai-code-diff report-code-diff">
          <section className="ai-code-pane is-original">
            <div><span>Original</span><strong>Vulnerable query</strong></div>
            <pre>{originalCode}</pre>
          </section>
          <section className="ai-code-pane is-proposed">
            <div><span>AI-proposed</span><strong>Bound parameter</strong></div>
            <pre>{proposedCode}</pre>
          </section>
        </div>
        <div className="report-verification-gate">
          <strong>Required before closure</strong>
          <ol>
            <li>Review the JDBC call signature and application-level error handling.</li>
            <li>Add tests for normal, missing, malformed, and injection-shaped identifiers.</li>
            <li>Commit the reviewed change and run Opengrep, Trivy, and Syft again.</li>
            <li>Allow policy v3.7 to evaluate only the new deterministic result.</li>
          </ol>
        </div>
      </div>
    ),
  },
  {
    id: "plan",
    label: "72-hour plan",
    kicker: "Prioritized response",
    title: "Close the critical path first, then reduce the remaining release risk",
    content: (
      <div className="report-plan-list">
        <article><span>0-4 hours</span><div><strong>Contain the critical path</strong><p>Assign an owner, parameterize the order lookup, and add hostile-input regression tests.</p></div></article>
        <article><span>Within 24 hours</span><div><strong>Rotate and remove the exposed credential</strong><p>Revoke the committed value, move retrieval to the approved secrets manager, and verify logs contain no copy.</p></div></article>
        <article><span>Within 48 hours</span><div><strong>Upgrade the vulnerable dependency</strong><p>Move Log4j to the approved patched version and confirm the resolved dependency inventory.</p></div></article>
        <article><span>Within 72 hours</span><div><strong>Re-scan and document the release decision</strong><p>Run the full deterministic set on the fixed commit, review residual findings, and attach this report to the release record.</p></div></article>
      </div>
    ),
  },
];

export function ReportPage() {
  const { reportId = DEMO_REPORT_ID } = useParams();
  const [activeSection, setActiveSection] = useState<ReportSectionId>("executive");
  const demoMode = isDemoMode();
  const section = reportSections.find((item) => item.id === activeSection) ?? reportSections[0];

  if (!demoMode) {
    return (
      <section className="dashboard-page">
        <div className="dashboard-inline-alert dashboard-inline-alert-neutral" role="status">
          <strong>The interactive narrative report is available in demo mode.</strong>
          <p>Use the standard dashboard PDF flow for authenticated production data.</p>
        </div>
        <Link className="dashboard-secondary-link" to="/dashboard">Return to dashboard</Link>
      </section>
    );
  }

  return (
    <section className="dashboard-page report-page">
      <header className="dashboard-hero report-hero">
        <div className="dashboard-hero-copy">
          <p className="eyebrow">Security review report · {reportId}</p>
          <h2>payment-api security review</h2>
          <div className="dashboard-hero-accent">
            <p>
              A natural-language decision brief grounded in deterministic findings, with AI
              remediation clearly separated as advisory guidance.
            </p>
          </div>
        </div>
        <div className="dashboard-hero-panel report-hero-panel">
          <div>
            <span className="dashboard-hero-panel-kicker">Review complete</span>
            <strong>Commit 8f3a21c · main</strong>
          </div>
        </div>
      </header>

      <div className="dashboard-layout report-layout">
        <main className="dashboard-section report-copy">
          <div className="dashboard-section-heading">
            <p className="eyebrow">{section.kicker}</p>
            <h3>{section.title}</h3>
          </div>
          {section.content}
        </main>

        <aside className="dashboard-aside">
          <section className="dashboard-aside-card">
            <p className="eyebrow">Report sections</p>
            <h3>Follow the evidence into action</h3>
            <nav className="report-section-nav" aria-label="Report sections">
              {reportSections.map((item, index) => (
                <button
                  className={item.id === activeSection ? "is-active" : ""}
                  key={item.id}
                  onClick={() => setActiveSection(item.id)}
                  type="button"
                >
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  {item.label}
                </button>
              ))}
            </nav>
          </section>
          <section className="dashboard-aside-card report-provenance-card">
            <p className="eyebrow">Audit lineage</p>
            <h3>What this report can and cannot decide</h3>
            <ul className="dashboard-trust-list">
              <li>Scan {DEMO_SCAN_ID} completed with Opengrep, Trivy, and Syft.</li>
              <li>Policy v3.7 owns the merge recommendation.</li>
              <li>AI suggestions are not applied and cannot close findings.</li>
              <li>Evidence is reduced, redacted, and expires after seven days.</li>
            </ul>
            <Link className="dashboard-secondary-link" to={buildDemoPath(`/scan/${DEMO_SCAN_ID}/review`)}>
              Return to finding review
            </Link>
          </section>
        </aside>
      </div>
    </section>
  );
}
