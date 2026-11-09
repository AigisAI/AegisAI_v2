import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import type { VulnerabilityDetail } from "@aegisai/shared";

import { DEMO_FINDING_ID, DEMO_REPORT_ID } from "../../demo/demoData";
import { buildDemoPath, isDemoMode } from "../../demo/demoMode";

type AdvisoryStage = "idle" | "generating" | "ready";

const proposedCode = `private static final String ORDER_BY_ID =
    "SELECT * FROM orders WHERE id = ?";

return jdbcTemplate.queryForObject(
    ORDER_BY_ID,
    orderMapper,
    orderId
);`;

export function AiAdvisoryPanel({ finding }: { finding: VulnerabilityDetail }) {
  const [isOpen, setIsOpen] = useState(false);
  const [stage, setStage] = useState<AdvisoryStage>("idle");
  const [commentVisible, setCommentVisible] = useState(false);
  const demoMode = isDemoMode();

  useEffect(() => {
    setIsOpen(false);
    setStage("idle");
    setCommentVisible(false);
  }, [finding.id]);

  useEffect(() => {
    if (stage !== "generating") {
      return;
    }

    const timeoutId = window.setTimeout(() => setStage("ready"), 900);
    return () => window.clearTimeout(timeoutId);
  }, [stage]);

  if (!demoMode || finding.id !== DEMO_FINDING_ID) {
    return null;
  }

  return (
    <>
      <div className="ai-advisory-entry">
        <div>
          <span className="review-block-label">AI advisory</span>
          <strong>Generate a reviewable remediation draft</strong>
          <p>
            Reduced, redacted evidence only. The deterministic finding remains authoritative.
          </p>
        </div>
        <button
          className="review-primary-action"
          onClick={() => {
            setIsOpen(true);
            setStage("generating");
          }}
          type="button"
        >
          Generate AI remediation
        </button>
      </div>

      {isOpen ? (
        <div className="ai-advisory-backdrop" role="presentation">
          <section
            aria-labelledby="ai-advisory-title"
            aria-modal="true"
            className="ai-advisory-dialog"
            role="dialog"
          >
            <header className="ai-advisory-header">
              <div>
                <p className="eyebrow">AI remediation planner</p>
                <h2 id="ai-advisory-title">Review the proposed code change</h2>
                <p>
                  Finding {finding.id} · {finding.filePath} · lines {finding.lineStart}-
                  {finding.lineEnd}
                </p>
              </div>
              <button
                aria-label="Close AI advisory"
                className="ai-advisory-close"
                onClick={() => setIsOpen(false)}
                type="button"
              >
                Close
              </button>
            </header>

            <div className="ai-advisory-authority" role="status">
              <strong>Advisory only · Not applied</strong>
              <span>Human review and a deterministic re-scan are required.</span>
            </div>

            {stage === "generating" ? (
              <div className="ai-advisory-generating" role="status">
                <span className="ai-advisory-spinner" aria-hidden="true" />
                <div>
                  <strong>Preparing a bounded remediation draft</strong>
                  <p>Reviewing the normalized finding, redacted snippet, and rule metadata.</p>
                </div>
              </div>
            ) : null}

            {stage === "ready" ? (
              <div className="ai-advisory-ready">
                <div className="ai-advisory-summary-grid">
                  <article>
                    <span>Root cause</span>
                    <strong>Untrusted input changes SQL command structure</strong>
                  </article>
                  <article>
                    <span>Suggested control</span>
                    <strong>Bind the order identifier as a query parameter</strong>
                  </article>
                  <article>
                    <span>Confidence</span>
                    <strong>High · 96%</strong>
                  </article>
                </div>

                <div className="ai-code-diff" aria-label="Original and AI-proposed code">
                  <section className="ai-code-pane is-original">
                    <div>
                      <span>Original</span>
                      <strong>OrderRepository.java</strong>
                    </div>
                    <pre>{finding.codeSnippet}</pre>
                  </section>
                  <section className="ai-code-pane is-proposed">
                    <div>
                      <span>AI-proposed change</span>
                      <strong>Parameterized query</strong>
                    </div>
                    <pre>{proposedCode}</pre>
                  </section>
                </div>

                <div className="ai-advisory-rationale">
                  <div>
                    <span className="review-block-label">Why this change</span>
                    <p>
                      Binding <code>orderId</code> separately keeps request data outside the SQL
                      command text, so crafted input cannot add clauses or alter the query plan.
                    </p>
                  </div>
                  <div>
                    <span className="review-block-label">Verification gate</span>
                    <ul>
                      <li>Developer reviews the proposed API signature and error behavior.</li>
                      <li>Unit tests cover valid, missing, and injection-shaped identifiers.</li>
                      <li>Opengrep re-runs on the fixed commit before policy is evaluated again.</li>
                    </ul>
                  </div>
                </div>

                {commentVisible ? (
                  <div className="ai-comment-preview" aria-label="Pull request comment preview">
                    <span className="review-block-label">PR comment draft · Not published</span>
                    <p>
                      AegisAI confirmed a critical SQL injection path in
                      <code> OrderRepository.java:87-92</code>. Replace SQL concatenation with a
                      bound parameter, add hostile-input coverage, and re-run deterministic
                      scanning before merge. The suggested patch is advisory and has not been
                      applied to the branch.
                    </p>
                  </div>
                ) : null}

                <footer className="ai-advisory-actions">
                  <button
                    className="review-secondary-action"
                    onClick={() => setCommentVisible((current) => !current)}
                    type="button"
                  >
                    {commentVisible ? "Hide PR comment draft" : "Prepare PR comment draft"}
                  </button>
                  <Link
                    className="review-primary-action"
                    to={buildDemoPath(`/reports/${DEMO_REPORT_ID}`)}
                  >
                    Open natural-language report
                  </Link>
                </footer>
              </div>
            ) : null}
          </section>
        </div>
      ) : null}
    </>
  );
}
