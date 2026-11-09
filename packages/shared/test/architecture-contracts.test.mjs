import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_EVIDENCE_TTL_MS,
  MAX_SCAN_CREDENTIAL_TTL_SECONDS,
  buildCanonicalScanKey,
  createEvidencePackMetadata
} from "../dist/index.js";

test("canonical scan keys are versioned and delimiter-safe", () => {
  const base = {
    tenantId: "tenant:a",
    repositoryBindingId: "repo",
    lane: "FAST",
    targetRef: "refs/heads/main",
    commitSha: "abcdef1",
    policyVersion: "policy:v1",
    scannerSetVersion: "scanner:v1"
  };

  const key = buildCanonicalScanKey(base);
  const ambiguousKey = buildCanonicalScanKey({
    ...base,
    tenantId: "tenant",
    repositoryBindingId: "a:repo"
  });

  assert.match(key, /^v1:/);
  assert.notEqual(key, ambiguousKey);
  assert.ok(key.includes("tenant%3Aa"));
});

test("evidence metadata rejects expired and overlong retention", () => {
  const input = {
    id: "evidence_1",
    tenantId: "tenant_a",
    scanRequestId: "scan_1",
    byteSize: 512,
    redacted: true
  };

  assert.throws(
    () => createEvidencePackMetadata({ ...input, expiresAt: new Date(Date.now() - 1_000).toISOString() }),
    RangeError
  );
  assert.throws(
    () =>
      createEvidencePackMetadata({
        ...input,
        expiresAt: new Date(Date.now() + MAX_EVIDENCE_TTL_MS + 60_000).toISOString()
      }),
    RangeError
  );
});

test("scan credential TTL is capped at ten minutes", () => {
  assert.equal(MAX_SCAN_CREDENTIAL_TTL_SECONDS, 600);
});
