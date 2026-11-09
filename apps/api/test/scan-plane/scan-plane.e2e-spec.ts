import type { NestExpressApplication } from "@nestjs/platform-express";
import { MAX_EVIDENCE_TTL_MS, MAX_MANIFEST_FILES, type RepositoryManifest } from "@aegisai/shared";
import request from "supertest";

import {
  createTestApplication,
  loginTestAgent,
  TEST_INTERNAL_API_SECRET
} from "../support/test-app";

describe("Scan Plane mock pipeline boundaries (e2e)", () => {
  let app: NestExpressApplication;
  let tenantAgent: request.Agent;
  let scanRequestId: string;
  let csrfToken: string;
  let repositoryBindingId: string;

  async function createScan(target: string): Promise<string> {
    const response = await tenantAgent.post("/api/scan-requests")
      .set("X-CSRF-Token", csrfToken)
      .send({
        repositoryBindingId,
        lane: "DEEP",
        targetRef: `refs/heads/${target}`,
        commitSha: "abcdef123",
        policyVersion: "policy-v1",
        scannerSetVersion: "scanner-set-v1"
      }).expect(201);
    return response.body.id as string;
  }

  function runScan(id: string, repositoryManifest?: unknown) {
    return request(app.getHttpServer()).post("/api/scan-plane/mock-runs")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send({ tenantId: "tenant_scan", scanRequestId: id,
        scannerSetVersion: "scanner-set-v1", repositoryManifest });
  }

  beforeAll(async () => {
    app = await createTestApplication();
    tenantAgent = request.agent(app.getHttpServer());
    csrfToken = await loginTestAgent(tenantAgent, "tenant_scan");

    await tenantAgent
      .post("/api/integrations/github/install")
      .set("X-CSRF-Token", csrfToken)
      .send({
        externalInstallationId: "gh-scan-test",
        repoReadPrincipalId: "repo-read-principal",
        repositories: [
          {
            providerRepoId: "4004",
            fullName: "acme/scan-test",
            defaultBranch: "main",
            isPrivate: true
          }
        ]
      })
      .expect(201);
    const repositories = await tenantAgent.get("/api/repository-bindings").expect(200);
    repositoryBindingId = repositories.body[0].id as string;
    const scan = await tenantAgent
      .post("/api/scan-requests")
      .set("X-CSRF-Token", csrfToken)
      .send({
        repositoryBindingId: repositories.body[0].id,
        lane: "DEEP",
        targetRef: "refs/heads/main",
        commitSha: "abcdef123",
        policyVersion: "policy-v1",
        scannerSetVersion: "scanner-set-v1"
      })
      .expect(201);
    scanRequestId = scan.body.id as string;
  });

  afterAll(async () => {
    await app.close();
  });

  it("requires internal authentication and emits bounded, redacted metadata", async () => {
    const payload = {
      tenantId: "tenant_scan",
      scanRequestId,
      scannerSetVersion: "scanner-set-v1"
    };

    await request(app.getHttpServer()).post("/api/scan-plane/mock-runs").send(payload).expect(401);

    const startedAt = Date.now();
    const response = await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send(payload)
      .expect(201);

    expect(response.body.scannerRuns).toEqual([
      expect.objectContaining({ scanner: "OPENGREP", status: "COMPLETED" }),
      expect.objectContaining({ scanner: "TRIVY", status: "COMPLETED" }),
      expect.objectContaining({ scanner: "SYFT", status: "COMPLETED" })
    ]);
    expect(response.body.findings).toEqual([
      expect.objectContaining({
        tenantId: "tenant_scan",
        scanRequestId,
        scannerProvenance: "OPENGREP",
        severity: "HIGH",
        status: "OPEN"
      })
    ]);
    expect(response.body).not.toHaveProperty("planning");
    expect(response.body.findings[0]).not.toHaveProperty("scanProfile");
    expect(response.body.scannerRuns.every((run: object) => !("planning" in run))).toBe(true);
    expect(response.body.evidencePacks).toEqual([
      expect.objectContaining({
        tenantId: "tenant_scan",
        scanRequestId,
        classification: "SHORT_LIVED_EVIDENCE",
        objectKey: expect.stringMatching(/\/evidence\/evidence_[0-9a-f-]{36}\.json$/),
        redacted: true
      })
    ]);
    const evidenceExpiry = Date.parse(response.body.evidencePacks[0].expiresAt);
    expect(evidenceExpiry).toBeGreaterThan(startedAt);
    expect(evidenceExpiry).toBeLessThanOrEqual(Date.now() + MAX_EVIDENCE_TTL_MS);
    expect(JSON.stringify(response.body)).not.toMatch(
      /accessToken|refreshToken|tokenValue|secretValue|fullRepository|sourceArchive/i
    );

    const retry = await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send(payload)
      .expect(201);
    expect(retry.body.scannerRuns[0].id).toBe(response.body.scannerRuns[0].id);
  });

  it("reads artifacts only through the authenticated tenant context", async () => {
    await tenantAgent
      .get("/api/scan-plane/scanner-runs")
      .query({ scanRequestId })
      .expect(200)
      .expect(({ body }) => expect(body).toHaveLength(3));
    await tenantAgent
      .get("/api/findings")
      .query({ scanRequestId })
      .expect(200)
      .expect(({ body }) => expect(body).toHaveLength(1));
    await tenantAgent
      .get("/api/evidence")
      .query({ scanRequestId })
      .expect(200)
      .expect(({ body }) => expect(body).toHaveLength(1));

    const otherTenant = request.agent(app.getHttpServer());
    await loginTestAgent(otherTenant, "tenant_other");
    await otherTenant
      .get("/api/findings")
      .query({ scanRequestId, tenantId: "tenant_scan" })
      .expect(400);
  });

  it("rejects a scanner set version that differs from the scan plan", async () => {
    await request(app.getHttpServer())
      .post("/api/scan-plane/mock-runs")
      .set("Authorization", `Bearer ${TEST_INTERNAL_API_SECRET}`)
      .send({
        tenantId: "tenant_scan",
        scanRequestId,
        scannerSetVersion: "scanner-set-v2"
      })
      .expect(400);
  });

  it("routes a mixed Java repository through detailed scanner metadata and preserves retries", async () => {
    const id = await createScan("java-planning");
    const manifest: RepositoryManifest = {
      files: [{ path: "service/pom.xml" }, { path: "src/App.java" }, { path: "web/package.json" }]
    };
    const response = await runScan(id, manifest).expect(201);
    expect(response.body.planning).toEqual({
      scanProfile: "JAVA_DETAILED",
      detectedLanguages: ["JAVA", "JAVASCRIPT"],
      detectedSurfaces: [],
      aiAdvisoryEligibility: { eligible: true, reason: "JAVA_DETAILED_FINDINGS_ONLY" }
    });
    expect(response.body.scannerRuns.map((run: { scanner: string }) => run.scanner))
      .toEqual(["OPENGREP", "TRIVY", "SYFT"]);
    for (const run of response.body.scannerRuns) {
      expect(run.planning).toEqual(response.body.planning);
    }
    expect(response.body.findings).toEqual([expect.objectContaining({
      scanProfile: "JAVA_DETAILED", language: "JAVA", scannerProvenance: "OPENGREP"
    })]);
    expect(response.body.evidencePacks).toEqual([expect.objectContaining({ redacted: true })]);
    expect(response.body).not.toHaveProperty("repositoryManifest");
    const retry = await runScan(id, { files: [...manifest.files].reverse().concat(manifest.files[0]) })
      .expect(201);
    expect(retry.body).toEqual(response.body);
    await runScan(id, { files: [{ path: "package.json" }] }).expect(400);
    await runScan(id).expect(400);
    const reads = await tenantAgent.get("/api/scan-plane/scanner-runs")
      .query({ scanRequestId: id }).expect(200);
    expect(reads.body).toEqual(response.body.scannerRuns);

    const otherTenant = request.agent(app.getHttpServer());
    await loginTestAgent(otherTenant, "tenant_java_other");
    for (const route of ["scan-plane/scanner-runs", "findings", "evidence"]) {
      await otherTenant.get(`/api/${route}`).query({ scanRequestId: id })
        .expect(200).expect(({ body }) => expect(body).toEqual([]));
    }
  });

  it.each([
    ["non-java", ["package.json", "pyproject.toml", "go.mod", "Dockerfile", "infra/main.tf", "k8s/app.yaml"]],
    ["unknown", ["README.md", "pom.xml.backup"]],
    ["empty", []]
  ])("keeps %s manifests common-only without fabricated Java findings or evidence", async (label, paths) => {
    const id = await createScan(`common-${label}`);
    const manifest = { files: (paths as string[]).map((path) => ({ path })) };
    const response = await runScan(id, manifest).expect(201);
    expect(response.body.planning.scanProfile).toBe("COMMON");
    expect(response.body.planning.aiAdvisoryEligibility.eligible).toBe(false);
    expect(response.body.scannerRuns).toHaveLength(3);
    for (const run of response.body.scannerRuns) {
      expect(run.planning.scanProfile).toBe("COMMON");
    }
    expect(response.body.findings).toEqual([]);
    expect(response.body.evidencePacks).toEqual([]);
    for (const route of ["findings", "evidence"]) {
      await tenantAgent.get(`/api/${route}`).query({ scanRequestId: id })
        .expect(200).expect(({ body }) => expect(body).toEqual([]));
    }
  });

  it("rejects unsafe paths, oversized manifests, nested source content and routing overrides before mutation", async () => {
    const id = await createScan("invalid-manifest");
    const invalidManifests: unknown[] = [null, [], {}, { files: null }, { files: [null] },
      { files: ["App.java"] }, { files: [{ path: "App.java", sourceContent: "class App {}" }] },
      { files: [], scanProfile: "JAVA_DETAILED" },
      { files: Array(MAX_MANIFEST_FILES + 1).fill({ path: "pom.xml" }) }
    ];
    for (const path of ["", "/App.java", "../App.java", "src/../App.java", "src/./App.java",
      "src//App.java", "src\\App.java", "C:/App.java", "App.java\n", "x".repeat(513)]) {
      invalidManifests.push({ files: [{ path }] });
    }
    for (const manifest of invalidManifests) {
      await runScan(id, manifest).expect(400);
    }
    await tenantAgent.get("/api/scan-plane/scanner-runs").query({ scanRequestId: id })
      .expect(200).expect(({ body }) => expect(body).toEqual([]));
    await runScan(id, { files: [{ path: "pom.xml" }] }).expect(201);
  });

  it("does not let a manifest retrofit an already completed legacy run", async () => {
    await runScan(scanRequestId, { files: [{ path: "pom.xml" }] }).expect(400);
  });
});
