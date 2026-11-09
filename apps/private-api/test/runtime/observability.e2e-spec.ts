import type { NestExpressApplication } from "@nestjs/platform-express";
import { SpanStatusCode } from "@opentelemetry/api";
import request from "supertest";
import { boundedRoute, RequestMeasurements, safeHttpLog, safeHttpSpan } from "../../src/runtime/observability";
import { createTestApplication, loginTestAgent } from "../support/test-app";

describe("Private observability boundaries", () => {
  let app: NestExpressApplication;
  beforeAll(async () => { app = await createTestApplication(); });
  afterAll(async () => { await app.close(); });

  it("rejects anonymous and spoofed proxy identities and derives the viewer from an admitted session", async () => {
    await request(app.getHttpServer()).get('/api/runtime/observability-auth')
      .set('X-WEBAUTH-USER', 'github-42').set('X-AegisAI-User', 'github-42').expect(401);
    const agent = request.agent(app.getHttpServer());
    await loginTestAgent(agent, 'tenant_observability_fixture');
    await agent.get('/api/runtime/observability-auth').set('X-WEBAUTH-USER', 'forged')
      .expect(204).expect('X-AegisAI-User', 'github-42').expect('X-AegisAI-Role', 'Viewer');
  });

  it("keeps raw paths, query secrets and scan identifiers out of bounded metric labels", () => {
    const measurements = new RequestMeasurements();
    for (let index = 0; index < 100; index++) {
      measurements.observe('/api/runtime/scans/scan_request_' + index, 'GET', 200, 0.01);
    }
    measurements.observe('/private-repository?token=do-not-export', 'UNTRUSTED"', 404, 0.02);
    const result = measurements.render();
    expect(result).toContain('route="/api/runtime/scans/:scanRequestId"');
    expect(result).toContain(' 100\n');
    expect(result).not.toMatch(/scan_request_|private-repository|do-not-export|UNTRUSTED/);
    expect(boundedRoute('/api/auth/github/callback?code=secret')).toBe('/unmatched');
  });

  it("exports only explicitly bounded manual HTTP spans", () => {
    const span = { instrumentationScope: { name: 'aegisai-private-http' },
      name: 'GET /api/runtime/scans', attributes: { 'http.route': '/api/runtime/scans', 'http.request.method': 'GET' },
      events: [], links: [], status: { code: SpanStatusCode.UNSET } };
    expect(safeHttpSpan(span)).toBe(true);
    expect(safeHttpSpan({ ...span, attributes: { ...span.attributes, 'db.statement': 'private-data' } })).toBe(false);
    expect(safeHttpSpan({ ...span, status: { code: SpanStatusCode.ERROR, message: 'private-error' } })).toBe(false);
    expect(safeHttpSpan({ ...span, instrumentationScope: { name: 'aws-sdk' } })).toBe(false);
  });

  it("rejects log bodies with headers, foreign scope or unbounded paths", () => {
    const value = { service: 'aegisai-api', level: 'info', method: 'GET', route: '/api/runtime/scans',
      status: 200, duration_ms: 10, trace_id: 'a'.repeat(32), span_id: 'b'.repeat(16), time: new Date().toISOString() };
    const record = { instrumentationScope: { name: 'aegisai-private-http' }, attributes: {}, body: JSON.stringify(value) };
    expect(safeHttpLog(record)).toBe(true);
    expect(safeHttpLog({ ...record, body: JSON.stringify({ ...value, authorization: 'private-token' }) })).toBe(false);
    expect(safeHttpLog({ ...record, body: JSON.stringify({ ...value, route: '/private?token=secret' }) })).toBe(false);
    expect(safeHttpLog({ ...record, instrumentationScope: { name: 'scm' } })).toBe(false);
  });
});
