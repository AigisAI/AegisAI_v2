import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('MVP OpenAPI contract', () => {
  const contract = readFileSync(
    join(__dirname, '../../../../specs/001-aegisai-mvp-foundation/contracts/mvp-openapi.yaml'),
    'utf8'
  ).replace(/\r\n/g, '\n');

  it('documents the currently implemented auth, repo, and scan endpoints', () => {
    expect(contract).toContain('/auth/github:');
    expect(contract).toContain('/auth/github/callback:');
    expect(contract).toContain('/auth/gitlab:');
    expect(contract).toContain('/auth/gitlab/callback:');
    expect(contract).toContain('/repos/{repoId}/scans:');
    expect(contract.match(/^\s{2}\/repos:$/gm)).toHaveLength(1);
    expect(contract).toContain('/repos:\n    get:');
    expect(contract).toContain("operationId: connectRepo");
  });

  it('documents the current vulnerability review endpoints and feedback contract', () => {
    expect(contract).toContain('/scans/{scanId}/vulnerabilities:');
    expect(contract).toContain('/vulnerabilities/{vulnId}:');
    expect(contract).toContain('/vulnerabilities/{vulnId}/feedback:\n    post:');
    expect(contract).toContain('operationId: submitVulnerabilityFeedback');
    expect(contract).toContain("$ref: '#/components/schemas/VulnerabilityFeedbackResponse'");
    expect(contract).not.toContain('/vulnerabilities/{vulnId}/feedback:\n    patch:');
  });

  it('uses the current auth, health, and session security shapes', () => {
    expect(contract).toContain('securitySchemes:');
    expect(contract).toContain('sessionCookie:');
    expect(contract).toContain("required: [id, name, connectedProviders]");
    expect(contract).toContain('connectedProviders:');
    expect(contract).toContain('uptime:');
    expect(contract).toContain('services:');
    expect(contract).toContain("'200':\n          description: Session cleared");
    expect(contract).not.toContain('nullable: true');
  });
});
