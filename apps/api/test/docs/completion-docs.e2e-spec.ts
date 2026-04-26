import { readFileSync } from 'node:fs';
import { join } from 'node:path';

describe('completion entrypoint docs', () => {
  const root = join(__dirname, '../../../..');
  const read = (relativePath: string) =>
    readFileSync(join(root, relativePath), 'utf8').replace(/\r\n/g, '\n');

  const readme = read('README.md');
  const agents = read('AGENTS.md');
  const quickstart = read('specs/001-aegisai-mvp-foundation/quickstart.md');
  const tasks = read('specs/001-aegisai-mvp-foundation/tasks.md');
  const hardeningReview = read('specs/001-aegisai-mvp-foundation/hardening-review.md');

  it('keeps the canonical entry docs aligned on the completion path', () => {
    expect(readme).toContain('AGENTS.md -> quickstart.md ->');
    expect(readme).toContain('hardening-review.md');

    expect(agents).toContain('## Frontend Design Tooling');
    expect(agents).toContain('## Completion Gate');
    expect(agents).toContain('hardening-review.md');

    expect(quickstart).toContain('## Final Validation Commands');
    expect(quickstart).toContain('corepack pnpm lint');
    expect(quickstart).toContain('corepack pnpm test');
    expect(quickstart).toContain('corepack pnpm typecheck');
    expect(quickstart).toContain('corepack pnpm build');
    expect(quickstart).toContain('hardening-review.md');
  });

  it('records the current report, dashboard, and phase 6 completion state', () => {
    expect(tasks).toContain('- [x] T015 [P] Implement report infrastructure');
    expect(tasks).toContain('- [x] T038 [P] [US3] Add dashboard and report API coverage');
    expect(tasks).toContain('- [x] T039 [P] [US3] Add dashboard and report UI tests');
    expect(tasks).toContain('- [x] T040 [P] [US3] Implement dashboard backend module');
    expect(tasks).toContain('- [x] T041 [P] [US3] Implement dashboard frontend experience');
    expect(tasks).toContain('- [x] T042 [US3] Implement report request, status, and download endpoints');
    expect(tasks).toContain('- [x] T043 [US3] Implement report frontend flow');
    expect(tasks).toContain('- [x] T044 [US3] Add report templates and file-lifecycle behavior');
    expect(tasks).toContain('- [x] T045 [P] Update documentation entry points');
    expect(tasks).toContain('- [x] T046 Run security and behavior review');
    expect(tasks).toContain('- [x] T047 [P] Add or refine regression coverage');
    expect(tasks).toContain('- [x] T048 Validate the quickstart flow');
  });

  it('captures the hardening review areas that close phase 6', () => {
    expect(hardeningReview).toContain('## Sessions');
    expect(hardeningReview).toContain('## CSRF');
    expect(hardeningReview).toContain('## Throttling');
    expect(hardeningReview).toContain('## Raw Health Responses');
    expect(hardeningReview).toContain('## Report Download Expiry');
    expect(hardeningReview).toContain('## Queue Recovery');
    expect(hardeningReview).toContain('## Provider Errors');
    expect(hardeningReview).toContain('## Frontend Error States');
  });
});
