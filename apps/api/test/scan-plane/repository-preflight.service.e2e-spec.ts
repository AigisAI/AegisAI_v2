import { SAST_SCAN_PROFILES, type SastRepositoryTreeEntry } from '@aegisai/shared';

import { RepositoryPreflightAttestationService } from '../../src/scan-plane/repository-preflight-attestation.service';
import { RepositoryPreflightService } from '../../src/scan-plane/repository-preflight.service';
import type { ConfigService } from '../../src/config/config.service';

const file = (
  path: string,
  byteSize = 10,
  overrides: Partial<SastRepositoryTreeEntry> = {}
): SastRepositoryTreeEntry => {
  const entry: SastRepositoryTreeEntry = {
    path,
    pathEncodingValid: true,
    kind: 'FILE',
    byteSize,
    gitObjectId: `sha1:${'1'.repeat(40)}`,
    executable: false,
    lfsPointer: false,
    ...overrides
  };
  if (
    entry.kind === 'SYMLINK' &&
    entry.symlinkTargetEncodingValid === undefined
  ) {
    entry.symlinkTargetEncodingValid = true;
  }
  return entry;
};

describe('RepositoryPreflightService', () => {
  const attestation = new RepositoryPreflightAttestationService({
    get: jest.fn(() => 'b'.repeat(64))
  } as unknown as ConfigService);
  const service = new RepositoryPreflightService(attestation);
  const profile = SAST_SCAN_PROFILES.JAVA_DEEP_V1;
  const baseInput = (entries: SastRepositoryTreeEntry[]) => ({
    attemptId: 'attempt-preflight-1',
    fixedCommitSha: 'a'.repeat(40),
    pathPolicyVersion: 'path-policy-v1',
    pathPolicy: profile.pathPolicy,
    limits: profile.limits,
    sourceExtensions: profile.sourceExtensions,
    manifestNames: profile.manifestNames,
    entries
  });

  it('produces an order-independent inventory digest and signed accepted attestation', () => {
    const entries = [
      file('src/main/java/App.java', 100),
      file('pom.xml', 20),
      file('docs/source.zip', 500)
    ];
    const first = service.evaluate(baseInput(entries));
    const second = service.evaluate(baseInput([...entries].reverse()));

    expect(first).toMatchObject({
      decision: 'ACCEPT',
      reasonCodes: ['ARCHIVE_PRESENT'],
      repositoryBytes: 620,
      selectedBytes: 120,
      counts: {
        fileCount: 3,
        directoryCount: 4,
        archiveCount: 1
      }
    });
    expect(first.inventoryDigest).toBe(second.inventoryDigest);
    const contentChanged = service.evaluate(
      baseInput([
        { ...entries[0], gitObjectId: `sha1:${'2'.repeat(40)}` },
        entries[1],
        entries[2]
      ])
    );
    expect(contentChanged.inventoryDigest).not.toBe(first.inventoryDigest);
    expect(
      attestation.verify(first.attestationRef, {
        attemptId: first.attemptId,
        fixedCommitSha: first.fixedCommitSha,
        pathPolicyVersion: first.pathPolicyVersion,
        inventoryDigest: first.inventoryDigest,
        decision: first.decision
      })
    ).toBe(true);
    expect(
      attestation.verify(`${first.attestationRef}tampered`, {
        attemptId: first.attemptId,
        fixedCommitSha: first.fixedCommitSha,
        pathPolicyVersion: first.pathPolicyVersion,
        inventoryDigest: first.inventoryDigest,
        decision: first.decision
      })
    ).toBe(false);
    expect(
      attestation.verify('attestation://sast-preflight/v1/'.padEnd(9000, 'a'), {
        attemptId: first.attemptId,
        fixedCommitSha: first.fixedCommitSha,
        pathPolicyVersion: first.pathPolicyVersion,
        inventoryDigest: first.inventoryDigest,
        decision: first.decision
      })
    ).toBe(false);
  });

  it('rejects traversal, absolute/UNC/drive paths, controls, collisions, and over-limit input', () => {
    const decomposed = 'src/cafe\u0301.java';
    const composed = 'src/café.java';
    const result = service.evaluate({
      ...baseInput([
        file('[invalid-utf8]', 10, { pathEncodingValid: false }),
        file('../escape.java'),
        file('/root.java'),
        file('C:\\root.java'),
        file('\\\\server\\share\\root.java'),
        file('src/bad\u0000name.java'),
        file('src/\u202eright-to-left.java'),
        file('src/App.java'),
        file('src/app.java'),
        file('src/Duplicate.java'),
        file('src/Duplicate.java'),
        file(decomposed),
        file(composed),
        file('x'.repeat(4097)),
        file('src/Huge.java', 101)
      ]),
      limits: {
        maxRepositoryBytes: 100,
        maxSelectedBytes: 50,
        maxFileCount: 5,
        maxSingleFileBytes: 100,
        maxPathDepth: 1
      }
    });

    expect(result.decision).toBe('REJECT');
    expect(result.reasonCodes).toEqual(
      expect.arrayContaining([
        'PATH_INVALID_UTF8',
        'PATH_NUL_OR_CONTROL',
        'PATH_ABSOLUTE',
        'PATH_DRIVE_OR_UNC',
        'PATH_PARENT_TRAVERSAL',
        'PATH_LENGTH_LIMIT_EXCEEDED',
        'PATH_CASE_COLLISION',
        'PATH_UNICODE_COLLISION',
        'PATH_DUPLICATE',
        'PATH_DEPTH_LIMIT_EXCEEDED',
        'REPOSITORY_BYTES_LIMIT_EXCEEDED',
        'SELECTED_BYTES_LIMIT_EXCEEDED',
        'FILE_COUNT_LIMIT_EXCEEDED',
        'SINGLE_FILE_BYTES_LIMIT_EXCEEDED'
      ])
    );
    expect(JSON.stringify(result.rejectedPaths)).not.toContain('\u0000');
    expect(JSON.stringify(result.rejectedPaths)).not.toContain('\u202e');
  });

  it('escalates safe links, submodules, and LFS pointers but rejects escape and cycles', () => {
    const restricted = service.evaluate(
      baseInput([
        file('src/App.java'),
        file('src/link', 8, {
          kind: 'SYMLINK',
          symlinkTarget: 'App.java'
        }),
        file('modules/payments', 0, { kind: 'SUBMODULE' }),
        file('assets/large.bin', 120, { lfsPointer: true })
      ])
    );
    expect(restricted.decision).toBe('RESTRICTED_ESCALATION');
    expect(restricted.reasonCodes).toEqual(
      expect.arrayContaining([
        'SYMLINK_PRESENT',
        'SUBMODULE_PRESENT',
        'LFS_POINTER_PRESENT'
      ])
    );

    const rejected = service.evaluate(
      baseInput([
        file('src/outside', 8, {
          kind: 'SYMLINK',
          symlinkTarget: '../../etc/passwd'
        }),
        file('a', 1, { kind: 'SYMLINK', symlinkTarget: 'b' }),
        file('b', 1, { kind: 'SYMLINK', symlinkTarget: 'a' }),
        file('prefix-a', 1, {
          kind: 'SYMLINK',
          symlinkTarget: 'prefix-b/child'
        }),
        file('prefix-b', 1, {
          kind: 'SYMLINK',
          symlinkTarget: 'prefix-a'
        })
      ])
    );
    expect(rejected.decision).toBe('REJECT');
    expect(rejected.reasonCodes).toEqual(
      expect.arrayContaining(['SYMLINK_OUTSIDE_ROOT', 'SYMLINK_CYCLE'])
    );

    const invalidTarget = service.evaluate(
      baseInput([
        file('invalid-target', 8, {
          kind: 'SYMLINK',
          symlinkTarget: '[invalid-utf8]',
          symlinkTargetEncodingValid: false
        })
      ])
    );
    expect(invalidTarget.decision).toBe('REJECT');
    expect(invalidTarget.reasonCodes).toContain('SYMLINK_INVALID_UTF8');
  });

  it('classifies generated, vendor, fixture, hidden, archive, and LFS entries deterministically', () => {
    const result = service.evaluate(
      baseInput([
        file('generated/Model.java'),
        file('vendor/Library.java'),
        file('fixtures/Vulnerable.java'),
        file('.cache/Hidden.java'),
        file('bundle.tar.gz'),
        file('large.bin', 120, { lfsPointer: true })
      ])
    );
    expect(result.counts).toMatchObject({
      generatedCount: 1,
      vendorCount: 1,
      fixtureCount: 1,
      hiddenSystemCount: 1,
      archiveCount: 1,
      lfsPointerCount: 1
    });
    expect(result.reasonCodes).toEqual(
      expect.arrayContaining(['ARCHIVE_PRESENT', 'LFS_POINTER_PRESENT'])
    );
  });

  it('rejects malformed runtime metadata before evaluating hostile paths', () => {
    const malformedEntry = {
      ...file('src/App.java'),
      kind: 'DEVICE'
    };
    expect(() =>
      service.evaluate({
        ...baseInput([]),
        entries: [malformedEntry] as unknown as SastRepositoryTreeEntry[]
      })
    ).toThrow('Repository preflight entry metadata is invalid.');

    expect(() =>
      service.evaluate(
        baseInput([
          file('src/App.java', 10, {
            gitObjectId: `sha256:${'1'.repeat(64)}`
          })
        ])
      )
    ).toThrow('Repository preflight entry metadata is invalid.');

    expect(() =>
      service.evaluate({
        ...baseInput([file('src/App.java')]),
        limits: {
          ...profile.limits,
          maxFileCount: Number.MAX_SAFE_INTEGER + 1
        }
      })
    ).toThrow('Repository preflight input is incomplete.');
  });
});
