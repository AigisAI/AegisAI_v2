import { createHash } from 'node:crypto';
import { verifiedRuleBundleLifecycle, verifiedTenantRulePolicy } from '../support/sast-scan-plan-fixtures';

import {
  SAST_APPROVED_PROFILE_DIGESTS,
  SAST_ARTIFACT_ENVELOPE_HEADER,
  SAST_ARTIFACT_IDEMPOTENCY_HEADER,
  SAST_ARTIFACT_INGRESS_MEDIA_TYPE,
  SAST_FORBIDDEN_CAPABILITIES,
  SAST_SCAN_PROFILES,
  buildSastArtifactIngressIdempotencyKey,
  canonicalizeScannerArtifactEnvelope,
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  type ScannerArtifactEnvelope,
  type SastScanPlan
} from '@aegisai/shared';
import { ValidationPipe, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { Request } from 'express';
import request from 'supertest';

import { SastArtifactIngressController } from '../../src/scan-plane/sast-artifact-ingress.controller';
import { SastArtifactIngressService } from '../../src/scan-plane/sast-artifact-ingress.service';
import { SastArtifactValidationService } from '../../src/scan-plane/sast-artifact-validation.service';
import {
  SastFileCoordinateAttestationProvider,
  UnavailableSastFileCoordinateAttestationProvider
} from '../../src/scan-plane/sast-file-coordinate-attestation.provider';
import {
  type AbortSastArtifactIngressInput,
  type CompleteSastArtifactIngressInput,
  type RejectSastArtifactIngressInput,
  type ReserveSastArtifactIngressInput,
  SastArtifactIngressReplayConflictError,
  type SastArtifactIngressReservation,
  type SastArtifactIngressRejectionAudit,
  type SastArtifactIngressExpectedBinding,
  SastArtifactIngressStore
} from '../../src/scan-plane/sast-artifact-ingress.store';
import {
  SastArtifactObjectStore,
  type SastArtifactObjectWrite,
  type SastArtifactObjectWriteResult
} from '../../src/scan-plane/sast-artifact-object-store';
import {
  DirectMtlsSastWorkloadIdentityAuthenticator,
  type AuthenticatedSastWorkloadIdentity,
  SastWorkloadIdentityAuthenticator
} from '../../src/scan-plane/sast-workload-identity.authenticator';
import { SastWorkloadIdentityGuard } from '../../src/scan-plane/sast-workload-identity.guard';

const digest = (value: string): `sha256:${string}` =>
  `sha256:${createHash('sha256').update(value).digest('hex')}`;
const FIXED_COMMIT = 'a'.repeat(40);
const ARTIFACT_BYTES = Buffer.from(
  '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"OpenGrep"}},"results":[]}]}',
  'utf8'
);

class InMemoryArtifactIngressStore extends SastArtifactIngressStore {
  expected = buildExpectedBinding();
  rejectionAudits: SastArtifactIngressRejectionAudit[] = [];
  reservations = new Map<
    string,
    {
      input: ReserveSastArtifactIngressInput;
      state: 'RECEIVING' | 'PENDING_VALIDATION' | 'REJECTED';
      receivedAt?: string;
    }
  >();
  completeError?: Error;
  lastCompletion?: CompleteSastArtifactIngressInput;

  loadExpectedBinding(
    scanRequestId: string,
    scannerRunId: string
  ): Promise<SastArtifactIngressExpectedBinding | null> {
    return Promise.resolve(
      scanRequestId === this.expected.plan.scanRequestId &&
        scannerRunId === this.expected.scannerRunId
        ? this.expected
        : null
    );
  }

  reserve(
    input: Readonly<ReserveSastArtifactIngressInput>
  ): Promise<SastArtifactIngressReservation> {
    const existing = this.reservations.get(input.expected.scannerRunId);
    if (existing) {
      if (
        existing.input.envelopeDigest !== input.envelopeDigest ||
        existing.input.idempotencyKey !== input.idempotencyKey ||
        existing.input.declaredContentDigest !==
          input.declaredContentDigest ||
        existing.input.declaredByteSize !== input.declaredByteSize
      ) {
        throw new SastArtifactIngressReplayConflictError();
      }
      return Promise.resolve({
        kind: 'REPLAY',
        ingestionId: existing.input.ingestionId,
        state: 'PENDING_VALIDATION',
        receivedAt: existing.receivedAt
      });
    }
    this.reservations.set(input.expected.scannerRunId, {
      input: structuredClone(input),
      state: 'RECEIVING'
    });
    return Promise.resolve({
      kind: 'RESERVED',
      ingestionId: input.ingestionId,
      state: 'RECEIVING'
    });
  }

  complete(
    input: Readonly<CompleteSastArtifactIngressInput>
  ): Promise<void> {
    if (this.completeError) {
      return Promise.reject(this.completeError);
    }
    const reservation = [...this.reservations.values()].find(
      (candidate) => candidate.input.ingestionId === input.ingestionId
    );
    if (!reservation) throw new Error('missing reservation');
    this.lastCompletion = structuredClone(input);
    reservation.state = 'PENDING_VALIDATION';
    reservation.receivedAt = input.receivedAt;
    return Promise.resolve();
  }

  reject(input: Readonly<RejectSastArtifactIngressInput>): Promise<void> {
    const reservation = [...this.reservations.values()].find(
      (candidate) => candidate.input.ingestionId === input.ingestionId
    );
    if (reservation) reservation.state = 'REJECTED';
    return Promise.resolve();
  }

  abort(input: Readonly<AbortSastArtifactIngressInput>): Promise<void> {
    for (const [scannerRunId, reservation] of this.reservations.entries()) {
      if (reservation.input.ingestionId === input.ingestionId) {
        this.reservations.delete(scannerRunId);
      }
    }
    return Promise.resolve();
  }

  recordRejectedRequest(
    input: Readonly<SastArtifactIngressRejectionAudit>
  ): Promise<void> {
    this.rejectionAudits.push(structuredClone(input));
    return Promise.resolve();
  }
}

class InMemoryArtifactObjectStore extends SastArtifactObjectStore {
  writes = 0;
  objects = new Map<string, Buffer>();
  consumeBody = true;
  deleteError?: Error;

  async put(
    input: Readonly<SastArtifactObjectWrite>
  ): Promise<SastArtifactObjectWriteResult> {
    this.writes += 1;
    const chunks: Buffer[] = [];
    if (this.consumeBody) {
      for await (const chunk of input.body) {
        chunks.push(Buffer.from(chunk));
      }
    }
    const objectKey = `raw-sast/${input.ingestionId}`;
    this.objects.set(objectKey, Buffer.concat(chunks));
    return { objectKey };
  }

  delete(objectKey: string): Promise<void> {
    if (this.deleteError) {
      return Promise.reject(this.deleteError);
    }
    this.objects.delete(objectKey);
    return Promise.resolve();
  }
}

describe('SAST per-scan write-only artifact ingress', () => {
  let app: INestApplication;
  let ingressStore: InMemoryArtifactIngressStore;
  let objectStore: InMemoryArtifactObjectStore;
  let authenticatedIdentity: AuthenticatedSastWorkloadIdentity | null;

  beforeEach(async () => {
    ingressStore = new InMemoryArtifactIngressStore();
    objectStore = new InMemoryArtifactObjectStore();
    authenticatedIdentity = {
      identityRef: ingressStore.expected.workloadIdentityRef,
      certificateFingerprint: digest('certificate')
    };
    const authenticator = {
      authenticate: jest.fn(
        async () => authenticatedIdentity
      )
    } satisfies Pick<SastWorkloadIdentityAuthenticator, 'authenticate'>;
    const module = await Test.createTestingModule({
      controllers: [SastArtifactIngressController],
      providers: [
        SastArtifactIngressService,
        SastArtifactValidationService,
        SastWorkloadIdentityGuard,
        UnavailableSastFileCoordinateAttestationProvider,
        {
          provide: SastFileCoordinateAttestationProvider,
          useExisting: UnavailableSastFileCoordinateAttestationProvider
        },
        {
          provide: SastWorkloadIdentityAuthenticator,
          useValue: authenticator
        },
        {
          provide: SastArtifactIngressStore,
          useValue: ingressStore
        },
        {
          provide: SastArtifactObjectStore,
          useValue: objectStore
        }
      ]
    }).compile();
    app = module.createNestApplication();
    app.setGlobalPrefix('api');
    app.useGlobalPipes(
      new ValidationPipe({
        forbidNonWhitelisted: true,
        transform: true,
        whitelist: true
      })
    );
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it('streams one immutable artifact and returns only a validation-pending receipt', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    const response = await upload(app, envelope, ARTIFACT_BYTES).expect(202);

    expect(response.body).toMatchObject({
      scannerRunId: envelope.scannerRunId,
      state: 'PENDING_VALIDATION',
      replayed: false
    });
    expect(response.body.ingestionId).toMatch(/^sast_ingestion_/);
    expect(response.body).not.toHaveProperty('objectKey');
    expect(response.body).not.toHaveProperty('artifactBytes');
    expect(objectStore.writes).toBe(1);
    expect([...objectStore.objects.values()][0]).toEqual(ARTIFACT_BYTES);
    expect(
      ingressStore.reservations.get(envelope.scannerRunId)?.state
    ).toBe('PENDING_VALIDATION');
    expect(ingressStore.lastCompletion?.validation).toMatchObject({
      outcome: 'PASSED',
      reasonCodes: []
    });
  });

  it('has no artifact read route', async () => {
    await request(app.getHttpServer())
      .get('/api/scan-plane/result-ingress/scan-1/scanner-runs/scanner-run-1')
      .expect(404);
  });

  it('rejects unauthenticated and mismatched workload identities before object storage', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    authenticatedIdentity = null;
    await upload(app, envelope, ARTIFACT_BYTES).expect(401);

    authenticatedIdentity = {
      identityRef: 'spiffe://aegis/scan/attempt-other',
      certificateFingerprint: digest('other-certificate')
    };
    const mismatch = await upload(app, envelope, ARTIFACT_BYTES).expect(403);

    expect(mismatch.body.errorCode).toBe(
      'ARTIFACT_WORKLOAD_IDENTITY_MISMATCH'
    );
    expect(objectStore.writes).toBe(0);
    expect(ingressStore.reservations.size).toBe(0);
    expect(ingressStore.rejectionAudits).toEqual([
      expect.objectContaining({
        reasonCode: 'ARTIFACT_WORKLOAD_IDENTITY_MISMATCH',
        workloadIdentityValidated: false
      })
    ]);
  });

  it('rejects cross-scan scope and closed lifecycle submissions', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    const wrongScope = {
      ...envelope,
      repositoryBindingId: 'repository-other'
    };
    const scopeResponse = await upload(
      app,
      wrongScope,
      ARTIFACT_BYTES
    ).expect(403);
    expect(scopeResponse.body.errorCode).toBe(
      'ARTIFACT_SCOPE_BINDING_MISMATCH'
    );
    expect(ingressStore.rejectionAudits.at(-1)).toMatchObject({
      workloadIdentityValidated: true
    });

    ingressStore.expected = {
      ...ingressStore.expected,
      attemptStage: 'CLEANUP_PENDING'
    };
    const closedResponse = await upload(
      app,
      envelope,
      ARTIFACT_BYTES
    ).expect(409);
    expect(closedResponse.body.errorCode).toBe('ARTIFACT_INGRESS_CLOSED');
    expect(objectStore.writes).toBe(0);
  });

  it('handles an exact replay idempotently and rejects a changed envelope', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    const first = await upload(app, envelope, ARTIFACT_BYTES).expect(202);
    const replay = await upload(app, envelope, ARTIFACT_BYTES).expect(202);

    expect(replay.body).toEqual({
      ...first.body,
      replayed: true
    });
    expect(objectStore.writes).toBe(1);

    const changedEnvelope = {
      ...envelope,
      producedAt: new Date(Date.now() - 1_000).toISOString()
    };
    const conflict = await upload(
      app,
      changedEnvelope,
      ARTIFACT_BYTES
    ).expect(409);
    expect(conflict.body.errorCode).toBe(
      'ARTIFACT_INGRESS_REPLAY_CONFLICT'
    );
    expect(objectStore.writes).toBe(1);
  });

  it('requires canonical envelope, media type, idempotency key, and byte length', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    const endpoint =
      `/api/scan-plane/result-ingress/${envelope.scanRequestId}` +
      `/scanner-runs/${envelope.scannerRunId}`;
    const nonCanonical = Buffer.from(
      JSON.stringify(envelope, null, 2),
      'utf8'
    ).toString('base64url');

    await request(app.getHttpServer())
      .put(endpoint)
      .set('content-type', SAST_ARTIFACT_INGRESS_MEDIA_TYPE)
      .set(SAST_ARTIFACT_ENVELOPE_HEADER, nonCanonical)
      .set(
        SAST_ARTIFACT_IDEMPOTENCY_HEADER,
        buildSastArtifactIngressIdempotencyKey(envelope)
      )
      .send(ARTIFACT_BYTES)
      .expect(400);
    await request(app.getHttpServer())
      .put(endpoint)
      .set('content-type', 'application/json')
      .set(SAST_ARTIFACT_ENVELOPE_HEADER, encodeEnvelope(envelope))
      .set(
        SAST_ARTIFACT_IDEMPOTENCY_HEADER,
        buildSastArtifactIngressIdempotencyKey(envelope)
      )
      .send(ARTIFACT_BYTES)
      .expect(415);
    await request(app.getHttpServer())
      .put(endpoint)
      .set('content-type', SAST_ARTIFACT_INGRESS_MEDIA_TYPE)
      .set(SAST_ARTIFACT_ENVELOPE_HEADER, encodeEnvelope(envelope))
      .set(SAST_ARTIFACT_IDEMPOTENCY_HEADER, 'caller-controlled')
      .send(ARTIFACT_BYTES)
      .expect(400);

    expect(objectStore.writes).toBe(0);
  });

  it('leaves no RECEIVING reservation when rejected-object cleanup fails', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    objectStore.consumeBody = false;
    objectStore.deleteError = new Error('cleanup unavailable');

    const response = await upload(app, envelope, ARTIFACT_BYTES).expect(503);

    expect(response.body.errorCode).toBe('ARTIFACT_OBJECT_DELETE_FAILED');
    expect(
      ingressStore.reservations.get(envelope.scannerRunId)?.state
    ).toBe('REJECTED');
  });

  it('aborts the RECEIVING reservation before failed cleanup after persistence errors', async () => {
    const envelope = buildEnvelope(ingressStore.expected.plan);
    ingressStore.completeError = new Error('persistence unavailable');
    objectStore.deleteError = new Error('cleanup unavailable');

    const response = await upload(app, envelope, ARTIFACT_BYTES).expect(503);

    expect(response.body.errorCode).toBe('ARTIFACT_OBJECT_DELETE_FAILED');
    expect(ingressStore.reservations.has(envelope.scannerRunId)).toBe(false);
  });
});

describe('DirectMtlsSastWorkloadIdentityAuthenticator', () => {
  const authenticator = new DirectMtlsSastWorkloadIdentityAuthenticator();

  it('accepts only one currently valid SPIFFE URI from an authorized direct TLS peer', async () => {
    const raw = Buffer.from('certificate');
    const identity = await authenticator.authenticate({
      socket: {
        encrypted: true,
        authorized: true,
        getPeerCertificate: () => ({
          raw,
          subjectaltname: 'URI:spiffe://aegis/scan/attempt-1',
          valid_from: new Date(Date.now() - 60_000).toUTCString(),
          valid_to: new Date(Date.now() + 60_000).toUTCString()
        })
      }
    } as unknown as Request);

    expect(identity).toEqual({
      identityRef: 'spiffe://aegis/scan/attempt-1',
      certificateFingerprint: digest('certificate')
    });
  });

  it('does not trust identity headers, unauthorized TLS, or ambiguous URI SANs', async () => {
    await expect(
      authenticator.authenticate({
        headers: {
          'x-forwarded-client-cert':
            'URI=spiffe://aegis/scan/attempt-1'
        },
        socket: {}
      } as unknown as Request)
    ).resolves.toBeNull();
    await expect(
      authenticator.authenticate({
        socket: {
          encrypted: true,
          authorized: false,
          getPeerCertificate: () => ({})
        }
      } as unknown as Request)
    ).resolves.toBeNull();
    await expect(
      authenticator.authenticate({
        socket: {
          encrypted: true,
          authorized: true,
          getPeerCertificate: () => ({
            raw: Buffer.from('certificate'),
            subjectaltname:
              'URI:spiffe://aegis/scan/attempt-1, URI:spiffe://aegis/scan/attempt-2',
            valid_from: new Date(Date.now() - 60_000).toUTCString(),
            valid_to: new Date(Date.now() + 60_000).toUTCString()
          })
        }
      } as unknown as Request)
    ).resolves.toBeNull();
  });

  it('rejects SPIFFE IDs with non-canonical trust domains or path segments', async () => {
    const authenticate = (identityRef: string) =>
      authenticator.authenticate({
        socket: {
          encrypted: true,
          authorized: true,
          getPeerCertificate: () => ({
            raw: Buffer.from('certificate'),
            subjectaltname: `URI:${identityRef}`,
            valid_from: new Date(Date.now() - 60_000).toUTCString(),
            valid_to: new Date(Date.now() + 60_000).toUTCString()
          })
        }
      } as unknown as Request);

    await expect(
      authenticate('spiffe://Aegis/scan/attempt-1')
    ).resolves.toBeNull();
    await expect(
      authenticate('spiffe://aegis/scan/attempt%2D1')
    ).resolves.toBeNull();
    await expect(
      authenticate('spiffe://aegis/scan/attempt@1')
    ).resolves.toBeNull();
    await expect(authenticate('spiffe://aegis/scan/../attempt-1')).resolves.toBeNull();
    await expect(
      authenticate('spiffe://aegis/scan/attempt_1.with-valid-chars')
    ).resolves.toMatchObject({
      identityRef: 'spiffe://aegis/scan/attempt_1.with-valid-chars'
    });
  });
});

function buildEnvelope(plan: SastScanPlan): ScannerArtifactEnvelope {
  const scanner = plan.scannerSet.scanners.OPENGREP;
  const rule = plan.scannerSet.ruleBundles.find(
    (bundle) => bundle.scanner === 'OPENGREP'
  )!;
  return {
    tenantId: plan.tenantId,
    repositoryBindingId: plan.repositoryState.repositoryBindingId,
    scanRequestId: plan.scanRequestId,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    scanner: 'OPENGREP',
    scannerVersion: scanner.version,
    scannerImageDigest: scanner.digest,
    wrapperDigest: scanner.wrapper.digest,
    ruleBundleDigest: rule.digest,
    scannerSetDigest: plan.scannerSet.scannerSetDigest,
    schemaBundleDigest: plan.scannerSet.schemaBundle.digest,
    normalizerBundleDigest: plan.scannerSet.normalizerBundle.digest,
    profileId: plan.profile.id,
    profileDigest: plan.profileDigest,
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    scannerWorkspaceInventoryDigest: digest('inventory'),
    inputCommitSha: plan.repositoryState.fixedCommitSha,
    artifactSchema: 'OPENGREP_SARIF',
    artifactSchemaVersion:
      SAST_ARTIFACT_SCHEMA_VERSIONS.OPENGREP_SARIF,
    artifactRef: `${plan.resultIngressRef}/opengrep`,
    contentDigest: digest(ARTIFACT_BYTES.toString('utf8')),
    byteSize: ARTIFACT_BYTES.byteLength,
    recordCount: 0,
    truncated: false,
    exitCode: 0,
    executionStatus: 'SUCCEEDED',
    producedAt: new Date().toISOString()
  };
}

function buildExpectedBinding(): SastArtifactIngressExpectedBinding {
  const plan = buildPlan();
  return {
    plan,
    attemptId: 'attempt-1',
    scannerRunId: 'scanner-run-1',
    workloadIdentityRef: 'spiffe://aegis/scan/attempt-1',
    preflightAttestationRef: 'preflight://attempt-1',
    preflightInventoryDigest: digest('inventory'),
    scanner: 'OPENGREP',
    artifactRef: `${plan.resultIngressRef}/opengrep`,
    attemptStage: 'SCANNING',
    attemptDeadlineAt: new Date(Date.now() + 60_000).toISOString(),
    scannerRunStatus: 'RUNNING'
  };
}

function buildPlan(): SastScanPlan {
  const profile = SAST_SCAN_PROFILES.JAVA_FAST_V1;
  const signed = (value: string) => ({
    digest: digest(value),
    signatureRef: `signature://${value}`,
    provenanceRef: `provenance://${value}`
  });
  const scanner = (
    kind: 'OPENGREP' | 'TRIVY' | 'SYFT',
    value: string
  ) => ({
    ...signed(`scanner-${value}`),
    scanner: kind,
    version: '1.0.0',
    sbomRef: `sbom://${kind.toLowerCase()}`,
    wrapper: signed(`wrapper-${value}`)
  });
  const rule = (kind: 'OPENGREP' | 'TRIVY', value: string) => ({
    ...signed(`rule-${value}`),
    bundleId: `${kind.toLowerCase()}-rules`,
    version: '1',
    state: 'ACTIVE' as const,
    manifestId: `sast-rule-bundle-manifest://${digest(`manifest-${value}`).slice('sha256:'.length)}`,
    manifestDigest: digest(`manifest-${value}`),
    verificationId: `sast-rule-bundle-verification://${digest(`manifest-${value}`).slice('sha256:'.length)}`,
    verificationDigest: digest(`verification-${value}`),
    compatibilityRef: `compatibility://${value}`,
    rolloutPolicyRef: `rollout://${value}`,
    killSwitchRef: `kill-switch://${value}`,
    rollbackTargetDigest: digest(`rollback-${value}`),
    compatibilityReceiptId: `sast-rule-bundle-compatibility://${digest(`receipt-${value}`).slice('sha256:'.length)}`,
    compatibilityReceiptDigest: digest(`receipt-${value}`),
    lifecycle: verifiedRuleBundleLifecycle(value),
    scanner: kind,
    source: 'PLATFORM_MANAGED' as const,
    immutable: true as const,
    customerExecutableConfigAllowed: false as const,
    rules: [
      {
        ruleId: `${kind.toLowerCase()}.fixture`,
        ruleRevision: '1',
        ruleSemanticId: `${kind.toLowerCase()}.fixture`,
        metadataDigest: digest(`rule-metadata-${value}`)
      }
    ]
  });
  return {
    tenantId: 'tenant-1',
    scanRequestId: 'scan-1',
    canonicalScanKey: digest('canonical'),
    profile,
    profileDigest: SAST_APPROVED_PROFILE_DIGESTS[profile.id],
    policyVersion: 'policy-v1',
    tenantRulePolicy: verifiedTenantRulePolicy('policy-v1'),
    repositoryState: {
      repositoryBindingId: 'repository-1',
      fixedCommitSha: FIXED_COMMIT,
      targetRef: 'refs/heads/main',
      inventoryDigest: digest('inventory'),
      attestationRef: 'repository-attestation://scan-1',
      shallowFetchPreferred: true,
      submodulesEnabled: false,
      lfsObjectsFetched: false
    },
    scannerSet: {
      scannerSetVersion: 'scanner-set-v1',
      scannerSetDigest: digest('scanner-set'),
      signatureRef: 'signature://scanner-set',
      provenanceRef: 'provenance://scanner-set',
      scanners: {
        OPENGREP: scanner('OPENGREP', 'opengrep'),
        TRIVY: scanner('TRIVY', 'trivy'),
        SYFT: scanner('SYFT', 'syft')
      },
      ruleBundles: [
        rule('OPENGREP', 'opengrep'),
        rule('TRIVY', 'trivy')
      ],
      vulnerabilityDatabase: {
        ...signed('trivy-db'),
        databaseVersion: '2026-07-24',
        publishedAt: '2026-07-24T00:00:00.000Z'
      },
      schemaBundle: signed('schema'),
      normalizerBundle: signed('normalizer'),
      sbomSchema: 'CYCLONEDX_JSON',
      rollbackRef: 'rollback://scanner-set-v0'
    },
    isolationClass: 'HARDENED',
    resultIngressRef: 'result-ingress://tenant-1/scan-1',
    evidenceOutputRef: 'evidence-output://tenant-1/scan-1',
    auditSinkRef: 'audit-sink://tenant-1/scan-1',
    forbiddenCapabilities: [...SAST_FORBIDDEN_CAPABILITIES],
    createdAt: new Date().toISOString()
  };
}

function encodeEnvelope(envelope: ScannerArtifactEnvelope): string {
  return Buffer.from(
    canonicalizeScannerArtifactEnvelope(envelope),
    'utf8'
  ).toString('base64url');
}

function upload(
  app: INestApplication,
  envelope: ScannerArtifactEnvelope,
  bytes: Buffer
) {
  return request(app.getHttpServer())
    .put(
      `/api/scan-plane/result-ingress/${envelope.scanRequestId}` +
        `/scanner-runs/${envelope.scannerRunId}`
    )
    .set('content-type', SAST_ARTIFACT_INGRESS_MEDIA_TYPE)
    .set(SAST_ARTIFACT_ENVELOPE_HEADER, encodeEnvelope(envelope))
    .set(
      SAST_ARTIFACT_IDEMPOTENCY_HEADER,
      buildSastArtifactIngressIdempotencyKey(envelope)
    )
    .send(bytes);
}
