import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  SAST_PRODUCTION_GO_NO_GO_ENTRY_ATTESTATION_VERSION,
  SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS,
  buildSastProductionGoNoGoEntryAttestation,
  buildSastProductionGoNoGoEvidenceAttestation,
  buildSastProductionGoNoGoPlan,
  deriveSastProductionGoNoGoUpstreamObservations,
  evaluateSastSupplyChainRollbackQualificationEvidence
} from '../../dist/index.js';
import { createProductionGoNoGoAssets } from '../../../../tools/sast-qualification/production-go-no-go-assets.mjs';
import { createT055QualificationBundle } from './t055-qualification-fixture.mjs';

const SIGNATURE_BYTES = Buffer.alloc(64).toString('base64');
let defaultPrerequisite;

export function createT056GoNoGoBundle(options = {}) {
  const signatureFactory = options.signatureFactory ?? signature;
  const prerequisite = options.signatureFactory || options.trustPolicyText
    ? createPrerequisite(
        signatureFactory,
        options.trustPolicyText,
        options.entryVerifiedAt
      )
    : (defaultPrerequisite ??= createPrerequisite(signature, undefined, undefined));
  const { assets, t055, upstream, entryAttestation } = prerequisite;
  const evidenceObservedAtBase = options.evidenceObservedAtBase
    ? Date.parse(options.evidenceObservedAtBase)
    : null;

  const evidenceAttestations = SAST_PRODUCTION_GO_NO_GO_EVIDENCE_KINDS.map(
    (evidenceKind, index) => {
      const evidenceDigest = digest(`t056-evidence:${evidenceKind}`);
      const evidenceRef =
        `qualification-evidence://aegisai/t056/${evidenceKind.toLowerCase()}/${evidenceDigest}`;
      const observations = assets.manifest.gates
        .filter((item) => item.evidenceKind === evidenceKind)
        .map((definition) => ({
          gateId: definition.gateId,
          disposition: options.notApplicableGateId === definition.gateId
            ? 'NOT_APPLICABLE'
            : 'MEASURED',
          observedValue: options.notApplicableGateId === definition.gateId
            ? null
            : observationValue(
                definition.gateId,
                upstream,
                options.overrides ?? {}
              ),
          unit: definition.unit,
          evidenceRef,
          evidenceDigest
        }));
      const observedAt = evidenceObservedAtBase === null
        ? `2026-08-20T20:0${index}:00.000Z`
        : new Date(evidenceObservedAtBase + index * 1_000).toISOString();
      const baseInput = {
        manifestId: assets.manifest.manifestId,
        manifestDigest: assets.manifest.manifestDigest,
        entryAttestationId: entryAttestation.attestationId,
        entryAttestationDigest: entryAttestation.attestationDigest,
        evidenceKind,
        providerId: entryAttestation.providerId,
        providerAdapterRef: entryAttestation.providerAdapterRef,
        repositoryCommitSha: 'a'.repeat(40),
        candidateScannerSetDigest: entryAttestation.candidateScannerSetDigest,
        baselineScannerSetDigest: entryAttestation.baselineScannerSetDigest,
        profileSetDigest: entryAttestation.profileSetDigest,
        t051SnapshotDigest: entryAttestation.t051SnapshotDigest,
        t051PriorReleaseManifestDigest:
          entryAttestation.t051PriorReleaseManifestDigest,
        t052SnapshotDigest: entryAttestation.t052SnapshotDigest,
        t054MeasurementsDigest: entryAttestation.t054MeasurementsDigest,
        t055MeasurementsDigest: entryAttestation.t055MeasurementsDigest,
        evidenceRef,
        evidenceDigest,
        observedAt,
        validUntil: options.staleEvidenceKind === evidenceKind
          ? '2026-08-20T20:10:00.000Z'
          : options.evidenceValidUntil ?? '2026-08-21T20:00:00.000Z',
        observations,
        externalEvidence: evidenceKind !== 'REPOSITORY_VALIDATION'
      };
      const unsigned = buildSastProductionGoNoGoEvidenceAttestation(
        baseInput,
        [],
        digest
      );
      assert.ok(
        unsigned,
        `failed to build ${evidenceKind} evidence: ${JSON.stringify(observations)}`
      );
      const roles = assets.manifest.gates.find(
        (item) => item.evidenceKind === evidenceKind
      ).requiredSignatureRoles;
      const signed = buildSastProductionGoNoGoEvidenceAttestation(
        baseInput,
        roles.map((role) =>
          signatureFactory(
            role,
            unsigned.attestationDigest,
            baseInput.observedAt,
            `t056-${evidenceKind}`
          )
        ),
        digest
      );
      assert.ok(signed);
      return signed;
    }
  );
  const decidedAt = options.decidedAt ?? '2026-08-20T20:30:00.000Z';
  const trustedEvaluatedAt = options.trustedEvaluatedAt ??
    new Date(Date.parse(decidedAt) + 1_000).toISOString();
  const plan = buildSastProductionGoNoGoPlan(
    {
      manifest: assets.manifest,
      entryAttestation,
      evidenceAttestations,
      decisionActorRef: digestRef(
        'deployment-operator://aegisai/t056',
        't056-decision-actor'
      ),
      decidedAt,
      verifySignature: () => true
    },
    digest
  );
  assert.ok(plan);
  const approvals = SAST_END_TO_END_QUALIFICATION_APPROVAL_ROLES.map((role) =>
    signatureFactory(
      role,
      plan.planDigest,
      options.approvalSignedAt ?? decidedAt,
      't056-approval'
    )
  );
  return {
    assets,
    t055,
    upstream,
    entryAttestation,
    evidenceAttestations,
    plan,
    approvals,
    evaluationInput: {
      manifest: assets.manifest,
      t054Manifest: assets.t054Manifest,
      t055Manifest: assets.t055Manifest,
      upstream,
      entryAttestation,
      evidenceAttestations,
      plan,
      approvals,
      trustedEvaluatedAt,
      verifySignature: () => true
    }
  };
}

function createPrerequisite(signatureFactory, trustPolicyText, entryVerifiedAt) {
  const assets = createProductionGoNoGoAssets();
  const t055 = createT055QualificationBundle({
    manifest: assets.t055Manifest,
    signatureFactory,
    trustPolicyText
  });
  const t055Result = evaluateSastSupplyChainRollbackQualificationEvidence(
    t055.evaluationInput,
    digest
  );
  assert.ok(t055Result);
  assert.equal(t055Result.status, 'PASSED');
  const upstream = {
    t054Result: t055.result,
    t054DependencySet: t055.dependencySet,
    t054ArtifactVerificationSet: t055.artifactVerificationSet,
    t054Plan: t055.t054Plan,
    t055EntryAttestation: t055.entryAttestation,
    t055Plan: t055.plan,
    t055Result
  };
  const verifiedAt = entryVerifiedAt ?? '2026-08-20T19:55:00.000Z';
  const verifierRef = digestRef(
    'qualification-verifier://aegisai/t056-entry',
    't056-entry-verifier'
  );
  const rollbackTargetDigest = t055.plan.rollbackLedgerHeadAttestations[0]
    .baselineReleaseSetDigest;
  const profileSetDigest = digest(stableJson(assets.t054Manifest.profiles));
  const entryCore = {
    version: SAST_PRODUCTION_GO_NO_GO_ENTRY_ATTESTATION_VERSION,
    manifestId: assets.manifest.manifestId,
    manifestDigest: assets.manifest.manifestDigest,
    t054ManifestId: assets.t054Manifest.manifestId,
    t054ManifestDigest: assets.t054Manifest.manifestDigest,
    t054ResultId: upstream.t054Result.resultId,
    t054ResultDigest: upstream.t054Result.resultDigest,
    t054DependencySetId: upstream.t054DependencySet.dependencySetId,
    t054DependencySetDigest: upstream.t054DependencySet.dependencySetDigest,
    t055ManifestId: assets.t055Manifest.manifestId,
    t055ManifestDigest: assets.t055Manifest.manifestDigest,
    t055PlanId: upstream.t055Plan.planId,
    t055PlanDigest: upstream.t055Plan.planDigest,
    t055ResultId: upstream.t055Result.resultId,
    t055ResultDigest: upstream.t055Result.resultDigest,
    providerId: upstream.t054DependencySet.providerId,
    providerAdapterRef: upstream.t054DependencySet.providerAdapterRef,
    candidateScannerSetDigest: upstream.t054DependencySet.candidateScannerSetDigest,
    baselineScannerSetDigest: upstream.t054DependencySet.baselineScannerSetDigest,
    profileSetDigest,
    t051SnapshotDigest: assets.t054Manifest.t051SnapshotDigest,
    t051PriorReleaseManifestDigest:
      assets.t054Manifest.t051PriorReleaseManifestDigest,
    t052SnapshotDigest: assets.t054Manifest.t052SnapshotDigest,
    t054MeasurementsDigest: upstream.t054Result.measurements.measurementsDigest,
    t055MeasurementsDigest: upstream.t055Result.measurements.measurementsDigest,
    rollbackTargetDigest,
    verifiedAt,
    verifierRef,
    t056EntryAuthorized: true,
    findingAuthority: false,
    policyAuthority: false,
    publicationAuthority: false,
    scmMutationAuthority: false,
    deploymentAuthority: false,
    kubernetesExecutionAuthority: false,
    productionMutationAuthority: false,
    productionReadinessAuthority: false
  };
  const entryDigest = digest(stableJson(entryCore));
  const entryAttestation = buildSastProductionGoNoGoEntryAttestation(
    {
      manifest: assets.manifest,
      t054Manifest: assets.t054Manifest,
      t055Manifest: assets.t055Manifest,
      upstream,
      verifiedAt,
      verifierRef,
      signature: signatureFactory(
        'QUALIFICATION_AUTHORITY',
        entryDigest,
        verifiedAt,
        't056-entry'
      ),
      verifySignature: () => true
    },
    digest
  );
  assert.ok(entryAttestation);
  return { assets, t055, upstream, entryAttestation };
}

function observationValue(gateId, upstream, overrides) {
  if (Object.hasOwn(overrides, gateId)) return overrides[gateId];
  const upstreamValues = deriveSastProductionGoNoGoUpstreamObservations(
    upstream.t054Result,
    upstream.t055Result
  );
  if (upstreamValues?.has(gateId)) return upstreamValues.get(gateId);
  const values = {
    REPOSITORY_CONTRACT_TESTS: 1,
    REPOSITORY_STATIC_VALIDATION: 1,
    REPOSITORY_DATABASE_VALIDATION: 1,
    NORMALIZATION_DATA_INTEGRITY: 1,
    EVIDENCE_RETENTION_DELETION: 1,
    AI_ADVISORY_ZERO_AUTHORITY: 1,
    CANARY_SIX_STEP_REPLAY: 6,
    CANARY_SAMPLE_SUFFICIENCY: 1_000,
    CANARY_OBSERVATION_WINDOW: 48,
    CANARY_TELEMETRY_COMPLETE: 1,
    CANARY_THRESHOLDS_ZERO_TOLERANCE: 1,
    KILL_SWITCH_PROPAGATION_BOUNDARIES: 5,
    KILL_SWITCH_FAIL_CLOSED: 1,
    KILL_SWITCH_DEACTIVATION_RECOVERY: 1,
    KILL_SWITCH_FORBIDDEN_SIDE_EFFECTS: 0,
    ROLLBACK_SIGNED_CHAIN: 1,
    ROLLBACK_TARGET_DERIVED: 1,
    ROLLBACK_POST_FENCE_INVOCATIONS: 0,
    DEPLOYMENT_OPERATIONS_REFERENCE_ONLY: 1,
    KUBERNETES_EXECUTION_NOT_PERFORMED: 0
  };
  assert.ok(Object.hasOwn(values, gateId), `missing fixture value for ${gateId}`);
  return values[gateId];
}

export function signature(role, payloadDigest, signedAt, namespace = 't056') {
  const keyDigest = digest(`${namespace}:${role}:key`);
  return {
    version: SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
    role,
    keyId: `qualification-key://aegisai/${namespace}/${role.toLowerCase()}/${keyDigest}`,
    payloadDigest,
    signedAt,
    algorithm: 'ED25519',
    valueBase64: SIGNATURE_BYTES
  };
}

export function digest(value) {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
}

function digestRef(prefix, seed) {
  return `${prefix}/${digest(seed)}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort(compareText).map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}
