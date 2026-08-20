import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
  verify as verifyBytes
} from 'node:crypto';
import test from 'node:test';

import {
  DEPLOYMENT_CREDENTIAL_SCOPES,
  DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS,
  SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
  SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES,
  buildDeploymentSastQualificationBinding,
  buildDeploymentSastQualificationEntryAttestation,
  buildDeploymentSastQualificationEntryAttestationDraft,
  evaluateSastProductionGoNoGoEvidence,
  isDeploymentOperationHandoffManifestReady,
  isDeploymentOperationPreflightReady,
  isDeploymentCredentialBoundaryCompliant,
  isDeploymentSastQualificationBindingValid,
  isDeploymentSastQualificationEntryAttestationValid,
  isMicroVmPlatformRolloutBoundaryValid,
  isProductionClusterProvisioningBoundaryValid,
  serializeSastEndToEndQualificationSignaturePayload
} from '../dist/index.js';
import {
  createT056GoNoGoBundle,
  digest
} from './helpers/t056-go-no-go-fixture.mjs';

let cachedDeploymentQualification;

test('005 preflight accepts only a fresh Qualification Authority-signed T056 GO binding', () => {
  const qualification = getDeploymentQualification();
  const preflight = createPreflight(qualification);
  const handoff = createHandoff(preflight);

  assert.equal(
    isProductionClusterProvisioningBoundaryValid(preflight.clusterProvisioning),
    true
  );
  assert.equal(isMicroVmPlatformRolloutBoundaryValid(preflight.microVmRollout), true);
  assert.ok(preflight.credentialBoundaries.every(isDeploymentCredentialBoundaryCompliant));

  assert.equal(
    isDeploymentSastQualificationEntryAttestationValid(
      qualification.entryAttestation,
      qualification.record,
      qualification.context
    ),
    true
  );
  assert.equal(
    isDeploymentSastQualificationBindingValid(
      qualification.binding,
      qualification.evidence,
      qualification.context
    ),
    true
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      preflight,
      qualification.evidence,
      qualification.context
    ),
    true
  );
  assert.equal(
    isDeploymentOperationHandoffManifestReady(
      handoff,
      qualification.evidence,
      qualification.context
    ),
    true
  );

  assert.equal(qualification.binding.deploymentOperationsEntryAuthorized, true);
  for (const authority of [
    'findingAuthority',
    'policyAuthority',
    'publicationAuthority',
    'scmMutationAuthority',
    'aiAuthority',
    'deploymentAuthority',
    'kubernetesExecutionAuthority',
    'productionMutationAuthority',
    'productionReadinessAuthority'
  ]) {
    assert.equal(qualification.binding[authority], false, authority);
  }
});

test('005 deployment entry fails closed for non-GO, signature, freshness, contract, commit, provider, adapter, rollback, and authority drift', () => {
  const qualification = getDeploymentQualification();
  const noGoBundle = createT056GoNoGoBundle({
    overrides: { CANARY_SAMPLE_SUFFICIENCY: 999 }
  });
  const noGoRecord = evaluateSastProductionGoNoGoEvidence(
    noGoBundle.evaluationInput,
    digest
  );
  assert.ok(noGoRecord);
  assert.equal(noGoRecord.status, 'NO_GO');
  assert.equal(
    buildDeploymentSastQualificationEntryAttestationDraft(
      {
        record: noGoRecord,
        attestedAt: qualification.entryAttestation.attestedAt,
        expiresAt: qualification.entryAttestation.expiresAt
      },
      digest
    ),
    null
  );
  assert.equal(
    buildDeploymentSastQualificationEntryAttestationDraft(
      {
        record: qualification.record,
        attestedAt: '2026-08-20T21:30:01.001Z',
        expiresAt: '2026-08-20T22:00:00.000Z'
      },
      digest
    ),
    null
  );
  assert.equal(
    buildDeploymentSastQualificationEntryAttestation(
      {
        record: qualification.record,
        attestedAt: qualification.entryAttestation.attestedAt,
        expiresAt: qualification.entryAttestation.expiresAt,
        signature: {
          ...qualification.entryAttestation.signature,
          role: 'SECURITY_ENGINEERING'
        }
      },
      digest
    ),
    null
  );

  const invalidSignatureContext = {
    ...qualification.context,
    verifySignature: () => false
  };
  assert.equal(
    isDeploymentSastQualificationEntryAttestationValid(
      qualification.entryAttestation,
      qualification.record,
      invalidSignatureContext
    ),
    false
  );

  const foreignSigning = createSigningContext();
  const foreignSignatureAttestation = buildDeploymentSastQualificationEntryAttestation(
    {
      record: qualification.record,
      attestedAt: qualification.entryAttestation.attestedAt,
      expiresAt: qualification.entryAttestation.expiresAt,
      signature: foreignSigning.sign(
        qualification.entryAttestation.attestationDigest,
        qualification.entryAttestation.attestedAt
      )
    },
    digest
  );
  assert.ok(foreignSignatureAttestation);
  assert.equal(
    isDeploymentSastQualificationEntryAttestationValid(
      foreignSignatureAttestation,
      qualification.record,
      qualification.context
    ),
    false
  );

  const staleContext = {
    ...qualification.context,
    trustedEvaluatedAt: qualification.entryAttestation.expiresAt
  };
  assert.equal(
    isDeploymentSastQualificationBindingValid(
      qualification.binding,
      qualification.evidence,
      staleContext
    ),
    false
  );
  assert.equal(
    isDeploymentSastQualificationEntryAttestationValid(
      qualification.entryAttestation,
      qualification.record,
      {
        ...qualification.context,
        trustedEvaluatedAt: '2026-08-20T20:30:59.999Z'
      }
    ),
    false
  );

  const preflight = createPreflight(qualification);
  for (const sastQualification of [
    {
      ...preflight.sastQualification,
      repositoryCommitSha: digest('detached-repository-commit')
    },
    {
      ...preflight.sastQualification,
      deploymentOperationsContractDigest: digest('detached-deployment-contract')
    },
    {
      ...preflight.sastQualification,
      rollbackTargetRef: ref('rollback', 'detached-qualification-target')
    },
    {
      ...preflight.sastQualification,
      deploymentAuthority: true
    }
  ]) {
    assert.equal(
      isDeploymentOperationPreflightReady(
        { ...preflight, sastQualification },
        qualification.evidence,
        qualification.context
      ),
      false
    );
  }
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        clusterProvisioning: {
          ...preflight.clusterProvisioning,
          provider: ref('provider', 'cross-provider')
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        microVmRollout: {
          ...preflight.microVmRollout,
          providerAdapterRef: ref('provider-adapter', 'detached-adapter')
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        credentialBoundaries: [...preflight.credentialBoundaries].reverse()
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        operatorApprovals: preflight.operatorApprovals.map((item, index) =>
          index === 0 ? { ...item, approvedAt: '2026-08-20T20:29:59.999Z' } : item
        )
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        clusterProvisioning: {
          ...preflight.clusterProvisioning,
          networkBoundaryRefs: Array.from(
            { length: 65 },
            (_, index) => ref('network-boundary', `boundary-${index}`)
          )
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        clusterProvisioning: {
          ...preflight.clusterProvisioning,
          controlPlaneNamespace: 'kube-system'
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        operatorApprovals: preflight.operatorApprovals.map((item, index) =>
          index === 0 ? { ...item, subjectDigest: digest('detached-subject') } : item
        )
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      { ...preflight, providerSecretValue: 'forbidden' },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        clusterProvisioning: {
          ...preflight.clusterProvisioning,
          clusterName: 'a/../../unsafe-cluster'
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        microVmRollout: { ...preflight.microVmRollout, ttlSeconds: 7_201 }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        kmsKeyRef: `kms-key://aegisai/unsafe\n/${digest('unsafe-reference')}`
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationPreflightReady(
      {
        ...preflight,
        kmsKeyRef: `kms-key://aegisai/../unsafe/${digest('unsafe-segment')}`
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );

  const handoff = createHandoff(preflight);
  assert.equal(
    isDeploymentOperationHandoffManifestReady(
      {
        ...handoff,
        executionWindow: {
          ...handoff.executionWindow,
          startsAt: qualification.entryAttestation.expiresAt
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationHandoffManifestReady(
      { ...handoff, rollbackPlanRef: ref('rollback', 'detached') },
      qualification.evidence,
      qualification.context
    ),
    false
  );
  assert.equal(
    isDeploymentOperationHandoffManifestReady(
      {
        ...handoff,
        executionWindow: {
          startsAt: handoff.executionWindow.startsAt,
          endsAt: '2026-08-21T04:35:00.001Z'
        }
      },
      qualification.evidence,
      qualification.context
    ),
    false
  );
});

function getDeploymentQualification() {
  cachedDeploymentQualification ??= createDeploymentQualification();
  return cachedDeploymentQualification;
}

function createDeploymentQualification() {
  const bundle = createT056GoNoGoBundle();
  const record = evaluateSastProductionGoNoGoEvidence(bundle.evaluationInput, digest);
  assert.ok(record);
  assert.equal(record.status, 'GO');

  const attestedAt = '2026-08-20T20:31:00.000Z';
  const expiresAt = '2026-08-20T21:01:00.000Z';
  const trustedEvaluatedAt = '2026-08-20T20:32:00.000Z';
  const draft = buildDeploymentSastQualificationEntryAttestationDraft(
    { record, attestedAt, expiresAt },
    digest
  );
  assert.ok(draft);

  const signing = createSigningContext();
  const signature = signing.sign(draft.attestationDigest, attestedAt);
  const entryAttestation = buildDeploymentSastQualificationEntryAttestation(
    { record, attestedAt, expiresAt, signature },
    digest
  );
  assert.ok(entryAttestation);
  const context = {
    trustedEvaluatedAt,
    verifySignature: signing.verify,
    digestCanonical: digest
  };
  const evidence = { record, entryAttestation };
  const binding = buildDeploymentSastQualificationBinding(evidence, context);
  assert.ok(binding);
  return { record, entryAttestation, context, evidence, binding };
}

function createSigningContext() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const keyDigest = `sha256:${createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')}`;
  const keyId =
    `qualification-key://aegisai/deployment-entry/qualification-authority/${keyDigest}`;
  const sign = (payloadDigest, signedAt) => {
    const unsigned = {
      version: SAST_END_TO_END_QUALIFICATION_SIGNATURE_VERSION,
      role: 'QUALIFICATION_AUTHORITY',
      keyId,
      payloadDigest,
      signedAt,
      algorithm: 'ED25519',
      valueBase64: Buffer.alloc(64).toString('base64')
    };
    const payload = serializeSastEndToEndQualificationSignaturePayload(unsigned);
    assert.ok(payload);
    return {
      ...unsigned,
      valueBase64: signBytes(null, Buffer.from(payload, 'utf8'), privateKey).toString('base64')
    };
  };
  const verify = (signature, payload) =>
    signature.keyId === keyId &&
    verifyBytes(
      null,
      Buffer.from(payload, 'utf8'),
      publicKey,
      Buffer.from(signature.valueBase64, 'base64')
    );
  return { sign, verify };
}

function createPreflight(qualification) {
  const { binding, context } = qualification;
  const approvedAt = '2026-08-20T20:31:30.000Z';
  const validUntil = '2026-08-21T20:31:30.000Z';
  return {
    clusterProvisioning: {
      environment: 'PRODUCTION',
      provider: binding.providerId,
      region: 'ap-northeast-2',
      clusterName: 'aegis-production',
      controlPlaneNamespace: 'aegis-control',
      scanPlaneNamespace: 'aegis-scan',
      aiPlaneNamespace: 'aegis-ai',
      dataSecurityNamespace: 'aegis-data-security',
      networkBoundaryRefs: [
        ref('network-boundary', 'control'),
        ref('network-boundary', 'scan'),
        ref('network-boundary', 'ai'),
        ref('network-boundary', 'data-security')
      ],
      auditSinkRef: ref('audit-sink', 'production')
    },
    microVmRollout: {
      provider: binding.providerId,
      providerAdapterRef: binding.providerAdapterRef,
      region: 'ap-northeast-2',
      platformName: 'aegis-microvm',
      isolationClass: 'RESTRICTED',
      scannerSandboxProfileRef: ref('sandbox-profile', 'restricted'),
      tokenBrokerRef: ref('token-broker', 'production'),
      evidenceStorageRef: ref('evidence-storage', 'production'),
      egressPolicyRef: ref('egress-policy', 'default-deny'),
      ttlSeconds: 3_600,
      forbiddenScannerCapabilities: [...SCANNER_SANDBOX_FORBIDDEN_CAPABILITIES]
    },
    credentialBoundaries: DEPLOYMENT_CREDENTIAL_SCOPES.map((credentialScope) => ({
      credentialProvider: ref(
        'credential-provider',
        credentialScope.toLowerCase()
      ),
      credentialScope,
      allowedUse: 'EXPLICIT_DEPLOYMENT_OPERATION',
      localDevelopmentDefault: false,
      repositoryPersisted: false,
      rotationRequired: true,
      auditRequired: true
    })),
    sastQualification: binding,
    auditSignal: {
      environment: 'PRODUCTION',
      provider: binding.providerId,
      operationId: ref('deployment-operation', 'preflight'),
      actor: 'DEPLOYMENT_OPERATOR',
      targetType: 'SAST_QUALIFICATION_BINDING',
      targetId: binding.bindingId,
      eventType: 'DEPLOYMENT_PREFLIGHT_VERIFIED',
      occurredAt: context.trustedEvaluatedAt
    },
    operatorApprovals: DEPLOYMENT_PREFLIGHT_REQUIRED_APPROVALS.map((approval) => ({
      approval,
      approvalRef: ref('deployment-approval', approval.toLowerCase()),
      subjectDigest: binding.bindingDigest,
      approvedAt,
      validUntil
    })),
    kmsKeyRef: ref('kms-key', 'production'),
    secretManagerRef: ref('secret-manager', 'production'),
    objectStorageRef: ref('object-storage', 'production'),
    dnsZoneRef: ref('dns-zone', 'production')
  };
}

function createHandoff(preflight) {
  return {
    preflight,
    credentialHandoffMode: 'EPHEMERAL_OIDC_FEDERATION',
    executionWindow: {
      startsAt: '2026-08-20T20:35:00.000Z',
      endsAt: '2026-08-20T23:35:00.000Z'
    },
    rollbackPlanRef: preflight.sastQualification.rollbackTargetRef,
    incidentChannelRef: ref('incident-channel', 'production-deployment'),
    dryRunEvidenceRef: ref('dry-run-evidence', 'production-deployment'),
    changeTicketRef: ref('change-ticket', 'production-deployment')
  };
}

function ref(namespace, seed) {
  return `${namespace}://aegisai/${seed}/${digest(`${namespace}:${seed}`)}`;
}
