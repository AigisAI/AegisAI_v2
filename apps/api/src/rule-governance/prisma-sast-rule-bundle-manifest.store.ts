import {
  canonicalizeSastRuleBundleCompatibilityReceipt,
  canonicalizeSastRuleBundleManifest,
  canonicalizeSastRuleBundleSupplyChainAttestation,
  isAttestationBoundToManifest,
  isSastRuleBundleCompatibilityReceiptShapeValid,
  isSastRuleBundleManifestShapeValid,
  isSastRuleBundleSupplyChainAttestationShapeValid,
  type SastRuleBundleCompatibilityMatrix,
  type SastRuleBundleCompatibilityReceipt,
  type SastRuleBundleManifest,
  type SastRuleBundleSupplyChainAttestation
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import {
  SastRuleBundleManifestPersistenceError,
  SastRuleBundleManifestStore,
  type PersistedSastRuleBundleCompatibilityReceipt,
  type PersistedVerifiedSastRuleBundle
} from './sast-rule-bundle-manifest.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 10_000;

const MANIFEST_INCLUDE = {
  members: { orderBy: { position: 'asc' as const } },
  rules: { orderBy: { position: 'asc' as const } },
  compatibilityEntries: {
    orderBy: [{ kind: 'asc' as const }, { position: 'asc' as const }]
  },
  supplyChainAttestation: true
} satisfies Prisma.SastRuleBundleManifestInclude;

type ManifestRow = Prisma.SastRuleBundleManifestGetPayload<{
  include: typeof MANIFEST_INCLUDE;
}>;

type CompatibilityEntryKind =
  | 'SCANNER_VERSION'
  | 'SCANNER_IMAGE_DIGEST'
  | 'WRAPPER_DIGEST'
  | 'SCHEMA_BUNDLE_DIGEST'
  | 'NORMALIZER_BUNDLE_DIGEST'
  | 'PROFILE_ID';

@Injectable()
export class PrismaSastRuleBundleManifestStore extends SastRuleBundleManifestStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async registerVerified(input: {
    manifest: Readonly<SastRuleBundleManifest>;
    attestation: Readonly<SastRuleBundleSupplyChainAttestation>;
  }): Promise<PersistedVerifiedSastRuleBundle> {
    if (
      !isSastRuleBundleManifestShapeValid(
        input.manifest,
        digestSastRuleBundleCanonical
      ) ||
      !isSastRuleBundleSupplyChainAttestationShapeValid(
        input.attestation,
        digestSastRuleBundleCanonical
      ) ||
      !isAttestationBoundToManifest(input.attestation, input.manifest)
    ) {
      throw new SastRuleBundleManifestPersistenceError('INPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        const existing = await tx.sastRuleBundleManifest.findUnique({
          where: { id: input.manifest.manifestId },
          include: MANIFEST_INCLUDE
        });
        if (existing) return replayVerified(existing, input);

        const created = await tx.sastRuleBundleManifest.create({
          data: manifestData(input.manifest, input.attestation),
          include: MANIFEST_INCLUDE
        });
        return replayVerified(created, input, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      return this.runSerializable(async (tx) => {
        const existing = await tx.sastRuleBundleManifest.findUnique({
          where: { id: input.manifest.manifestId },
          include: MANIFEST_INCLUDE
        });
        if (!existing) {
          throw new SastRuleBundleManifestPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayVerified(existing, input);
      });
    }
  }

  async findVerified(
    manifestId: string
  ): Promise<PersistedVerifiedSastRuleBundle | null> {
    const row = await this.prisma.sastRuleBundleManifest.findUnique({
      where: { id: manifestId },
      include: MANIFEST_INCLUDE
    });
    if (!row) return null;
    return verifiedFromRow(row);
  }

  async recordCompatibilityReceipt(
    receipt: Readonly<SastRuleBundleCompatibilityReceipt>
  ): Promise<PersistedSastRuleBundleCompatibilityReceipt> {
    if (
      !isSastRuleBundleCompatibilityReceiptShapeValid(
        receipt,
        digestSastRuleBundleCanonical
      )
    ) {
      throw new SastRuleBundleManifestPersistenceError('INPUT_INVALID');
    }

    try {
      return await this.runSerializable(async (tx) => {
        const verified = await tx.sastRuleBundleManifest.findUnique({
          where: { id: receipt.manifestId },
          include: MANIFEST_INCLUDE
        });
        if (!verified) {
          throw new SastRuleBundleManifestPersistenceError(
            'MANIFEST_NOT_FOUND'
          );
        }
        const durable = verifiedFromRow(verified);
        if (!isReceiptBoundToVerified(receipt, durable)) {
          throw new SastRuleBundleManifestPersistenceError(
            'REPLAY_CONFLICT'
          );
        }

        const existing =
          await tx.sastRuleBundleCompatibilityReceipt.findUnique({
            where: { id: receipt.receiptId }
          });
        if (existing) return replayReceipt(existing, receipt);

        const created =
          await tx.sastRuleBundleCompatibilityReceipt.create({
            data: receiptData(receipt)
          });
        return replayReceipt(created, receipt, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      return this.runSerializable(async (tx) => {
        const existing =
          await tx.sastRuleBundleCompatibilityReceipt.findUnique({
            where: { id: receipt.receiptId }
          });
        if (!existing) {
          throw new SastRuleBundleManifestPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayReceipt(existing, receipt);
      });
    }
  }

  private async runSerializable<T>(
    operation: (tx: Prisma.TransactionClient) => Promise<T>
  ): Promise<T> {
    for (let attempt = 1; attempt <= SERIALIZABLE_RETRIES; attempt += 1) {
      try {
        return await this.prisma.$transaction(operation, {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          maxWait: SERIALIZABLE_TIMEOUT_MILLISECONDS,
          timeout: SERIALIZABLE_TIMEOUT_MILLISECONDS
        });
      } catch (error) {
        if (
          !isSerializableConflict(error) ||
          attempt === SERIALIZABLE_RETRIES
        ) {
          throw error;
        }
        await new Promise((resolve) =>
          setTimeout(
            resolve,
            20 * attempt + Math.floor(Math.random() * 20)
          )
        );
      }
    }
    throw new SastRuleBundleManifestPersistenceError('REPLAY_CONFLICT');
  }
}

function manifestData(
  manifest: Readonly<SastRuleBundleManifest>,
  attestation: Readonly<SastRuleBundleSupplyChainAttestation>
): Prisma.SastRuleBundleManifestCreateInput {
  return {
    id: manifest.manifestId,
    manifestDigest: manifest.manifestDigest,
    contractVersion: manifest.version,
    bundleId: manifest.bundleId,
    bundleVersion: manifest.bundleVersion,
    lifecycleState: manifest.lifecycleState,
    scanner: manifest.scanner,
    builtAt: new Date(manifest.builtAt),
    sourceRevision: manifest.sourceRevision,
    bundleDigest: manifest.bundleDigest,
    memberCount: manifest.members.length,
    memberSetDigest: manifest.memberSetDigest,
    ruleCount: manifest.rules.length,
    ruleSetDigest: manifest.ruleSetDigest,
    scannerVersionCount: manifest.compatibility.scannerVersions.length,
    scannerImageDigestCount:
      manifest.compatibility.scannerImageDigests.length,
    wrapperDigestCount: manifest.compatibility.wrapperDigests.length,
    schemaBundleDigestCount:
      manifest.compatibility.schemaBundleDigests.length,
    normalizerBundleDigestCount:
      manifest.compatibility.normalizerBundleDigests.length,
    profileIdCount: manifest.compatibility.profileIds.length,
    compatibilityDigest: manifest.compatibilityDigest,
    goldenCorpusResultRef:
      manifest.qualityEvidence.goldenCorpusResultRef,
    regressionCorpusResultRef:
      manifest.qualityEvidence.regressionCorpusResultRef,
    maliciousCorpusResultRef:
      manifest.qualityEvidence.maliciousCorpusResultRef,
    performanceCorpusResultRef:
      manifest.qualityEvidence.performanceCorpusResultRef,
    qualityEvidenceDigest: manifest.qualityEvidenceDigest,
    signerIdentity: manifest.signerIdentity,
    signatureRef: manifest.signatureRef,
    provenanceRef: manifest.provenanceRef,
    compatibilityRef: manifest.compatibilityRef,
    rolloutPolicyRef: manifest.rolloutPolicyRef,
    killSwitchNamespace: manifest.killSwitchNamespace,
    killSwitchRef: manifest.killSwitchRef,
    rollbackTargetDigest: manifest.rollbackTargetDigest,
    source: manifest.source,
    immutable: manifest.immutable,
    customerExecutableConfigAllowed:
      manifest.customerExecutableConfigAllowed,
    executableRuleContentStored: false,
    customerSourceStored: false,
    secretValueStored: false,
    members: {
      create: manifest.members.map((member, position) => ({
        position,
        memberId: member.memberId,
        digest: member.digest
      }))
    },
    rules: {
      create: manifest.rules.map((rule, position) => ({
        position,
        ruleId: rule.ruleId,
        ruleRevision: rule.ruleRevision,
        ruleSemanticId: rule.ruleSemanticId,
        metadataDigest: rule.metadataDigest
      }))
    },
    compatibilityEntries: {
      create: compatibilityData(manifest.compatibility)
    },
    supplyChainAttestation: {
      create: {
        id: attestation.verificationId,
        contractVersion: attestation.version,
        manifestDigest: attestation.manifestDigest,
        bundleDigest: attestation.bundleDigest,
        memberSetDigest: attestation.memberSetDigest,
        signerIdentity: attestation.signerIdentity,
        signatureRef: attestation.signatureRef,
        provenanceRef: attestation.provenanceRef,
        signatureVerified: attestation.signatureVerified,
        provenanceVerified: attestation.provenanceVerified,
        trustedSigner: attestation.trustedSigner,
        subjectDigestsVerified: attestation.subjectDigestsVerified,
        signatureBytesStored: attestation.signatureBytesStored,
        provenancePayloadStored: attestation.provenancePayloadStored,
        executableRuleContentStored:
          attestation.executableRuleContentStored,
        verifiedAt: new Date(attestation.verifiedAt),
        attestationDigest: attestation.attestationDigest
      }
    }
  };
}

function compatibilityData(
  compatibility: Readonly<SastRuleBundleCompatibilityMatrix>
): Array<{ kind: CompatibilityEntryKind; position: number; value: string }> {
  return [
    ...entries('SCANNER_VERSION', compatibility.scannerVersions),
    ...entries(
      'SCANNER_IMAGE_DIGEST',
      compatibility.scannerImageDigests
    ),
    ...entries('WRAPPER_DIGEST', compatibility.wrapperDigests),
    ...entries(
      'SCHEMA_BUNDLE_DIGEST',
      compatibility.schemaBundleDigests
    ),
    ...entries(
      'NORMALIZER_BUNDLE_DIGEST',
      compatibility.normalizerBundleDigests
    ),
    ...entries('PROFILE_ID', compatibility.profileIds)
  ];
}

function entries(
  kind: CompatibilityEntryKind,
  values: readonly string[]
): Array<{ kind: CompatibilityEntryKind; position: number; value: string }> {
  return values.map((value, position) => ({ kind, position, value }));
}

function receiptData(
  receipt: Readonly<SastRuleBundleCompatibilityReceipt>
): Prisma.SastRuleBundleCompatibilityReceiptUncheckedCreateInput {
  return {
    id: receipt.receiptId,
    contractVersion: receipt.version,
    manifestId: receipt.manifestId,
    manifestDigest: receipt.manifestDigest,
    verificationId: receipt.verificationId,
    verificationDigest: receipt.verificationDigest,
    bundleDigest: receipt.bundleDigest,
    scannerSetDigest: receipt.context.scannerSetDigest,
    profileId: receipt.context.profileId,
    profileDigest: receipt.context.profileDigest,
    scanner: receipt.context.scanner,
    scannerVersion: receipt.context.scannerVersion,
    scannerImageDigest: receipt.context.scannerImageDigest,
    wrapperDigest: receipt.context.wrapperDigest,
    schemaBundleDigest: receipt.context.schemaBundleDigest,
    normalizerBundleDigest: receipt.context.normalizerBundleDigest,
    compatible: receipt.compatible,
    manifestProjectionMatched: receipt.manifestProjectionMatched,
    signatureVerified: receipt.signatureVerified,
    provenanceVerified: receipt.provenanceVerified,
    trustedSigner: receipt.trustedSigner,
    customerInputAccepted: receipt.customerInputAccepted,
    executableRuleContentStored: receipt.executableRuleContentStored,
    evaluatedAt: new Date(receipt.evaluatedAt),
    receiptDigest: receipt.receiptDigest
  };
}

function replayVerified(
  row: ManifestRow,
  expected: {
    manifest: Readonly<SastRuleBundleManifest>;
    attestation: Readonly<SastRuleBundleSupplyChainAttestation>;
  },
  replayed = true
): PersistedVerifiedSastRuleBundle {
  const persisted = verifiedFromRow(row, replayed);
  if (
    canonicalizeSastRuleBundleManifest(persisted.manifest) !==
      canonicalizeSastRuleBundleManifest(expected.manifest) ||
    canonicalizeSastRuleBundleSupplyChainAttestation(
      persisted.attestation
    ) !==
      canonicalizeSastRuleBundleSupplyChainAttestation(
        expected.attestation
      )
  ) {
    throw new SastRuleBundleManifestPersistenceError('REPLAY_CONFLICT');
  }
  return persisted;
}

function isReceiptBoundToVerified(
  receipt: Readonly<SastRuleBundleCompatibilityReceipt>,
  verified: Readonly<PersistedVerifiedSastRuleBundle>
): boolean {
  return (
    verified.manifest.manifestId === receipt.manifestId &&
    verified.manifest.manifestDigest === receipt.manifestDigest &&
    verified.manifest.bundleDigest === receipt.bundleDigest &&
    verified.attestation.verificationId === receipt.verificationId &&
    verified.attestation.attestationDigest ===
      receipt.verificationDigest &&
    Date.parse(receipt.evaluatedAt) >=
      Date.parse(verified.attestation.verifiedAt)
  );
}

function verifiedFromRow(
  row: ManifestRow,
  replayed = true
): PersistedVerifiedSastRuleBundle {
  const attestationRow = row.supplyChainAttestation;
  if (!attestationRow) {
    throw new SastRuleBundleManifestPersistenceError('LEDGER_CORRUPT');
  }
  const compatibility = compatibilityFromRows(row);
  if (!compatibility) {
    throw new SastRuleBundleManifestPersistenceError('LEDGER_CORRUPT');
  }
  const manifest: SastRuleBundleManifest = {
    version: row.contractVersion as SastRuleBundleManifest['version'],
    manifestId: row.id,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    bundleId: row.bundleId,
    bundleVersion: row.bundleVersion,
    lifecycleState:
      row.lifecycleState as SastRuleBundleManifest['lifecycleState'],
    scanner: row.scanner as SastRuleBundleManifest['scanner'],
    builtAt: row.builtAt.toISOString(),
    sourceRevision: row.sourceRevision,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    members: row.members.map((member) => ({
      memberId: member.memberId,
      digest: member.digest as `sha256:${string}`
    })),
    memberSetDigest: row.memberSetDigest as `sha256:${string}`,
    rules: row.rules.map((rule) => ({
      ruleId: rule.ruleId,
      ruleRevision: rule.ruleRevision,
      ruleSemanticId: rule.ruleSemanticId,
      metadataDigest: rule.metadataDigest as `sha256:${string}`
    })),
    ruleSetDigest: row.ruleSetDigest as `sha256:${string}`,
    compatibility,
    compatibilityDigest: row.compatibilityDigest as `sha256:${string}`,
    qualityEvidence: {
      goldenCorpusResultRef: row.goldenCorpusResultRef,
      regressionCorpusResultRef: row.regressionCorpusResultRef,
      maliciousCorpusResultRef: row.maliciousCorpusResultRef,
      performanceCorpusResultRef: row.performanceCorpusResultRef
    },
    qualityEvidenceDigest: row.qualityEvidenceDigest as `sha256:${string}`,
    signerIdentity: row.signerIdentity,
    signatureRef: row.signatureRef,
    provenanceRef: row.provenanceRef,
    compatibilityRef: row.compatibilityRef,
    rolloutPolicyRef: row.rolloutPolicyRef,
    killSwitchNamespace: row.killSwitchNamespace,
    killSwitchRef: row.killSwitchRef,
    rollbackTargetDigest: row.rollbackTargetDigest as `sha256:${string}`,
    source: row.source as 'PLATFORM_MANAGED',
    immutable: row.immutable as true,
    customerExecutableConfigAllowed:
      row.customerExecutableConfigAllowed as false
  };
  const attestation: SastRuleBundleSupplyChainAttestation = {
    version:
      attestationRow.contractVersion as SastRuleBundleSupplyChainAttestation['version'],
    verificationId: attestationRow.id,
    manifestId: attestationRow.manifestId,
    manifestDigest: attestationRow.manifestDigest as `sha256:${string}`,
    bundleDigest: attestationRow.bundleDigest as `sha256:${string}`,
    memberSetDigest:
      attestationRow.memberSetDigest as `sha256:${string}`,
    signerIdentity: attestationRow.signerIdentity,
    signatureRef: attestationRow.signatureRef,
    provenanceRef: attestationRow.provenanceRef,
    signatureVerified: attestationRow.signatureVerified as true,
    provenanceVerified: attestationRow.provenanceVerified as true,
    trustedSigner: attestationRow.trustedSigner as true,
    subjectDigestsVerified: attestationRow.subjectDigestsVerified as true,
    signatureBytesStored: attestationRow.signatureBytesStored as false,
    provenancePayloadStored:
      attestationRow.provenancePayloadStored as false,
    executableRuleContentStored:
      attestationRow.executableRuleContentStored as false,
    verifiedAt: attestationRow.verifiedAt.toISOString(),
    attestationDigest:
      attestationRow.attestationDigest as `sha256:${string}`
  };
  if (
    row.memberCount !== manifest.members.length ||
    row.ruleCount !== manifest.rules.length ||
    row.members.some((member, position) => member.position !== position) ||
    row.rules.some((rule, position) => rule.position !== position) ||
    !isSastRuleBundleManifestShapeValid(
      manifest,
      digestSastRuleBundleCanonical
    ) ||
    !isSastRuleBundleSupplyChainAttestationShapeValid(
      attestation,
      digestSastRuleBundleCanonical
    ) ||
    !isAttestationBoundToManifest(attestation, manifest) ||
    Date.parse(attestation.verifiedAt) < Date.parse(manifest.builtAt) ||
    row.executableRuleContentStored !== false ||
    row.customerSourceStored !== false ||
    row.secretValueStored !== false
  ) {
    throw new SastRuleBundleManifestPersistenceError('LEDGER_CORRUPT');
  }
  return { manifest, attestation, replayed };
}

function compatibilityFromRows(
  row: ManifestRow
): SastRuleBundleCompatibilityMatrix | null {
  const expectedEntryCount =
    row.scannerVersionCount +
    row.scannerImageDigestCount +
    row.wrapperDigestCount +
    row.schemaBundleDigestCount +
    row.normalizerBundleDigestCount +
    row.profileIdCount;
  if (row.compatibilityEntries.length !== expectedEntryCount) {
    return null;
  }
  const scannerVersions = valuesFor(
    row,
    'SCANNER_VERSION',
    row.scannerVersionCount
  );
  const scannerImageDigests = valuesFor(
    row,
    'SCANNER_IMAGE_DIGEST',
    row.scannerImageDigestCount
  );
  const wrapperDigests = valuesFor(
    row,
    'WRAPPER_DIGEST',
    row.wrapperDigestCount
  );
  const schemaBundleDigests = valuesFor(
    row,
    'SCHEMA_BUNDLE_DIGEST',
    row.schemaBundleDigestCount
  );
  const normalizerBundleDigests = valuesFor(
    row,
    'NORMALIZER_BUNDLE_DIGEST',
    row.normalizerBundleDigestCount
  );
  const profileIds = valuesFor(row, 'PROFILE_ID', row.profileIdCount);
  if (
    !scannerVersions ||
    !scannerImageDigests ||
    !wrapperDigests ||
    !schemaBundleDigests ||
    !normalizerBundleDigests ||
    !profileIds
  ) {
    return null;
  }
  return {
    scannerVersions,
    scannerImageDigests: scannerImageDigests as `sha256:${string}`[],
    wrapperDigests: wrapperDigests as `sha256:${string}`[],
    schemaBundleDigests: schemaBundleDigests as `sha256:${string}`[],
    normalizerBundleDigests:
      normalizerBundleDigests as `sha256:${string}`[],
    profileIds: profileIds as SastRuleBundleCompatibilityMatrix['profileIds']
  };
}

function valuesFor(
  row: ManifestRow,
  kind: CompatibilityEntryKind,
  expectedCount: number
): string[] | null {
  const entries = row.compatibilityEntries.filter(
    (entry) => entry.kind === kind
  );
  if (
    entries.length !== expectedCount ||
    entries.some((entry, position) => entry.position !== position)
  ) {
    return null;
  }
  return entries.map((entry) => entry.value);
}

type ReceiptRow = Prisma.SastRuleBundleCompatibilityReceiptGetPayload<object>;

function replayReceipt(
  row: ReceiptRow,
  expected: Readonly<SastRuleBundleCompatibilityReceipt>,
  replayed = true
): PersistedSastRuleBundleCompatibilityReceipt {
  const receipt = receiptFromRow(row);
  const replayCandidate: SastRuleBundleCompatibilityReceipt = {
    ...expected,
    evaluatedAt: receipt.evaluatedAt,
    receiptDigest: receipt.receiptDigest
  };
  if (
    canonicalizeSastRuleBundleCompatibilityReceipt(receipt) !==
      canonicalizeSastRuleBundleCompatibilityReceipt(replayCandidate) ||
    Date.parse(expected.evaluatedAt) < Date.parse(receipt.evaluatedAt)
  ) {
    throw new SastRuleBundleManifestPersistenceError('REPLAY_CONFLICT');
  }
  return { receipt, replayed };
}

function receiptFromRow(
  row: ReceiptRow
): SastRuleBundleCompatibilityReceipt {
  const receipt: SastRuleBundleCompatibilityReceipt = {
    version:
      row.contractVersion as SastRuleBundleCompatibilityReceipt['version'],
    receiptId: row.id,
    manifestId: row.manifestId,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    verificationId: row.verificationId,
    verificationDigest: row.verificationDigest as `sha256:${string}`,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    context: {
      scannerSetDigest: row.scannerSetDigest as `sha256:${string}`,
      profileId:
        row.profileId as SastRuleBundleCompatibilityReceipt['context']['profileId'],
      profileDigest: row.profileDigest as `sha256:${string}`,
      scanner:
        row.scanner as SastRuleBundleCompatibilityReceipt['context']['scanner'],
      scannerVersion: row.scannerVersion,
      scannerImageDigest: row.scannerImageDigest as `sha256:${string}`,
      wrapperDigest: row.wrapperDigest as `sha256:${string}`,
      schemaBundleDigest: row.schemaBundleDigest as `sha256:${string}`,
      normalizerBundleDigest:
        row.normalizerBundleDigest as `sha256:${string}`
    },
    compatible: row.compatible as true,
    reasonCodes: [],
    manifestProjectionMatched: row.manifestProjectionMatched as true,
    signatureVerified: row.signatureVerified as true,
    provenanceVerified: row.provenanceVerified as true,
    trustedSigner: row.trustedSigner as true,
    customerInputAccepted: row.customerInputAccepted as false,
    executableRuleContentStored: row.executableRuleContentStored as false,
    evaluatedAt: row.evaluatedAt.toISOString(),
    receiptDigest: row.receiptDigest as `sha256:${string}`
  };
  if (
    !isSastRuleBundleCompatibilityReceiptShapeValid(
      receipt,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleBundleManifestPersistenceError('LEDGER_CORRUPT');
  }
  return receipt;
}

function isSerializableConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2034'
  );
}

function isUniqueConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002'
  );
}
