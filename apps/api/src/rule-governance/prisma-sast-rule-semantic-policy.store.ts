import {
  canonicalizeSastRuleDefinitionMetadata,
  canonicalizeSastRuleDefinitionMetadataBinding,
  canonicalizeSastTenantRulePolicy,
  canonicalizeSastTenantRulePolicyResolutionReceipt,
  isSastRuleDefinitionMetadataShapeValid,
  isSastRuleDefinitionMetadataBindingShapeValid,
  isSastTenantRulePolicyResolutionReceiptShapeValid,
  isSastTenantRulePolicyShapeValid,
  type SastRuleDefinitionMetadata,
  type SastRuleDefinitionMetadataBinding,
  type SastRuleSemanticIdentity,
  type SastTenantRulePolicy,
  type SastTenantRulePolicyResolutionReceipt
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

import { PrismaService } from '../prisma/prisma.service';
import { digestSastRuleBundleCanonical } from './sast-rule-bundle-canonical';
import {
  SastRuleSemanticPolicyPersistenceError,
  SastRuleSemanticPolicyStore,
  type PersistedSastRuleDefinitionMetadataBinding,
  type PersistedSastTenantRulePolicy,
  type PersistedSastTenantRulePolicyResolution,
  type SastApprovedRulePolicyTargets
} from './sast-rule-semantic-policy.store';

const SERIALIZABLE_RETRIES = 3;
const SERIALIZABLE_TIMEOUT_MILLISECONDS = 10_000;

const METADATA_INCLUDE = {
  semanticIdentity: {
    include: {
      values: {
        orderBy: [{ kind: 'asc' as const }, { position: 'asc' as const }]
      }
    }
  },
  values: {
    orderBy: [{ kind: 'asc' as const }, { position: 'asc' as const }]
  }
} satisfies Prisma.SastRuleDefinitionMetadataInclude;

const METADATA_BINDING_INCLUDE = {
  metadata: { include: METADATA_INCLUDE }
} satisfies Prisma.SastRuleDefinitionMetadataBindingInclude;

const POLICY_INCLUDE = {
  decisions: {
    orderBy: [{ kind: 'asc' as const }, { position: 'asc' as const }]
  },
  pathExclusions: { orderBy: { position: 'asc' as const } },
  repositoryOverrides: {
    orderBy: { position: 'asc' as const },
    include: {
      decisions: {
        orderBy: [
          { kind: 'asc' as const },
          { position: 'asc' as const }
        ]
      },
      pathExclusions: { orderBy: { position: 'asc' as const } }
    }
  },
  waiverReferences: { orderBy: { position: 'asc' as const } },
  suppressionReferences: { orderBy: { position: 'asc' as const } }
} satisfies Prisma.SastTenantRulePolicyInclude;

const RESOLUTION_INCLUDE = {
  rules: { orderBy: { position: 'asc' as const } },
  pathExclusions: { orderBy: { position: 'asc' as const } }
} satisfies Prisma.SastTenantRulePolicyResolutionInclude;

type MetadataRow = Prisma.SastRuleDefinitionMetadataGetPayload<{
  include: typeof METADATA_INCLUDE;
}>;
type MetadataBindingRow =
  Prisma.SastRuleDefinitionMetadataBindingGetPayload<{
    include: typeof METADATA_BINDING_INCLUDE;
  }>;
type PolicyRow = Prisma.SastTenantRulePolicyGetPayload<{
  include: typeof POLICY_INCLUDE;
}>;
type ResolutionRow = Prisma.SastTenantRulePolicyResolutionGetPayload<{
  include: typeof RESOLUTION_INCLUDE;
}>;

type IdentityValueKind =
  | 'LANGUAGE'
  | 'FORMAT'
  | 'SOURCE_KIND'
  | 'SINK_KIND';
type MetadataValueKind = 'CWE' | 'OWASP' | 'FIXTURE';
type PolicyDecisionKind = 'CATEGORY' | 'RULE';

@Injectable()
export class PrismaSastRuleSemanticPolicyStore extends SastRuleSemanticPolicyStore {
  constructor(private readonly prisma: PrismaService) {
    super();
  }

  async registerRuleMetadataBinding(
    binding: Readonly<SastRuleDefinitionMetadataBinding>
  ): Promise<PersistedSastRuleDefinitionMetadataBinding> {
    assertMetadataBindingValid(binding);
    const metadata = binding.metadata;
    try {
      return await this.runSerializable(async (tx) => {
        await ensureSemanticIdentity(tx, metadata.semanticIdentity);
        await assertReplacementSafe(tx, metadata);
        const existingMetadata =
          await tx.sastRuleDefinitionMetadata.findUnique({
            where: { id: metadata.metadataId },
            include: METADATA_INCLUDE
          });
        if (existingMetadata) {
          replayMetadata(existingMetadata, metadata);
        } else {
          await tx.sastRuleDefinitionMetadata.create({
            data: metadataData(metadata)
          });
          const values = metadataValues(metadata);
          if (values.length > 0) {
            await tx.sastRuleDefinitionMetadataValue.createMany({
              data: values
            });
          }
        }
        const existingBinding =
          await tx.sastRuleDefinitionMetadataBinding.findFirst({
            where: {
              OR: [
                { id: binding.bindingId },
                { bindingDigest: binding.bindingDigest },
                {
                  manifestId: binding.manifestId,
                  ruleId: binding.ruleId
                }
              ]
            },
            include: METADATA_BINDING_INCLUDE
          });
        if (existingBinding) {
          return replayMetadataBinding(existingBinding, binding);
        }
        await tx.sastRuleDefinitionMetadataBinding.create({
          data: metadataBindingData(binding)
        });
        const created =
          await tx.sastRuleDefinitionMetadataBinding.findUnique({
            where: { id: binding.bindingId },
            include: METADATA_BINDING_INCLUDE
          });
        if (!created) {
          throw new SastRuleSemanticPolicyPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayMetadataBinding(created, binding, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      return this.runSerializable(async (tx) => {
        const existing =
          await tx.sastRuleDefinitionMetadataBinding.findFirst({
            where: {
              OR: [
                { id: binding.bindingId },
                { bindingDigest: binding.bindingDigest },
                {
                  manifestId: binding.manifestId,
                  ruleId: binding.ruleId
                }
              ]
            },
            include: METADATA_BINDING_INCLUDE
          });
        if (!existing) {
          throw new SastRuleSemanticPolicyPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayMetadataBinding(existing, binding);
      });
    }
  }

  async findRuleMetadataBindingsForManifests(
    manifestIds: readonly string[]
  ): Promise<SastRuleDefinitionMetadataBinding[]> {
    if (
      !Array.isArray(manifestIds) ||
      manifestIds.length === 0 ||
      manifestIds.some(
        (value, index) =>
          typeof value !== 'string' ||
          value.length === 0 ||
          (index > 0 && manifestIds[index - 1]! >= value)
      )
    ) {
      throw new SastRuleSemanticPolicyPersistenceError('INPUT_INVALID');
    }
    const rows =
      await this.prisma.sastRuleDefinitionMetadataBinding.findMany({
        where: { manifestId: { in: [...manifestIds] } },
        orderBy: [{ manifestId: 'asc' }, { ruleId: 'asc' }],
        include: METADATA_BINDING_INCLUDE
      });
    return rows.map((row) => metadataBindingFromRow(row));
  }

  async findApprovedPolicyTargets(): Promise<SastApprovedRulePolicyTargets> {
    const rows = await this.prisma.sastRuleSemanticIdentity.findMany({
      select: { semanticRuleId: true, category: true },
      orderBy: { semanticRuleId: 'asc' }
    });
    return {
      semanticRuleIds: rows.map((row) => row.semanticRuleId),
      categories: [...new Set(rows.map((row) => row.category))].sort(
        compareStrings
      )
    };
  }

  async registerTenantPolicy(
    policy: Readonly<SastTenantRulePolicy>
  ): Promise<PersistedSastTenantRulePolicy> {
    assertPolicyValid(policy);
    try {
      return await this.runSerializable(async (tx) => {
        await assertPolicyReferences(tx, policy);
        const existing = await tx.sastTenantRulePolicy.findFirst({
          where: {
            OR: [
              { id: policy.policyId },
              {
                tenantId: policy.tenantId,
                policyVersion: policy.policyVersion
              }
            ]
          },
          include: POLICY_INCLUDE
        });
        if (existing) return replayPolicy(existing, policy);

        await tx.sastTenantRulePolicy.create({ data: policyData(policy) });
        await createPolicyChildren(tx, policy);
        const created = await tx.sastTenantRulePolicy.findUnique({
          where: { id: policy.policyId },
          include: POLICY_INCLUDE
        });
        if (!created) {
          throw new SastRuleSemanticPolicyPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayPolicy(created, policy, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      return this.runSerializable(async (tx) => {
        const existing = await tx.sastTenantRulePolicy.findFirst({
          where: {
            OR: [
              { id: policy.policyId },
              {
                tenantId: policy.tenantId,
                policyVersion: policy.policyVersion
              }
            ]
          },
          include: POLICY_INCLUDE
        });
        if (!existing) {
          throw new SastRuleSemanticPolicyPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayPolicy(existing, policy);
      });
    }
  }

  async findTenantPolicy(
    tenantId: string,
    policyVersion: string
  ): Promise<PersistedSastTenantRulePolicy | null> {
    const row = await this.prisma.sastTenantRulePolicy.findUnique({
      where: {
        tenantId_policyVersion: { tenantId, policyVersion }
      },
      include: POLICY_INCLUDE
    });
    return row ? { policy: policyFromRow(row), replayed: true } : null;
  }

  async recordPolicyResolution(
    receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
  ): Promise<PersistedSastTenantRulePolicyResolution> {
    assertResolutionValid(receipt);
    try {
      return await this.runSerializable(async (tx) => {
        await assertResolutionBindings(tx, receipt);
        const existing =
          await tx.sastTenantRulePolicyResolution.findUnique({
            where: { id: receipt.receiptId },
            include: RESOLUTION_INCLUDE
          });
        if (existing) return replayResolution(existing, receipt);

        await tx.sastTenantRulePolicyResolution.create({
          data: resolutionData(receipt)
        });
        await createResolutionChildren(tx, receipt);
        const created =
          await tx.sastTenantRulePolicyResolution.findUnique({
            where: { id: receipt.receiptId },
            include: RESOLUTION_INCLUDE
          });
        if (!created) {
          throw new SastRuleSemanticPolicyPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayResolution(created, receipt, false);
      });
    } catch (error) {
      if (!isUniqueConflict(error)) throw error;
      return this.runSerializable(async (tx) => {
        const existing =
          await tx.sastTenantRulePolicyResolution.findUnique({
            where: { id: receipt.receiptId },
            include: RESOLUTION_INCLUDE
          });
        if (!existing) {
          throw new SastRuleSemanticPolicyPersistenceError(
            'REPLAY_CONFLICT'
          );
        }
        return replayResolution(existing, receipt);
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
          setTimeout(resolve, 20 * attempt + Math.floor(Math.random() * 20))
        );
      }
    }
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
}

async function ensureSemanticIdentity(
  tx: Prisma.TransactionClient,
  identity: Readonly<SastRuleSemanticIdentity>
): Promise<void> {
  const existing = await tx.sastRuleSemanticIdentity.findFirst({
    where: {
      OR: [
        { id: identity.semanticIdentityId },
        { semanticRuleId: identity.ruleSemanticId },
        { semanticIdentityDigest: identity.semanticIdentityDigest }
      ]
    },
    include: {
      values: {
        orderBy: [{ kind: 'asc' }, { position: 'asc' }]
      }
    }
  });
  if (existing) {
    if (stableJson(identityFromRow(existing)) !== stableJson(identity)) {
      throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
    }
    return;
  }
  await tx.sastRuleSemanticIdentity.create({ data: identityData(identity) });
  const values = identityValues(identity);
  if (values.length > 0) {
    await tx.sastRuleSemanticIdentityValue.createMany({ data: values });
  }
}

async function assertReplacementSafe(
  tx: Prisma.TransactionClient,
  metadata: Readonly<SastRuleDefinitionMetadata>
): Promise<void> {
  const target = metadata.replacementSemanticRuleId;
  if (!target) return;
  const targetIdentity = await tx.sastRuleSemanticIdentity.findUnique({
    where: { semanticRuleId: target }
  });
  if (!targetIdentity) {
    throw new SastRuleSemanticPolicyPersistenceError(
      'REFERENCE_INVALID'
    );
  }
  let current = target;
  const visited = new Set([metadata.ruleSemanticId]);
  for (let depth = 0; depth < 64; depth += 1) {
    if (visited.has(current)) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'REFERENCE_INVALID'
      );
    }
    visited.add(current);
    const replacements = await tx.sastRuleDefinitionMetadata.findMany({
      where: {
        semanticRuleId: current,
        replacementSemanticRuleId: { not: null }
      },
      select: { replacementSemanticRuleId: true },
      distinct: ['replacementSemanticRuleId']
    });
    if (replacements.length === 0) return;
    if (
      replacements.length !== 1 ||
      !replacements[0]?.replacementSemanticRuleId
    ) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'REFERENCE_INVALID'
      );
    }
    current = replacements[0].replacementSemanticRuleId;
  }
  throw new SastRuleSemanticPolicyPersistenceError('REFERENCE_INVALID');
}

async function assertPolicyReferences(
  tx: Prisma.TransactionClient,
  policy: Readonly<SastTenantRulePolicy>
): Promise<void> {
  const tenant = await tx.tenant.findUnique({
    where: { id: policy.tenantId },
    select: { status: true }
  });
  if (!tenant || tenant.status !== 'ACTIVE') {
    throw new SastRuleSemanticPolicyPersistenceError(
      'TENANT_SCOPE_INVALID'
    );
  }
  const ruleTargets = uniqueSorted([
    ...policy.ruleDecisions.map((decision) => decision.ruleSemanticId),
    ...policy.repositoryOverrides.flatMap((override) =>
      override.ruleDecisions.map((decision) => decision.ruleSemanticId)
    )
  ]);
  const categoryTargets = uniqueSorted([
    ...policy.categoryDecisions.map((decision) => decision.category),
    ...policy.repositoryOverrides.flatMap((override) =>
      override.categoryDecisions.map((decision) => decision.category)
    )
  ]);
  const identities = await tx.sastRuleSemanticIdentity.findMany({
    where: {
      OR: [
        { semanticRuleId: { in: ruleTargets } },
        { category: { in: categoryTargets } }
      ]
    },
    select: {
      semanticRuleId: true,
      category: true,
      tenantControl: true
    }
  });
  if (
    ruleTargets.some(
      (target) =>
        !identities.some((identity) => identity.semanticRuleId === target)
    ) ||
    categoryTargets.some(
      (target) =>
        !identities.some((identity) => identity.category === target)
    )
  ) {
    throw new SastRuleSemanticPolicyPersistenceError(
      'REFERENCE_INVALID'
    );
  }
  const disabledRules = new Set(
    [
      ...policy.ruleDecisions,
      ...policy.repositoryOverrides.flatMap(
        (override) => override.ruleDecisions
      )
    ]
      .filter((decision) => decision.state === 'DISABLED')
      .map((decision) => decision.ruleSemanticId)
  );
  const disabledCategories = new Set(
    [
      ...policy.categoryDecisions,
      ...policy.repositoryOverrides.flatMap(
        (override) => override.categoryDecisions
      )
    ]
      .filter((decision) => decision.state === 'DISABLED')
      .map((decision) => decision.category)
  );
  if (
    identities.some(
      (identity) =>
        identity.tenantControl === 'MANDATORY' &&
        (disabledRules.has(identity.semanticRuleId) ||
          disabledCategories.has(identity.category))
    )
  ) {
    throw new SastRuleSemanticPolicyPersistenceError(
      'REFERENCE_INVALID'
    );
  }

  const repositoryIds = policy.repositoryOverrides.map(
    (override) => override.repositoryBindingId
  );
  if (repositoryIds.length > 0) {
    const repositoryCount = await tx.repositoryBinding.count({
      where: {
        id: { in: repositoryIds },
        tenantId: policy.tenantId,
        status: 'ACTIVE'
      }
    });
    if (repositoryCount !== repositoryIds.length) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'TENANT_SCOPE_INVALID'
      );
    }
  }
  const waiverIds = policy.approvedWaiverRefs.map(referenceSuffix);
  if (waiverIds.length > 0) {
    const waiverCount = await tx.waiver.count({
      where: {
        id: { in: waiverIds },
        tenantId: policy.tenantId,
        expiresAt: { gte: new Date(policy.expiresAt) }
      }
    });
    if (waiverCount !== waiverIds.length) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'REFERENCE_INVALID'
      );
    }
  }
  const suppressionIds =
    policy.approvedSuppressionRefs.map(referenceSuffix);
  if (suppressionIds.length > 0) {
    const suppressionCount = await tx.suppression.count({
      where: {
        id: { in: suppressionIds },
        tenantId: policy.tenantId
      }
    });
    if (suppressionCount !== suppressionIds.length) {
      throw new SastRuleSemanticPolicyPersistenceError(
        'REFERENCE_INVALID'
      );
    }
  }
}

async function assertResolutionBindings(
  tx: Prisma.TransactionClient,
  receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
): Promise<void> {
  const policyRow = await tx.sastTenantRulePolicy.findUnique({
    where: { id: receipt.policyId },
    include: POLICY_INCLUDE
  });
  if (!policyRow) {
    throw new SastRuleSemanticPolicyPersistenceError('POLICY_NOT_FOUND');
  }
  const policy = policyFromRow(policyRow);
  if (
    policy.tenantId !== receipt.context.tenantId ||
    policy.policyVersion !== receipt.policyVersion ||
    policy.policyDigest !== receipt.policyDigest ||
    Date.parse(receipt.evaluatedAt) < Date.parse(policy.effectiveAt) ||
    Date.parse(receipt.evaluatedAt) >= Date.parse(policy.expiresAt)
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
  const repository = await tx.repositoryBinding.findFirst({
    where: {
      id: receipt.context.repositoryBindingId,
      tenantId: receipt.context.tenantId,
      status: 'ACTIVE'
    },
    select: { id: true }
  });
  if (!repository) {
    throw new SastRuleSemanticPolicyPersistenceError(
      'TENANT_SCOPE_INVALID'
    );
  }
  const bindingRows =
    await tx.sastRuleDefinitionMetadataBinding.findMany({
      where: {
        id: { in: receipt.rules.map((rule) => rule.bindingId) }
      },
      include: METADATA_BINDING_INCLUDE
    });
  if (bindingRows.length !== receipt.rules.length) {
    throw new SastRuleSemanticPolicyPersistenceError(
      'METADATA_NOT_FOUND'
    );
  }
  const bindingById = new Map(
    bindingRows.map(
      (row) => [row.id, metadataBindingFromRow(row)] as const
    )
  );
  if (
    receipt.rules.some((rule) => {
      const binding = bindingById.get(rule.bindingId);
      const metadata = binding?.metadata;
      return (
        !binding ||
        !metadata ||
        binding.bindingDigest !== rule.bindingDigest ||
        metadata.metadataDigest !== rule.metadataDigest ||
        binding.manifestId !== rule.manifestId ||
        binding.manifestDigest !== rule.manifestDigest ||
        binding.bundleDigest !== rule.bundleDigest ||
        metadata.ruleId !== rule.ruleId ||
        metadata.ruleRevision !== rule.ruleRevision ||
        metadata.ruleSemanticId !== rule.ruleSemanticId ||
        metadata.semanticIdentity.semanticIdentityDigest !==
          rule.semanticIdentityDigest ||
        metadata.semanticIdentity.category !== rule.category ||
        metadata.semanticIdentity.tenantControl !== rule.tenantControl
      );
    })
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
}

function identityData(
  identity: Readonly<SastRuleSemanticIdentity>
): Prisma.SastRuleSemanticIdentityUncheckedCreateInput {
  return {
    id: identity.semanticIdentityId,
    contractVersion: identity.version,
    semanticRuleId: identity.ruleSemanticId,
    semanticIdentityDigest: identity.semanticIdentityDigest,
    capability: identity.capability,
    category: identity.category,
    languageCount: identity.languages.length,
    formatCount: identity.formats.length,
    vulnerabilityPredicateRef: identity.vulnerabilityPredicateRef,
    sourceKindCount: identity.sourceKinds.length,
    sinkKindCount: identity.sinkKinds.length,
    defaultSeverity: identity.defaultSeverity,
    defaultConfidence: identity.defaultConfidence,
    findingIdentityRef: identity.findingIdentityRef,
    tenantControl: identity.tenantControl,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    executableRuleContentStored: false,
    customerSourceStored: false,
    secretValueStored: false
  };
}

function identityValues(
  identity: Readonly<SastRuleSemanticIdentity>
): Prisma.SastRuleSemanticIdentityValueCreateManyInput[] {
  return [
    ...valueRows(identity.semanticIdentityId, 'LANGUAGE', identity.languages),
    ...valueRows(identity.semanticIdentityId, 'FORMAT', identity.formats),
    ...valueRows(
      identity.semanticIdentityId,
      'SOURCE_KIND',
      identity.sourceKinds
    ),
    ...valueRows(
      identity.semanticIdentityId,
      'SINK_KIND',
      identity.sinkKinds
    )
  ];
}

function valueRows(
  semanticIdentityId: string,
  kind: IdentityValueKind,
  values: readonly string[]
): Prisma.SastRuleSemanticIdentityValueCreateManyInput[] {
  return values.map((value, position) => ({
    semanticIdentityId,
    kind,
    position,
    value
  }));
}

function metadataData(
  metadata: Readonly<SastRuleDefinitionMetadata>
): Prisma.SastRuleDefinitionMetadataUncheckedCreateInput {
  return {
    id: metadata.metadataId,
    contractVersion: metadata.version,
    metadataDigest: metadata.metadataDigest,
    scanner: metadata.scanner,
    ruleId: metadata.ruleId,
    ruleRevision: metadata.ruleRevision,
    semanticRuleId: metadata.ruleSemanticId,
    semanticIdentityId: metadata.semanticIdentity.semanticIdentityId,
    semanticIdentityDigest:
      metadata.semanticIdentity.semanticIdentityDigest,
    ownerRef: metadata.ownerRef,
    cweCount: metadata.cweIds.length,
    owaspMappingCount: metadata.owaspMappings.length,
    documentationRef: metadata.documentationRef,
    fixtureRefCount: metadata.fixtureRefs.length,
    introducedInBundleVersion: metadata.introducedInBundleVersion,
    firstSupportedScannerVersion: metadata.firstSupportedScannerVersion,
    lastSupportedScannerVersion: metadata.lastSupportedScannerVersion,
    deprecationState: metadata.deprecationState,
    replacementSemanticRuleId: metadata.replacementSemanticRuleId,
    source: metadata.source,
    immutable: metadata.immutable,
    executableRuleContentStored: metadata.executableRuleContentStored,
    customerExecutableConfigAllowed:
      metadata.customerExecutableConfigAllowed,
    customerSourceStored: metadata.customerSourceStored,
    secretValueStored: metadata.secretValueStored
  };
}

function metadataBindingData(
  binding: Readonly<SastRuleDefinitionMetadataBinding>
): Prisma.SastRuleDefinitionMetadataBindingUncheckedCreateInput {
  return {
    id: binding.bindingId,
    contractVersion: binding.version,
    bindingDigest: binding.bindingDigest,
    manifestId: binding.manifestId,
    manifestDigest: binding.manifestDigest,
    bundleId: binding.bundleId,
    bundleDigest: binding.bundleDigest,
    scanner: binding.scanner,
    ruleId: binding.ruleId,
    ruleRevision: binding.ruleRevision,
    semanticRuleId: binding.ruleSemanticId,
    metadataId: binding.metadataId,
    metadataDigest: binding.metadataDigest,
    semanticIdentityDigest: binding.semanticIdentityDigest,
    source: binding.source,
    immutable: binding.immutable,
    executableRuleContentStored: binding.executableRuleContentStored,
    customerExecutableConfigAllowed:
      binding.customerExecutableConfigAllowed,
    customerSourceStored: binding.customerSourceStored,
    secretValueStored: binding.secretValueStored
  };
}

function metadataValues(
  metadata: Readonly<SastRuleDefinitionMetadata>
): Prisma.SastRuleDefinitionMetadataValueCreateManyInput[] {
  return [
    ...metadataValueRows(metadata.metadataId, 'CWE', metadata.cweIds),
    ...metadataValueRows(
      metadata.metadataId,
      'OWASP',
      metadata.owaspMappings
    ),
    ...metadataValueRows(
      metadata.metadataId,
      'FIXTURE',
      metadata.fixtureRefs
    )
  ];
}

function metadataValueRows(
  metadataId: string,
  kind: MetadataValueKind,
  values: readonly string[]
): Prisma.SastRuleDefinitionMetadataValueCreateManyInput[] {
  return values.map((value, position) => ({
    metadataId,
    kind,
    position,
    value
  }));
}

function policyData(
  policy: Readonly<SastTenantRulePolicy>
): Prisma.SastTenantRulePolicyUncheckedCreateInput {
  return {
    id: policy.policyId,
    contractVersion: policy.version,
    tenantId: policy.tenantId,
    policyVersion: policy.policyVersion,
    policyDigest: policy.policyDigest,
    effectiveAt: new Date(policy.effectiveAt),
    expiresAt: new Date(policy.expiresAt),
    categoryDecisionCount: policy.categoryDecisions.length,
    categoryDecisionDigest: policy.categoryDecisionDigest,
    ruleDecisionCount: policy.ruleDecisions.length,
    ruleDecisionDigest: policy.ruleDecisionDigest,
    pathExclusionCount: policy.pathExclusions.length,
    pathExclusionDigest: policy.pathExclusionDigest,
    dashboardSeverityFloor: policy.severityFloors.dashboard,
    publicationSeverityFloor: policy.severityFloors.publication,
    repositoryOverrideCount: policy.repositoryOverrides.length,
    repositoryOverrideDigest: policy.repositoryOverrideDigest,
    approvedWaiverRefCount: policy.approvedWaiverRefs.length,
    approvedSuppressionRefCount: policy.approvedSuppressionRefs.length,
    approvedReferenceDigest: policy.approvedReferenceDigest,
    actorRef: policy.actorRef,
    auditRef: policy.auditRef,
    source: policy.source,
    immutable: policy.immutable,
    executableRulesAccepted: policy.executableRulesAccepted,
    cliFlagsAccepted: policy.cliFlagsAccepted,
    pluginsAccepted: policy.pluginsAccepted,
    arbitraryConfigurationAccepted:
      policy.arbitraryConfigurationAccepted,
    customerSourceStored: policy.customerSourceStored,
    secretValueStored: policy.secretValueStored
  };
}

async function createPolicyChildren(
  tx: Prisma.TransactionClient,
  policy: Readonly<SastTenantRulePolicy>
): Promise<void> {
  const decisions = policyDecisions(policy.policyId, policy);
  if (decisions.length > 0) {
    await tx.sastTenantRulePolicyDecision.createMany({ data: decisions });
  }
  if (policy.pathExclusions.length > 0) {
    await tx.sastTenantRulePolicyPathExclusion.createMany({
      data: policy.pathExclusions.map((pathPrefix, position) => ({
        policyId: policy.policyId,
        position,
        pathPrefix
      }))
    });
  }
  for (const [position, override] of policy.repositoryOverrides.entries()) {
    await tx.sastTenantRulePolicyRepositoryOverride.create({
      data: {
        policyId: policy.policyId,
        tenantId: policy.tenantId,
        repositoryBindingId: override.repositoryBindingId,
        position,
        categoryDecisionCount: override.categoryDecisions.length,
        ruleDecisionCount: override.ruleDecisions.length,
        pathExclusionCount: override.pathExclusions.length,
        dashboardSeverityFloor: override.severityFloors.dashboard,
        publicationSeverityFloor: override.severityFloors.publication
      }
    });
    const overrideDecisions = policyOverrideDecisions(
      policy.policyId,
      override.repositoryBindingId,
      override
    );
    if (overrideDecisions.length > 0) {
      await tx.sastTenantRulePolicyRepositoryDecision.createMany({
        data: overrideDecisions
      });
    }
    if (override.pathExclusions.length > 0) {
      await tx.sastTenantRulePolicyRepositoryPathExclusion.createMany({
        data: override.pathExclusions.map((pathPrefix, childPosition) => ({
          policyId: policy.policyId,
          repositoryBindingId: override.repositoryBindingId,
          position: childPosition,
          pathPrefix
        }))
      });
    }
  }
  if (policy.approvedWaiverRefs.length > 0) {
    await tx.sastTenantRulePolicyWaiverReference.createMany({
      data: policy.approvedWaiverRefs.map((reference, position) => ({
        policyId: policy.policyId,
        tenantId: policy.tenantId,
        position,
        reference,
        waiverId: referenceSuffix(reference)
      }))
    });
  }
  if (policy.approvedSuppressionRefs.length > 0) {
    await tx.sastTenantRulePolicySuppressionReference.createMany({
      data: policy.approvedSuppressionRefs.map((reference, position) => ({
        policyId: policy.policyId,
        tenantId: policy.tenantId,
        position,
        reference,
        suppressionId: referenceSuffix(reference)
      }))
    });
  }
}

function policyDecisions(
  policyId: string,
  policy: Readonly<SastTenantRulePolicy>
): Prisma.SastTenantRulePolicyDecisionCreateManyInput[] {
  return [
    ...decisionRows(
      policyId,
      'CATEGORY',
      policy.categoryDecisions.map((decision) => ({
        target: decision.category,
        state: decision.state
      }))
    ),
    ...decisionRows(
      policyId,
      'RULE',
      policy.ruleDecisions.map((decision) => ({
        target: decision.ruleSemanticId,
        state: decision.state
      }))
    )
  ];
}

function decisionRows(
  policyId: string,
  kind: PolicyDecisionKind,
  decisions: readonly { target: string; state: string }[]
): Prisma.SastTenantRulePolicyDecisionCreateManyInput[] {
  return decisions.map((decision, position) => ({
    policyId,
    kind,
    position,
    target: decision.target,
    state: decision.state
  }));
}

function policyOverrideDecisions(
  policyId: string,
  repositoryBindingId: string,
  override: Readonly<
    SastTenantRulePolicy['repositoryOverrides'][number]
  >
): Prisma.SastTenantRulePolicyRepositoryDecisionCreateManyInput[] {
  const category = override.categoryDecisions.map((decision, position) => ({
    policyId,
    repositoryBindingId,
    kind: 'CATEGORY',
    position,
    target: decision.category,
    state: decision.state
  }));
  const rules = override.ruleDecisions.map((decision, position) => ({
    policyId,
    repositoryBindingId,
    kind: 'RULE',
    position,
    target: decision.ruleSemanticId,
    state: decision.state
  }));
  return [...category, ...rules];
}

function resolutionData(
  receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
): Prisma.SastTenantRulePolicyResolutionUncheckedCreateInput {
  return {
    id: receipt.receiptId,
    contractVersion: receipt.version,
    receiptIdentityDigest: receipt.receiptIdentityDigest,
    receiptDigest: receipt.receiptDigest,
    policyId: receipt.policyId,
    tenantId: receipt.context.tenantId,
    policyVersion: receipt.policyVersion,
    policyDigest: receipt.policyDigest,
    repositoryBindingId: receipt.context.repositoryBindingId,
    scannerSetDigest: receipt.context.scannerSetDigest,
    profileId: receipt.context.profileId,
    profileDigest: receipt.context.profileDigest,
    manifestCount: receipt.manifestDigests.length,
    manifestSetDigest: receipt.manifestSetDigest,
    semanticMetadataSetDigest: receipt.semanticMetadataSetDigest,
    ruleCount: receipt.rules.length,
    ruleResolutionDigest: receipt.ruleResolutionDigest,
    enabledRuleSetDigest: receipt.enabledRuleSetDigest,
    disabledRuleSetDigest: receipt.disabledRuleSetDigest,
    pathExclusionCount: receipt.pathExclusions.length,
    pathExclusionDigest: receipt.pathExclusionDigest,
    dashboardSeverityFloor: receipt.severityFloors.dashboard,
    publicationSeverityFloor: receipt.severityFloors.publication,
    policyMatched: receipt.policyMatched,
    manifestMetadataMatched: receipt.manifestMetadataMatched,
    semanticIdentityVerified: receipt.semanticIdentityVerified,
    mandatoryRulesPreserved: receipt.mandatoryRulesPreserved,
    executableConfigurationAccepted:
      receipt.executableConfigurationAccepted,
    customerInputStored: receipt.customerInputStored,
    evaluatedAt: new Date(receipt.evaluatedAt)
  };
}

async function createResolutionChildren(
  tx: Prisma.TransactionClient,
  receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
): Promise<void> {
  await tx.sastTenantRulePolicyResolutionRule.createMany({
    data: receipt.rules.map((rule, position) => ({
      resolutionId: receipt.receiptId,
      position,
      bindingId: rule.bindingId,
      bindingDigest: rule.bindingDigest,
      manifestId: rule.manifestId,
      manifestDigest: rule.manifestDigest,
      bundleDigest: rule.bundleDigest,
      ruleId: rule.ruleId,
      ruleRevision: rule.ruleRevision,
      semanticRuleId: rule.ruleSemanticId,
      metadataId: rule.metadataId,
      metadataDigest: rule.metadataDigest,
      semanticIdentityDigest: rule.semanticIdentityDigest,
      category: rule.category,
      tenantControl: rule.tenantControl,
      state: rule.state
    }))
  });
  if (receipt.pathExclusions.length > 0) {
    await tx.sastTenantRulePolicyResolutionPathExclusion.createMany({
      data: receipt.pathExclusions.map((pathPrefix, position) => ({
        resolutionId: receipt.receiptId,
        position,
        pathPrefix
      }))
    });
  }
}

function replayMetadata(
  row: MetadataRow,
  expected: Readonly<SastRuleDefinitionMetadata>,
  replayed = true
): { metadata: SastRuleDefinitionMetadata; replayed: boolean } {
  const metadata = metadataFromRow(row);
  if (
    canonicalizeSastRuleDefinitionMetadata(metadata) !==
    canonicalizeSastRuleDefinitionMetadata(expected)
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
  return { metadata, replayed };
}

function replayMetadataBinding(
  row: MetadataBindingRow,
  expected: Readonly<SastRuleDefinitionMetadataBinding>,
  replayed = true
): PersistedSastRuleDefinitionMetadataBinding {
  const binding = metadataBindingFromRow(row);
  if (
    canonicalizeSastRuleDefinitionMetadataBinding(binding) !==
    canonicalizeSastRuleDefinitionMetadataBinding(expected)
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
  return { binding, replayed };
}

function replayPolicy(
  row: PolicyRow,
  expected: Readonly<SastTenantRulePolicy>,
  replayed = true
): PersistedSastTenantRulePolicy {
  const policy = policyFromRow(row);
  if (
    canonicalizeSastTenantRulePolicy(policy) !==
    canonicalizeSastTenantRulePolicy(expected)
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
  return { policy, replayed };
}

function replayResolution(
  row: ResolutionRow,
  expected: Readonly<SastTenantRulePolicyResolutionReceipt>,
  replayed = true
): PersistedSastTenantRulePolicyResolution {
  const receipt = resolutionFromRow(row);
  const replayCandidate: SastTenantRulePolicyResolutionReceipt = {
    ...expected,
    context: {
      ...expected.context,
      evaluatedAt: receipt.evaluatedAt
    },
    evaluatedAt: receipt.evaluatedAt,
    receiptDigest: receipt.receiptDigest
  };
  if (
    Date.parse(expected.evaluatedAt) < Date.parse(receipt.evaluatedAt) ||
    canonicalizeSastTenantRulePolicyResolutionReceipt(receipt) !==
      canonicalizeSastTenantRulePolicyResolutionReceipt(replayCandidate)
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('REPLAY_CONFLICT');
  }
  return { receipt, replayed };
}

function metadataFromRow(row: MetadataRow): SastRuleDefinitionMetadata {
  const identity = identityFromRow(row.semanticIdentity);
  const metadata: SastRuleDefinitionMetadata = {
    version:
      row.contractVersion as SastRuleDefinitionMetadata['version'],
    metadataId: row.id,
    metadataDigest: row.metadataDigest as `sha256:${string}`,
    scanner: row.scanner as SastRuleDefinitionMetadata['scanner'],
    ruleId: row.ruleId,
    ruleRevision: row.ruleRevision,
    ruleSemanticId: row.semanticRuleId,
    semanticIdentity: identity,
    ownerRef: row.ownerRef,
    cweIds: valuesFor(row.values, 'CWE', row.cweCount),
    owaspMappings: valuesFor(
      row.values,
      'OWASP',
      row.owaspMappingCount
    ),
    documentationRef: row.documentationRef,
    fixtureRefs: valuesFor(
      row.values,
      'FIXTURE',
      row.fixtureRefCount
    ),
    introducedInBundleVersion: row.introducedInBundleVersion,
    firstSupportedScannerVersion: row.firstSupportedScannerVersion,
    lastSupportedScannerVersion: row.lastSupportedScannerVersion,
    deprecationState:
      row.deprecationState as SastRuleDefinitionMetadata['deprecationState'],
    replacementSemanticRuleId: row.replacementSemanticRuleId,
    source: row.source as 'PLATFORM_MANAGED',
    immutable: row.immutable as true,
    executableRuleContentStored:
      row.executableRuleContentStored as false,
    customerExecutableConfigAllowed:
      row.customerExecutableConfigAllowed as false,
    customerSourceStored: row.customerSourceStored as false,
    secretValueStored: row.secretValueStored as false
  };
  assertMetadataValid(metadata, 'LEDGER_CORRUPT');
  return metadata;
}

function metadataBindingFromRow(
  row: MetadataBindingRow
): SastRuleDefinitionMetadataBinding {
  const metadata = metadataFromRow(row.metadata);
  const binding: SastRuleDefinitionMetadataBinding = {
    version:
      row.contractVersion as SastRuleDefinitionMetadataBinding['version'],
    bindingId: row.id,
    bindingDigest: row.bindingDigest as `sha256:${string}`,
    manifestId: row.manifestId,
    manifestDigest: row.manifestDigest as `sha256:${string}`,
    bundleId: row.bundleId,
    bundleDigest: row.bundleDigest as `sha256:${string}`,
    scanner:
      row.scanner as SastRuleDefinitionMetadataBinding['scanner'],
    ruleId: row.ruleId,
    ruleRevision: row.ruleRevision,
    ruleSemanticId: row.semanticRuleId,
    metadataId: row.metadataId,
    metadataDigest: row.metadataDigest as `sha256:${string}`,
    semanticIdentityDigest:
      row.semanticIdentityDigest as `sha256:${string}`,
    source: row.source as 'PLATFORM_MANAGED',
    immutable: row.immutable as true,
    executableRuleContentStored:
      row.executableRuleContentStored as false,
    customerExecutableConfigAllowed:
      row.customerExecutableConfigAllowed as false,
    customerSourceStored: row.customerSourceStored as false,
    secretValueStored: row.secretValueStored as false,
    metadata
  };
  assertMetadataBindingValid(binding, 'LEDGER_CORRUPT');
  return binding;
}

function identityFromRow(row: {
  id: string;
  contractVersion: string;
  semanticRuleId: string;
  semanticIdentityDigest: string;
  capability: string;
  category: string;
  languageCount: number;
  formatCount: number;
  vulnerabilityPredicateRef: string;
  sourceKindCount: number;
  sinkKindCount: number;
  defaultSeverity: string;
  defaultConfidence: string;
  findingIdentityRef: string;
  tenantControl: string;
  source: string;
  immutable: boolean;
  executableRuleContentStored: boolean;
  customerSourceStored: boolean;
  secretValueStored: boolean;
  values: Array<{ kind: string; position: number; value: string }>;
}): SastRuleSemanticIdentity {
  const identity: SastRuleSemanticIdentity = {
    version:
      row.contractVersion as SastRuleSemanticIdentity['version'],
    semanticIdentityId: row.id,
    ruleSemanticId: row.semanticRuleId,
    capability:
      row.capability as SastRuleSemanticIdentity['capability'],
    category: row.category,
    languages: valuesFor(row.values, 'LANGUAGE', row.languageCount),
    formats: valuesFor(row.values, 'FORMAT', row.formatCount),
    vulnerabilityPredicateRef: row.vulnerabilityPredicateRef,
    sourceKinds: valuesFor(
      row.values,
      'SOURCE_KIND',
      row.sourceKindCount
    ),
    sinkKinds: valuesFor(row.values, 'SINK_KIND', row.sinkKindCount),
    defaultSeverity:
      row.defaultSeverity as SastRuleSemanticIdentity['defaultSeverity'],
    defaultConfidence:
      row.defaultConfidence as SastRuleSemanticIdentity['defaultConfidence'],
    findingIdentityRef: row.findingIdentityRef,
    tenantControl:
      row.tenantControl as SastRuleSemanticIdentity['tenantControl'],
    semanticIdentityDigest:
      row.semanticIdentityDigest as `sha256:${string}`
  };
  if (
    row.source !== 'PLATFORM_MANAGED' ||
    row.immutable !== true ||
    row.executableRuleContentStored !== false ||
    row.customerSourceStored !== false ||
    row.secretValueStored !== false
  ) {
    throw new SastRuleSemanticPolicyPersistenceError('LEDGER_CORRUPT');
  }
  return identity;
}

function policyFromRow(row: PolicyRow): SastTenantRulePolicy {
  const categoryDecisions = policyDecisionValues(
    row.decisions,
    'CATEGORY',
    row.categoryDecisionCount
  ).map((decision) => ({
    category: decision.target,
    state: decision.state as 'ENABLED' | 'DISABLED'
  }));
  const ruleDecisions = policyDecisionValues(
    row.decisions,
    'RULE',
    row.ruleDecisionCount
  ).map((decision) => ({
    ruleSemanticId: decision.target,
    state: decision.state as 'ENABLED' | 'DISABLED'
  }));
  const repositoryOverrides = row.repositoryOverrides.map(
    (override, position) => {
      if (override.position !== position) ledgerCorrupt();
      return {
        repositoryBindingId: override.repositoryBindingId,
        categoryDecisions: policyDecisionValues(
          override.decisions,
          'CATEGORY',
          override.categoryDecisionCount
        ).map((decision) => ({
          category: decision.target,
          state: decision.state as 'ENABLED' | 'DISABLED'
        })),
        ruleDecisions: policyDecisionValues(
          override.decisions,
          'RULE',
          override.ruleDecisionCount
        ).map((decision) => ({
          ruleSemanticId: decision.target,
          state: decision.state as 'ENABLED' | 'DISABLED'
        })),
        pathExclusions: orderedPathValues(
          override.pathExclusions,
          override.pathExclusionCount
        ),
        severityFloors: {
          dashboard: override.dashboardSeverityFloor,
          publication: override.publicationSeverityFloor
        }
      };
    }
  );
  if (
    repositoryOverrides.length !== row.repositoryOverrideCount ||
    row.waiverReferences.length !== row.approvedWaiverRefCount ||
    row.suppressionReferences.length !==
      row.approvedSuppressionRefCount ||
    row.waiverReferences.some(
      (reference, position) => reference.position !== position
    ) ||
    row.suppressionReferences.some(
      (reference, position) => reference.position !== position
    )
  ) {
    ledgerCorrupt();
  }
  const policy: SastTenantRulePolicy = {
    version: row.contractVersion as SastTenantRulePolicy['version'],
    policyId: row.id,
    tenantId: row.tenantId,
    policyVersion: row.policyVersion,
    policyDigest: row.policyDigest as `sha256:${string}`,
    effectiveAt: row.effectiveAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    categoryDecisions,
    categoryDecisionDigest:
      row.categoryDecisionDigest as `sha256:${string}`,
    ruleDecisions,
    ruleDecisionDigest: row.ruleDecisionDigest as `sha256:${string}`,
    pathExclusions: orderedPathValues(
      row.pathExclusions,
      row.pathExclusionCount
    ),
    pathExclusionDigest: row.pathExclusionDigest as `sha256:${string}`,
    severityFloors: {
      dashboard: row.dashboardSeverityFloor,
      publication: row.publicationSeverityFloor
    },
    repositoryOverrides,
    repositoryOverrideDigest:
      row.repositoryOverrideDigest as `sha256:${string}`,
    approvedWaiverRefs: row.waiverReferences.map(
      (reference) => reference.reference
    ),
    approvedSuppressionRefs: row.suppressionReferences.map(
      (reference) => reference.reference
    ),
    approvedReferenceDigest:
      row.approvedReferenceDigest as `sha256:${string}`,
    actorRef: row.actorRef,
    auditRef: row.auditRef,
    source: row.source as 'TENANT_ADMIN_METADATA',
    immutable: row.immutable as true,
    executableRulesAccepted: row.executableRulesAccepted as false,
    cliFlagsAccepted: row.cliFlagsAccepted as false,
    pluginsAccepted: row.pluginsAccepted as false,
    arbitraryConfigurationAccepted:
      row.arbitraryConfigurationAccepted as false,
    customerSourceStored: row.customerSourceStored as false,
    secretValueStored: row.secretValueStored as false
  };
  assertPolicyValid(policy, 'LEDGER_CORRUPT');
  return policy;
}

function resolutionFromRow(
  row: ResolutionRow
): SastTenantRulePolicyResolutionReceipt {
  if (
    row.rules.length !== row.ruleCount ||
    row.rules.some((rule, position) => rule.position !== position)
  ) {
    ledgerCorrupt();
  }
  const manifestDigests = [
    ...new Set(row.rules.map((rule) => rule.manifestDigest))
  ].sort(compareStrings);
  if (manifestDigests.length !== row.manifestCount) ledgerCorrupt();
  const receipt: SastTenantRulePolicyResolutionReceipt = {
    version:
      row.contractVersion as SastTenantRulePolicyResolutionReceipt['version'],
    receiptId: row.id,
    receiptIdentityDigest:
      row.receiptIdentityDigest as `sha256:${string}`,
    receiptDigest: row.receiptDigest as `sha256:${string}`,
    policyId: row.policyId,
    policyVersion: row.policyVersion,
    policyDigest: row.policyDigest as `sha256:${string}`,
    context: {
      tenantId: row.tenantId,
      repositoryBindingId: row.repositoryBindingId,
      scannerSetDigest: row.scannerSetDigest as `sha256:${string}`,
      profileId:
        row.profileId as SastTenantRulePolicyResolutionReceipt['context']['profileId'],
      profileDigest: row.profileDigest as `sha256:${string}`,
      evaluatedAt: row.evaluatedAt.toISOString()
    },
    manifestDigests: manifestDigests as `sha256:${string}`[],
    manifestSetDigest: row.manifestSetDigest as `sha256:${string}`,
    semanticMetadataSetDigest:
      row.semanticMetadataSetDigest as `sha256:${string}`,
    rules: row.rules.map((rule) => ({
      bindingId: rule.bindingId,
      bindingDigest: rule.bindingDigest as `sha256:${string}`,
      manifestId: rule.manifestId,
      manifestDigest: rule.manifestDigest as `sha256:${string}`,
      bundleDigest: rule.bundleDigest as `sha256:${string}`,
      ruleId: rule.ruleId,
      ruleRevision: rule.ruleRevision,
      ruleSemanticId: rule.semanticRuleId,
      metadataId: rule.metadataId,
      metadataDigest: rule.metadataDigest as `sha256:${string}`,
      semanticIdentityDigest:
        rule.semanticIdentityDigest as `sha256:${string}`,
      category: rule.category,
      tenantControl:
        rule.tenantControl as 'MANDATORY' | 'OPTIONAL',
      state: rule.state as 'ENABLED' | 'DISABLED'
    })),
    ruleResolutionDigest:
      row.ruleResolutionDigest as `sha256:${string}`,
    enabledRuleSetDigest:
      row.enabledRuleSetDigest as `sha256:${string}`,
    disabledRuleSetDigest:
      row.disabledRuleSetDigest as `sha256:${string}`,
    pathExclusions: orderedPathValues(
      row.pathExclusions,
      row.pathExclusionCount
    ),
    pathExclusionDigest: row.pathExclusionDigest as `sha256:${string}`,
    severityFloors: {
      dashboard: row.dashboardSeverityFloor,
      publication: row.publicationSeverityFloor
    },
    policyMatched: row.policyMatched as true,
    manifestMetadataMatched: row.manifestMetadataMatched as true,
    semanticIdentityVerified: row.semanticIdentityVerified as true,
    mandatoryRulesPreserved: row.mandatoryRulesPreserved as true,
    executableConfigurationAccepted:
      row.executableConfigurationAccepted as false,
    customerInputStored: row.customerInputStored as false,
    evaluatedAt: row.evaluatedAt.toISOString()
  };
  assertResolutionValid(receipt, 'LEDGER_CORRUPT');
  return receipt;
}

function policyDecisionValues(
  values: readonly { kind: string; position: number; target: string; state: string }[],
  kind: PolicyDecisionKind,
  expectedCount: number
): Array<{ target: string; state: string }> {
  const filtered = values.filter((value) => value.kind === kind);
  if (
    filtered.length !== expectedCount ||
    filtered.some((value, position) => value.position !== position)
  ) {
    ledgerCorrupt();
  }
  return filtered.map(({ target, state }) => ({ target, state }));
}

function valuesFor(
  values: readonly { kind: string; position: number; value: string }[],
  kind: string,
  expectedCount: number
): string[] {
  const filtered = values.filter((value) => value.kind === kind);
  if (
    filtered.length !== expectedCount ||
    filtered.some((value, position) => value.position !== position)
  ) {
    ledgerCorrupt();
  }
  return filtered.map((value) => value.value);
}

function orderedPathValues(
  values: readonly { position: number; pathPrefix: string }[],
  expectedCount: number
): string[] {
  if (
    values.length !== expectedCount ||
    values.some((value, position) => value.position !== position)
  ) {
    ledgerCorrupt();
  }
  return values.map((value) => value.pathPrefix);
}

function assertMetadataValid(
  metadata: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts metadata is SastRuleDefinitionMetadata {
  if (
    !isSastRuleDefinitionMetadataShapeValid(
      metadata,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleSemanticPolicyPersistenceError(reason);
  }
}

function assertMetadataBindingValid(
  binding: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts binding is SastRuleDefinitionMetadataBinding {
  if (
    !isSastRuleDefinitionMetadataBindingShapeValid(
      binding,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleSemanticPolicyPersistenceError(reason);
  }
}

function assertPolicyValid(
  policy: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts policy is SastTenantRulePolicy {
  if (
    !isSastTenantRulePolicyShapeValid(
      policy,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleSemanticPolicyPersistenceError(reason);
  }
}

function assertResolutionValid(
  receipt: unknown,
  reason: 'INPUT_INVALID' | 'LEDGER_CORRUPT' = 'INPUT_INVALID'
): asserts receipt is SastTenantRulePolicyResolutionReceipt {
  if (
    !isSastTenantRulePolicyResolutionReceiptShapeValid(
      receipt,
      digestSastRuleBundleCanonical
    )
  ) {
    throw new SastRuleSemanticPolicyPersistenceError(reason);
  }
}

function ledgerCorrupt(): never {
  throw new SastRuleSemanticPolicyPersistenceError('LEDGER_CORRUPT');
}

function referenceSuffix(value: string): string {
  return value.slice(value.indexOf('://') + 3);
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareStrings);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort(compareStrings)
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
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
