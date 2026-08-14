import type { FindingSeverity } from './production-architecture';
import type {
  SastCapability,
  SastProfileId
} from './sast-runtime';
import type { SastRuleBundleScanner } from './sast-rule-bundle-manifest';

export const SAST_RULE_SEMANTIC_IDENTITY_VERSION =
  'sast-rule-semantic-identity-v1' as const;
export const SAST_RULE_DEFINITION_METADATA_VERSION =
  'sast-rule-definition-metadata-v1' as const;
export const SAST_RULE_DEFINITION_METADATA_BINDING_VERSION =
  'sast-rule-definition-metadata-binding-v1' as const;
export const SAST_TENANT_RULE_POLICY_VERSION =
  'sast-tenant-rule-policy-v1' as const;
export const SAST_TENANT_RULE_POLICY_RESOLUTION_VERSION =
  'sast-tenant-rule-policy-resolution-v1' as const;

export const SAST_RULE_POLICY_LIMITS = Object.freeze({
  identifierBytes: 256,
  referenceBytes: 2_048,
  maximumLanguages: 32,
  maximumFormats: 32,
  maximumTaxonomyValues: 64,
  maximumMappings: 64,
  maximumFixtureReferences: 64,
  maximumCategoryDecisions: 256,
  maximumRuleDecisions: 25_000,
  maximumPathExclusions: 256,
  maximumRepositoryOverrides: 256,
  maximumManifestDigests: 256,
  maximumApprovedReferences: 1_024,
  maximumResolvedRules: 50_000,
  maximumPolicyLifetimeMilliseconds: 366 * 24 * 60 * 60 * 1_000
});

export const SAST_RULE_METADATA_CAPABILITIES = [
  'SAST',
  'SECRET_DETECTION',
  'IAC_MISCONFIGURATION'
] as const satisfies readonly SastCapability[];
export type SastRuleMetadataCapability =
  (typeof SAST_RULE_METADATA_CAPABILITIES)[number];

export const SAST_RULE_CONFIDENCE_LEVELS = [
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN'
] as const;
export type SastRuleConfidence =
  (typeof SAST_RULE_CONFIDENCE_LEVELS)[number];

export const SAST_RULE_TENANT_CONTROLS = [
  'MANDATORY',
  'OPTIONAL'
] as const;
export type SastRuleTenantControl =
  (typeof SAST_RULE_TENANT_CONTROLS)[number];

export const SAST_RULE_DEPRECATION_STATES = [
  'ACTIVE',
  'DEPRECATED',
  'RETIRED'
] as const;
export type SastRuleDeprecationState =
  (typeof SAST_RULE_DEPRECATION_STATES)[number];

export const SAST_TENANT_RULE_POLICY_STATES = [
  'ENABLED',
  'DISABLED'
] as const;
export type SastTenantRulePolicyState =
  (typeof SAST_TENANT_RULE_POLICY_STATES)[number];

export const SAST_PLATFORM_RULE_POLICY_SEVERITY_FLOORS = Object.freeze({
  dashboard: 'INFO',
  publication: 'MEDIUM'
} as const satisfies SastTenantRulePolicySeverityFloors);

type Sha256Digest = `sha256:${string}`;
export type SastRulePolicyCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastRuleSemanticIdentityCore {
  version: typeof SAST_RULE_SEMANTIC_IDENTITY_VERSION;
  ruleSemanticId: string;
  capability: SastRuleMetadataCapability;
  category: string;
  languages: string[];
  formats: string[];
  vulnerabilityPredicateRef: string;
  sourceKinds: string[];
  sinkKinds: string[];
  defaultSeverity: FindingSeverity;
  defaultConfidence: SastRuleConfidence;
  findingIdentityRef: string;
  tenantControl: SastRuleTenantControl;
}

export interface SastRuleSemanticIdentity
  extends SastRuleSemanticIdentityCore {
  semanticIdentityId: string;
  semanticIdentityDigest: Sha256Digest;
}

export type SastRuleSemanticIdentityInput = Omit<
  SastRuleSemanticIdentityCore,
  'version'
>;

export interface SastRuleDefinitionMetadataCore {
  version: typeof SAST_RULE_DEFINITION_METADATA_VERSION;
  scanner: SastRuleBundleScanner;
  ruleId: string;
  ruleRevision: string;
  ruleSemanticId: string;
  semanticIdentity: SastRuleSemanticIdentity;
  ownerRef: string;
  cweIds: string[];
  owaspMappings: string[];
  documentationRef: string;
  fixtureRefs: string[];
  introducedInBundleVersion: string;
  firstSupportedScannerVersion: string;
  lastSupportedScannerVersion: string | null;
  deprecationState: SastRuleDeprecationState;
  replacementSemanticRuleId: string | null;
  source: 'PLATFORM_MANAGED';
  immutable: true;
  executableRuleContentStored: false;
  customerExecutableConfigAllowed: false;
  customerSourceStored: false;
  secretValueStored: false;
}

export interface SastRuleDefinitionMetadata
  extends SastRuleDefinitionMetadataCore {
  metadataId: string;
  metadataDigest: Sha256Digest;
}

export type SastRuleDefinitionMetadataInput = Omit<
  SastRuleDefinitionMetadataCore,
  | 'version'
  | 'semanticIdentity'
  | 'source'
  | 'immutable'
  | 'executableRuleContentStored'
  | 'customerExecutableConfigAllowed'
  | 'customerSourceStored'
  | 'secretValueStored'
> & {
  semanticIdentity: SastRuleSemanticIdentityInput;
};

export interface SastRuleDefinitionMetadataBindingCore {
  version: typeof SAST_RULE_DEFINITION_METADATA_BINDING_VERSION;
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleId: string;
  bundleDigest: Sha256Digest;
  scanner: SastRuleBundleScanner;
  ruleId: string;
  ruleRevision: string;
  ruleSemanticId: string;
  metadataId: string;
  metadataDigest: Sha256Digest;
  semanticIdentityDigest: Sha256Digest;
  source: 'PLATFORM_MANAGED';
  immutable: true;
  executableRuleContentStored: false;
  customerExecutableConfigAllowed: false;
  customerSourceStored: false;
  secretValueStored: false;
}

export interface SastRuleDefinitionMetadataBinding
  extends SastRuleDefinitionMetadataBindingCore {
  bindingId: string;
  bindingDigest: Sha256Digest;
  metadata: SastRuleDefinitionMetadata;
}

export interface SastRuleDefinitionMetadataBindingInput {
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleId: string;
  bundleDigest: Sha256Digest;
  metadata: SastRuleDefinitionMetadata;
}

export interface SastTenantRuleCategoryDecision {
  category: string;
  state: SastTenantRulePolicyState;
}

export interface SastTenantRuleDecision {
  ruleSemanticId: string;
  state: SastTenantRulePolicyState;
}

export interface SastTenantRulePolicySeverityFloors {
  dashboard: FindingSeverity;
  publication: FindingSeverity;
}

export interface SastTenantRulePolicyRepositoryOverride {
  repositoryBindingId: string;
  categoryDecisions: SastTenantRuleCategoryDecision[];
  ruleDecisions: SastTenantRuleDecision[];
  pathExclusions: string[];
  severityFloors: SastTenantRulePolicySeverityFloors;
}

export interface SastTenantRulePolicyCore {
  version: typeof SAST_TENANT_RULE_POLICY_VERSION;
  tenantId: string;
  policyVersion: string;
  effectiveAt: string;
  expiresAt: string;
  categoryDecisions: SastTenantRuleCategoryDecision[];
  categoryDecisionDigest: Sha256Digest;
  ruleDecisions: SastTenantRuleDecision[];
  ruleDecisionDigest: Sha256Digest;
  pathExclusions: string[];
  pathExclusionDigest: Sha256Digest;
  severityFloors: SastTenantRulePolicySeverityFloors;
  repositoryOverrides: SastTenantRulePolicyRepositoryOverride[];
  repositoryOverrideDigest: Sha256Digest;
  approvedWaiverRefs: string[];
  approvedSuppressionRefs: string[];
  approvedReferenceDigest: Sha256Digest;
  actorRef: string;
  auditRef: string;
  source: 'TENANT_ADMIN_METADATA';
  immutable: true;
  executableRulesAccepted: false;
  cliFlagsAccepted: false;
  pluginsAccepted: false;
  arbitraryConfigurationAccepted: false;
  customerSourceStored: false;
  secretValueStored: false;
}

export interface SastTenantRulePolicy extends SastTenantRulePolicyCore {
  policyId: string;
  policyDigest: Sha256Digest;
}

export type SastTenantRulePolicyInput = Omit<
  SastTenantRulePolicyCore,
  | 'version'
  | 'categoryDecisionDigest'
  | 'ruleDecisionDigest'
  | 'pathExclusionDigest'
  | 'repositoryOverrideDigest'
  | 'approvedReferenceDigest'
  | 'source'
  | 'immutable'
  | 'executableRulesAccepted'
  | 'cliFlagsAccepted'
  | 'pluginsAccepted'
  | 'arbitraryConfigurationAccepted'
  | 'customerSourceStored'
  | 'secretValueStored'
>;

export interface SastTenantRulePolicyResolutionContext {
  tenantId: string;
  repositoryBindingId: string;
  scannerSetDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  evaluatedAt: string;
}

export interface SastTenantRulePolicyResolvedRule {
  bindingId: string;
  bindingDigest: Sha256Digest;
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleDigest: Sha256Digest;
  ruleId: string;
  ruleRevision: string;
  ruleSemanticId: string;
  metadataId: string;
  metadataDigest: Sha256Digest;
  semanticIdentityDigest: Sha256Digest;
  category: string;
  tenantControl: SastRuleTenantControl;
  state: SastTenantRulePolicyState;
}

export const SAST_TENANT_RULE_POLICY_RESOLUTION_REASON_CODES = [
  'POLICY_SCOPE_MISMATCH',
  'POLICY_NOT_EFFECTIVE',
  'POLICY_EXPIRED',
  'POLICY_SELECTOR_UNKNOWN',
  'POLICY_METADATA_INVALID',
  'POLICY_SEMANTIC_IDENTITY_CONFLICT',
  'POLICY_MANDATORY_RULE_DISABLED'
] as const;
export type SastTenantRulePolicyResolutionReasonCode =
  (typeof SAST_TENANT_RULE_POLICY_RESOLUTION_REASON_CODES)[number];

export interface SastTenantRulePolicyResolutionReceipt {
  version: typeof SAST_TENANT_RULE_POLICY_RESOLUTION_VERSION;
  receiptId: string;
  receiptIdentityDigest: Sha256Digest;
  policyId: string;
  policyVersion: string;
  policyDigest: Sha256Digest;
  context: SastTenantRulePolicyResolutionContext;
  manifestDigests: Sha256Digest[];
  manifestSetDigest: Sha256Digest;
  semanticMetadataSetDigest: Sha256Digest;
  rules: SastTenantRulePolicyResolvedRule[];
  ruleResolutionDigest: Sha256Digest;
  enabledRuleSetDigest: Sha256Digest;
  disabledRuleSetDigest: Sha256Digest;
  pathExclusions: string[];
  pathExclusionDigest: Sha256Digest;
  severityFloors: SastTenantRulePolicySeverityFloors;
  policyMatched: true;
  manifestMetadataMatched: true;
  semanticIdentityVerified: true;
  mandatoryRulesPreserved: true;
  executableConfigurationAccepted: false;
  customerInputStored: false;
  evaluatedAt: string;
  receiptDigest: Sha256Digest;
}

export interface VerifiedSastTenantRulePolicyDescriptor {
  policyId: string;
  policyVersion: string;
  policyDigest: Sha256Digest;
  resolutionReceiptId: string;
  resolutionIdentityDigest: Sha256Digest;
  resolutionReceiptDigest: Sha256Digest;
  semanticMetadataSetDigest: Sha256Digest;
  ruleResolutionDigest: Sha256Digest;
  enabledRuleSetDigest: Sha256Digest;
  disabledRuleSetDigest: Sha256Digest;
  pathExclusionDigest: Sha256Digest;
  severityFloors: SastTenantRulePolicySeverityFloors;
}

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const MANIFEST_ID_PATTERN =
  /^sast-rule-bundle-manifest:\/\/[a-f0-9]{64}$/u;
const SEMANTIC_IDENTITY_ID_PATTERN =
  /^sast-rule-semantic-identity:\/\/[a-f0-9]{64}$/u;
const METADATA_ID_PATTERN =
  /^sast-rule-definition-metadata:\/\/[a-f0-9]{64}$/u;
const METADATA_BINDING_ID_PATTERN =
  /^sast-rule-definition-metadata-binding:\/\/[a-f0-9]{64}$/u;
const POLICY_ID_PATTERN =
  /^sast-tenant-rule-policy:\/\/[a-f0-9]{64}$/u;
const RESOLUTION_ID_PATTERN =
  /^sast-tenant-rule-policy-resolution:\/\/[a-f0-9]{64}$/u;
const BUNDLE_ID_PATTERN =
  /^sast-rule-bundle:\/\/(?:opengrep|trivy)\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const SEMANTIC_RULE_ID_PATTERN =
  /^[a-z0-9][a-z0-9._:-]{0,255}$/u;
const CATEGORY_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/u;
const TAXONOMY_PATTERN = /^[A-Z][A-Z0-9_.:-]{0,127}$/u;
const LANGUAGE_FORMAT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SEMANTIC_VERSION_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const CWE_PATTERN = /^CWE-[1-9]\d{0,8}$/u;
const OWASP_PATTERN = /^OWASP-[A-Z0-9][A-Z0-9._:-]{0,127}$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const ACTOR_REFERENCE_PATTERN =
  /^(?:user|service|tenant-admin):\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u;
const WAIVER_REFERENCE_PATTERN = /^waiver:\/\/[A-Za-z0-9._-]{1,256}$/u;
const SUPPRESSION_REFERENCE_PATTERN =
  /^suppression:\/\/[A-Za-z0-9._-]{1,256}$/u;
const RESOURCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const ISO_INSTANT_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const UTF8_ENCODER = new TextEncoder();

const SEVERITIES = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO'
] as const satisfies readonly FindingSeverity[];
const PROFILES = [
  'JAVA_FAST_V1',
  'JAVA_DEEP_V1',
  'COMMON_DEEP_V1'
] as const satisfies readonly SastProfileId[];

export function buildSastRuleSemanticIdentity(
  input: Readonly<SastRuleSemanticIdentityInput>,
  digestCanonical: SastRulePolicyCanonicalDigester
): SastRuleSemanticIdentity | null {
  if (
    !hasExactKeys(input, [
      'ruleSemanticId',
      'capability',
      'category',
      'languages',
      'formats',
      'vulnerabilityPredicateRef',
      'sourceKinds',
      'sinkKinds',
      'defaultSeverity',
      'defaultConfidence',
      'findingIdentityRef',
      'tenantControl'
    ])
  ) {
    return null;
  }
  const core: SastRuleSemanticIdentityCore = {
    version: SAST_RULE_SEMANTIC_IDENTITY_VERSION,
    ruleSemanticId: input.ruleSemanticId,
    capability: input.capability,
    category: input.category,
    languages: cloneArray(input.languages),
    formats: cloneArray(input.formats),
    vulnerabilityPredicateRef: input.vulnerabilityPredicateRef,
    sourceKinds: cloneArray(input.sourceKinds),
    sinkKinds: cloneArray(input.sinkKinds),
    defaultSeverity: input.defaultSeverity,
    defaultConfidence: input.defaultConfidence,
    findingIdentityRef: input.findingIdentityRef,
    tenantControl: input.tenantControl
  };
  if (!isSemanticIdentityCoreValid(core)) return null;
  const semanticIdentityDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(semanticIdentityDigest);
  if (!suffix) return null;
  const identity: SastRuleSemanticIdentity = {
    ...core,
    semanticIdentityId: `sast-rule-semantic-identity://${suffix}`,
    semanticIdentityDigest
  };
  return isSastRuleSemanticIdentityShapeValid(identity, digestCanonical)
    ? identity
    : null;
}

export function buildSastRuleDefinitionMetadata(
  input: Readonly<SastRuleDefinitionMetadataInput>,
  digestCanonical: SastRulePolicyCanonicalDigester
): SastRuleDefinitionMetadata | null {
  if (
    !hasExactKeys(input, [
      'scanner',
      'ruleId',
      'ruleRevision',
      'ruleSemanticId',
      'semanticIdentity',
      'ownerRef',
      'cweIds',
      'owaspMappings',
      'documentationRef',
      'fixtureRefs',
      'introducedInBundleVersion',
      'firstSupportedScannerVersion',
      'lastSupportedScannerVersion',
      'deprecationState',
      'replacementSemanticRuleId'
    ])
  ) {
    return null;
  }
  const semanticIdentity = buildSastRuleSemanticIdentity(
    input.semanticIdentity,
    digestCanonical
  );
  if (!semanticIdentity) return null;
  const core: SastRuleDefinitionMetadataCore = {
    version: SAST_RULE_DEFINITION_METADATA_VERSION,
    scanner: input.scanner,
    ruleId: input.ruleId,
    ruleRevision: input.ruleRevision,
    ruleSemanticId: input.ruleSemanticId,
    semanticIdentity,
    ownerRef: input.ownerRef,
    cweIds: cloneArray(input.cweIds),
    owaspMappings: cloneArray(input.owaspMappings),
    documentationRef: input.documentationRef,
    fixtureRefs: cloneArray(input.fixtureRefs),
    introducedInBundleVersion: input.introducedInBundleVersion,
    firstSupportedScannerVersion: input.firstSupportedScannerVersion,
    lastSupportedScannerVersion: input.lastSupportedScannerVersion,
    deprecationState: input.deprecationState,
    replacementSemanticRuleId: input.replacementSemanticRuleId,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    executableRuleContentStored: false,
    customerExecutableConfigAllowed: false,
    customerSourceStored: false,
    secretValueStored: false
  };
  if (!isDefinitionMetadataCoreValid(core, digestCanonical)) return null;
  const metadataDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(metadataDigest);
  if (!suffix) return null;
  const metadata: SastRuleDefinitionMetadata = {
    ...core,
    metadataId: `sast-rule-definition-metadata://${suffix}`,
    metadataDigest
  };
  return isSastRuleDefinitionMetadataShapeValid(
    metadata,
    digestCanonical
  )
    ? metadata
    : null;
}

export function buildSastRuleDefinitionMetadataBinding(
  input: Readonly<SastRuleDefinitionMetadataBindingInput>,
  digestCanonical: SastRulePolicyCanonicalDigester
): SastRuleDefinitionMetadataBinding | null {
  if (
    !hasExactKeys(input, [
      'manifestId',
      'manifestDigest',
      'bundleId',
      'bundleDigest',
      'metadata'
    ]) ||
    !isSastRuleDefinitionMetadataShapeValid(
      input.metadata,
      digestCanonical
    )
  ) {
    return null;
  }
  const core: SastRuleDefinitionMetadataBindingCore = {
    version: SAST_RULE_DEFINITION_METADATA_BINDING_VERSION,
    manifestId: input.manifestId,
    manifestDigest: input.manifestDigest,
    bundleId: input.bundleId,
    bundleDigest: input.bundleDigest,
    scanner: input.metadata.scanner,
    ruleId: input.metadata.ruleId,
    ruleRevision: input.metadata.ruleRevision,
    ruleSemanticId: input.metadata.ruleSemanticId,
    metadataId: input.metadata.metadataId,
    metadataDigest: input.metadata.metadataDigest,
    semanticIdentityDigest:
      input.metadata.semanticIdentity.semanticIdentityDigest,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    executableRuleContentStored: false,
    customerExecutableConfigAllowed: false,
    customerSourceStored: false,
    secretValueStored: false
  };
  if (!isDefinitionMetadataBindingCoreValid(core, input.metadata)) {
    return null;
  }
  const bindingDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(bindingDigest);
  if (!suffix) return null;
  const binding: SastRuleDefinitionMetadataBinding = {
    ...core,
    bindingId: `sast-rule-definition-metadata-binding://${suffix}`,
    bindingDigest,
    metadata: cloneDefinitionMetadata(input.metadata)
  };
  return isSastRuleDefinitionMetadataBindingShapeValid(
    binding,
    digestCanonical
  )
    ? binding
    : null;
}

export function buildSastTenantRulePolicy(
  input: Readonly<SastTenantRulePolicyInput>,
  digestCanonical: SastRulePolicyCanonicalDigester
): SastTenantRulePolicy | null {
  if (
    !hasExactKeys(input, [
      'tenantId',
      'policyVersion',
      'effectiveAt',
      'expiresAt',
      'categoryDecisions',
      'ruleDecisions',
      'pathExclusions',
      'severityFloors',
      'repositoryOverrides',
      'approvedWaiverRefs',
      'approvedSuppressionRefs',
      'actorRef',
      'auditRef'
    ])
  ) {
    return null;
  }
  const categoryDecisions = cloneCategoryDecisions(
    input.categoryDecisions
  );
  const ruleDecisions = cloneRuleDecisions(input.ruleDecisions);
  const pathExclusions = cloneArray(input.pathExclusions);
  const repositoryOverrides = cloneRepositoryOverrides(
    input.repositoryOverrides
  );
  const approvedWaiverRefs = cloneArray(input.approvedWaiverRefs);
  const approvedSuppressionRefs = cloneArray(
    input.approvedSuppressionRefs
  );
  const categoryDecisionDigest = digestCanonical(
    stableJson(categoryDecisions)
  );
  const ruleDecisionDigest = digestCanonical(stableJson(ruleDecisions));
  const pathExclusionDigest = digestCanonical(
    stableJson(pathExclusions)
  );
  const repositoryOverrideDigest = digestCanonical(
    stableJson(repositoryOverrides)
  );
  const approvedReferenceDigest = digestCanonical(
    stableJson({ approvedSuppressionRefs, approvedWaiverRefs })
  );
  const core: SastTenantRulePolicyCore = {
    version: SAST_TENANT_RULE_POLICY_VERSION,
    tenantId: input.tenantId,
    policyVersion: input.policyVersion,
    effectiveAt: input.effectiveAt,
    expiresAt: input.expiresAt,
    categoryDecisions,
    categoryDecisionDigest,
    ruleDecisions,
    ruleDecisionDigest,
    pathExclusions,
    pathExclusionDigest,
    severityFloors: { ...input.severityFloors },
    repositoryOverrides,
    repositoryOverrideDigest,
    approvedWaiverRefs,
    approvedSuppressionRefs,
    approvedReferenceDigest,
    actorRef: input.actorRef,
    auditRef: input.auditRef,
    source: 'TENANT_ADMIN_METADATA',
    immutable: true,
    executableRulesAccepted: false,
    cliFlagsAccepted: false,
    pluginsAccepted: false,
    arbitraryConfigurationAccepted: false,
    customerSourceStored: false,
    secretValueStored: false
  };
  if (!isTenantRulePolicyCoreValid(core, digestCanonical)) return null;
  const policyDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(policyDigest);
  if (!suffix) return null;
  const policy: SastTenantRulePolicy = {
    ...core,
    policyId: `sast-tenant-rule-policy://${suffix}`,
    policyDigest
  };
  return isSastTenantRulePolicyShapeValid(policy, digestCanonical)
    ? policy
    : null;
}

export function buildSastTenantRulePolicyResolution(input: {
  policy: Readonly<SastTenantRulePolicy>;
  context: Readonly<SastTenantRulePolicyResolutionContext>;
  selectedMetadata: readonly Readonly<SastRuleDefinitionMetadataBinding>[];
  approvedSemanticRuleIds: readonly string[];
  approvedCategories: readonly string[];
  digestCanonical: SastRulePolicyCanonicalDigester;
}): SastTenantRulePolicyResolutionReceipt | null {
  if (
    !isSastTenantRulePolicyShapeValid(
      input.policy,
      input.digestCanonical
    ) ||
    !isResolutionContextValid(input.context) ||
    !isCanonicalStringSet(
      input.approvedSemanticRuleIds,
      SAST_RULE_POLICY_LIMITS.maximumResolvedRules,
      isSemanticRuleId
    ) ||
    !isCanonicalStringSet(
      input.approvedCategories,
      SAST_RULE_POLICY_LIMITS.maximumCategoryDecisions,
      isCategory
    ) ||
    findSastTenantRulePolicyResolutionReasonCodes(input).length > 0
  ) {
    return null;
  }

  const repositoryOverride = input.policy.repositoryOverrides.find(
    (override) =>
      override.repositoryBindingId === input.context.repositoryBindingId
  );
  const categoryDecisions = new Map(
    input.policy.categoryDecisions.map((decision) => [
      decision.category,
      decision.state
    ])
  );
  const ruleDecisions = new Map(
    input.policy.ruleDecisions.map((decision) => [
      decision.ruleSemanticId,
      decision.state
    ])
  );
  const repositoryCategoryDecisions = new Map(
    (repositoryOverride?.categoryDecisions ?? []).map((decision) => [
      decision.category,
      decision.state
    ])
  );
  const repositoryRuleDecisions = new Map(
    (repositoryOverride?.ruleDecisions ?? []).map((decision) => [
      decision.ruleSemanticId,
      decision.state
    ])
  );
  const rules = input.selectedMetadata
    .map((binding): SastTenantRulePolicyResolvedRule => {
      const metadata = binding.metadata;
      const state: SastTenantRulePolicyState = [
        categoryDecisions.get(metadata.semanticIdentity.category),
        ruleDecisions.get(metadata.ruleSemanticId),
        repositoryCategoryDecisions.get(
          metadata.semanticIdentity.category
        ),
        repositoryRuleDecisions.get(metadata.ruleSemanticId)
      ].includes('DISABLED')
        ? 'DISABLED'
        : 'ENABLED';
      return {
        bindingId: binding.bindingId,
        bindingDigest: binding.bindingDigest,
        manifestId: binding.manifestId,
        manifestDigest: binding.manifestDigest,
        bundleDigest: binding.bundleDigest,
        ruleId: metadata.ruleId,
        ruleRevision: metadata.ruleRevision,
        ruleSemanticId: metadata.ruleSemanticId,
        metadataId: metadata.metadataId,
        metadataDigest: metadata.metadataDigest,
        semanticIdentityDigest:
          metadata.semanticIdentity.semanticIdentityDigest,
        category: metadata.semanticIdentity.category,
        tenantControl: metadata.semanticIdentity.tenantControl,
        state
      };
    })
    .sort(compareResolvedRules);
  if (
    rules.some(
      (rule) =>
        rule.tenantControl === 'MANDATORY' && rule.state === 'DISABLED'
    )
  ) {
    return null;
  }
  const manifestDigests = [
    ...new Set(rules.map((rule) => rule.manifestDigest))
  ].sort(compareStrings);
  const manifestSetDigest = input.digestCanonical(
    stableJson(manifestDigests)
  );
  const semanticMetadataSetDigest = input.digestCanonical(
    stableJson(
      rules.map((rule) => ({
        bindingDigest: rule.bindingDigest,
        metadataDigest: rule.metadataDigest,
        ruleSemanticId: rule.ruleSemanticId,
        semanticIdentityDigest: rule.semanticIdentityDigest
      }))
    )
  );
  const ruleResolutionDigest = input.digestCanonical(stableJson(rules));
  const enabledRuleSetDigest = input.digestCanonical(
    stableJson(
      rules
        .filter((rule) => rule.state === 'ENABLED')
        .map((rule) => ({
          bindingId: rule.bindingId,
          ruleSemanticId: rule.ruleSemanticId
        }))
    )
  );
  const disabledRuleSetDigest = input.digestCanonical(
    stableJson(
      rules
        .filter((rule) => rule.state === 'DISABLED')
        .map((rule) => ({
          bindingId: rule.bindingId,
          ruleSemanticId: rule.ruleSemanticId
        }))
    )
  );
  const pathExclusions = [
    ...input.policy.pathExclusions,
    ...(repositoryOverride?.pathExclusions ?? [])
  ]
    .filter((value, index, values) => values.indexOf(value) === index)
    .sort(compareStrings);
  const pathExclusionDigest = input.digestCanonical(
    stableJson(pathExclusions)
  );
  const severityFloors = {
    ...(repositoryOverride?.severityFloors ??
      input.policy.severityFloors)
  };
  const identityDigest = input.digestCanonical(
    stableJson({
      version: SAST_TENANT_RULE_POLICY_RESOLUTION_VERSION,
      policyDigest: input.policy.policyDigest,
      repositoryBindingId: input.context.repositoryBindingId,
      scannerSetDigest: input.context.scannerSetDigest,
      profileDigest: input.context.profileDigest,
      manifestSetDigest,
      semanticMetadataSetDigest
    })
  );
  const suffix = digestSuffix(identityDigest);
  if (!suffix) return null;
  const core = {
    version: SAST_TENANT_RULE_POLICY_RESOLUTION_VERSION,
    receiptId: `sast-tenant-rule-policy-resolution://${suffix}`,
    receiptIdentityDigest: identityDigest,
    policyId: input.policy.policyId,
    policyVersion: input.policy.policyVersion,
    policyDigest: input.policy.policyDigest,
    context: { ...input.context },
    manifestDigests,
    manifestSetDigest,
    semanticMetadataSetDigest,
    rules,
    ruleResolutionDigest,
    enabledRuleSetDigest,
    disabledRuleSetDigest,
    pathExclusions,
    pathExclusionDigest,
    severityFloors,
    policyMatched: true as const,
    manifestMetadataMatched: true as const,
    semanticIdentityVerified: true as const,
    mandatoryRulesPreserved: true as const,
    executableConfigurationAccepted: false as const,
    customerInputStored: false as const,
    evaluatedAt: input.context.evaluatedAt
  };
  const receipt: SastTenantRulePolicyResolutionReceipt = {
    ...core,
    receiptDigest: input.digestCanonical(stableJson(core))
  };
  return isSastTenantRulePolicyResolutionReceiptShapeValid(
    receipt,
    input.digestCanonical
  )
    ? receipt
    : null;
}

export function findSastTenantRulePolicyResolutionReasonCodes(input: {
  policy: Readonly<SastTenantRulePolicy>;
  context: Readonly<SastTenantRulePolicyResolutionContext>;
  selectedMetadata: readonly Readonly<SastRuleDefinitionMetadataBinding>[];
  approvedSemanticRuleIds: readonly string[];
  approvedCategories: readonly string[];
  digestCanonical: SastRulePolicyCanonicalDigester;
}): SastTenantRulePolicyResolutionReasonCode[] {
  const reasons: SastTenantRulePolicyResolutionReasonCode[] = [];
  const policy = input.policy;
  const context = input.context;
  if (
    !isSastTenantRulePolicyShapeValid(policy, input.digestCanonical) ||
    !isResolutionContextValid(context) ||
    policy.tenantId !== context.tenantId
  ) {
    reasons.push('POLICY_SCOPE_MISMATCH');
    return reasons;
  }
  if (Date.parse(context.evaluatedAt) < Date.parse(policy.effectiveAt)) {
    reasons.push('POLICY_NOT_EFFECTIVE');
  }
  if (Date.parse(context.evaluatedAt) >= Date.parse(policy.expiresAt)) {
    reasons.push('POLICY_EXPIRED');
  }
  const metadataValid =
    input.selectedMetadata.length > 0 &&
    input.selectedMetadata.length <=
      SAST_RULE_POLICY_LIMITS.maximumResolvedRules &&
    input.selectedMetadata.every((binding) =>
      isSastRuleDefinitionMetadataBindingShapeValid(
        binding,
        input.digestCanonical
      )
    ) &&
    input.selectedMetadata.every(
      (metadata, index, values) =>
        index === 0 || compareDefinitionMetadata(values[index - 1]!, metadata) < 0
    );
  if (!metadataValid) reasons.push('POLICY_METADATA_INVALID');
  const semanticIdentityDigests = new Map<string, string>();
  for (const binding of input.selectedMetadata) {
    const metadata = binding.metadata;
    const previous = semanticIdentityDigests.get(metadata.ruleSemanticId);
    if (
      previous &&
      previous !== metadata.semanticIdentity.semanticIdentityDigest
    ) {
      reasons.push('POLICY_SEMANTIC_IDENTITY_CONFLICT');
      break;
    }
    semanticIdentityDigests.set(
      metadata.ruleSemanticId,
      metadata.semanticIdentity.semanticIdentityDigest
    );
  }
  const approvedRules = new Set(input.approvedSemanticRuleIds);
  const approvedCategories = new Set(input.approvedCategories);
  const selectors = [
    ...policy.ruleDecisions,
    ...policy.repositoryOverrides.flatMap(
      (override) => override.ruleDecisions
    )
  ];
  const categorySelectors = [
    ...policy.categoryDecisions,
    ...policy.repositoryOverrides.flatMap(
      (override) => override.categoryDecisions
    )
  ];
  if (
    selectors.some((decision) => !approvedRules.has(decision.ruleSemanticId)) ||
    categorySelectors.some(
      (decision) => !approvedCategories.has(decision.category)
    )
  ) {
    reasons.push('POLICY_SELECTOR_UNKNOWN');
  }
  if (metadataValid && wouldDisableMandatoryRule(input)) {
    reasons.push('POLICY_MANDATORY_RULE_DISABLED');
  }
  return uniqueReasons(reasons);
}

export function isSastRuleSemanticIdentityShapeValid(
  value: unknown,
  digestCanonical: SastRulePolicyCanonicalDigester
): value is SastRuleSemanticIdentity {
  if (
    !hasExactKeys(value, [
      'version',
      'semanticIdentityId',
      'ruleSemanticId',
      'capability',
      'category',
      'languages',
      'formats',
      'vulnerabilityPredicateRef',
      'sourceKinds',
      'sinkKinds',
      'defaultSeverity',
      'defaultConfidence',
      'findingIdentityRef',
      'tenantControl',
      'semanticIdentityDigest'
    ])
  ) {
    return false;
  }
  const identity = value as unknown as SastRuleSemanticIdentity;
  const core = semanticIdentityCore(identity);
  return (
    isSemanticIdentityCoreValid(core) &&
    SEMANTIC_IDENTITY_ID_PATTERN.test(identity.semanticIdentityId) &&
    isDigest(identity.semanticIdentityDigest) &&
    identity.semanticIdentityDigest === digestCanonical(stableJson(core)) &&
    identity.semanticIdentityId ===
      `sast-rule-semantic-identity://${digestSuffix(identity.semanticIdentityDigest)}`
  );
}

export function isSastRuleDefinitionMetadataShapeValid(
  value: unknown,
  digestCanonical: SastRulePolicyCanonicalDigester
): value is SastRuleDefinitionMetadata {
  if (
    !hasExactKeys(value, [
      'version',
      'metadataId',
      'scanner',
      'ruleId',
      'ruleRevision',
      'ruleSemanticId',
      'semanticIdentity',
      'ownerRef',
      'cweIds',
      'owaspMappings',
      'documentationRef',
      'fixtureRefs',
      'introducedInBundleVersion',
      'firstSupportedScannerVersion',
      'lastSupportedScannerVersion',
      'deprecationState',
      'replacementSemanticRuleId',
      'source',
      'immutable',
      'executableRuleContentStored',
      'customerExecutableConfigAllowed',
      'customerSourceStored',
      'secretValueStored',
      'metadataDigest'
    ])
  ) {
    return false;
  }
  const metadata = value as unknown as SastRuleDefinitionMetadata;
  const core = definitionMetadataCore(metadata);
  return (
    isDefinitionMetadataCoreValid(core, digestCanonical) &&
    METADATA_ID_PATTERN.test(metadata.metadataId) &&
    isDigest(metadata.metadataDigest) &&
    metadata.metadataDigest === digestCanonical(stableJson(core)) &&
    metadata.metadataId ===
      `sast-rule-definition-metadata://${digestSuffix(metadata.metadataDigest)}`
  );
}

export function isSastRuleDefinitionMetadataBindingShapeValid(
  value: unknown,
  digestCanonical: SastRulePolicyCanonicalDigester
): value is SastRuleDefinitionMetadataBinding {
  if (
    !hasExactKeys(value, [
      'version',
      'bindingId',
      'bindingDigest',
      'manifestId',
      'manifestDigest',
      'bundleId',
      'bundleDigest',
      'scanner',
      'ruleId',
      'ruleRevision',
      'ruleSemanticId',
      'metadataId',
      'metadataDigest',
      'semanticIdentityDigest',
      'source',
      'immutable',
      'executableRuleContentStored',
      'customerExecutableConfigAllowed',
      'customerSourceStored',
      'secretValueStored',
      'metadata'
    ])
  ) {
    return false;
  }
  const binding =
    value as unknown as SastRuleDefinitionMetadataBinding;
  if (
    !isSastRuleDefinitionMetadataShapeValid(
      binding.metadata,
      digestCanonical
    )
  ) {
    return false;
  }
  const core = definitionMetadataBindingCore(binding);
  return (
    isDefinitionMetadataBindingCoreValid(core, binding.metadata) &&
    METADATA_BINDING_ID_PATTERN.test(binding.bindingId) &&
    isDigest(binding.bindingDigest) &&
    binding.bindingDigest === digestCanonical(stableJson(core)) &&
    binding.bindingId ===
      `sast-rule-definition-metadata-binding://${digestSuffix(binding.bindingDigest)}`
  );
}

export function isSastTenantRulePolicyShapeValid(
  value: unknown,
  digestCanonical: SastRulePolicyCanonicalDigester
): value is SastTenantRulePolicy {
  if (
    !hasExactKeys(value, [
      'version',
      'policyId',
      'tenantId',
      'policyVersion',
      'effectiveAt',
      'expiresAt',
      'categoryDecisions',
      'categoryDecisionDigest',
      'ruleDecisions',
      'ruleDecisionDigest',
      'pathExclusions',
      'pathExclusionDigest',
      'severityFloors',
      'repositoryOverrides',
      'repositoryOverrideDigest',
      'approvedWaiverRefs',
      'approvedSuppressionRefs',
      'approvedReferenceDigest',
      'actorRef',
      'auditRef',
      'source',
      'immutable',
      'executableRulesAccepted',
      'cliFlagsAccepted',
      'pluginsAccepted',
      'arbitraryConfigurationAccepted',
      'customerSourceStored',
      'secretValueStored',
      'policyDigest'
    ])
  ) {
    return false;
  }
  const policy = value as unknown as SastTenantRulePolicy;
  const core = tenantRulePolicyCore(policy);
  return (
    isTenantRulePolicyCoreValid(core, digestCanonical) &&
    POLICY_ID_PATTERN.test(policy.policyId) &&
    isDigest(policy.policyDigest) &&
    policy.policyDigest === digestCanonical(stableJson(core)) &&
    policy.policyId ===
      `sast-tenant-rule-policy://${digestSuffix(policy.policyDigest)}`
  );
}

export function isSastTenantRulePolicyResolutionReceiptShapeValid(
  value: unknown,
  digestCanonical: SastRulePolicyCanonicalDigester
): value is SastTenantRulePolicyResolutionReceipt {
  if (
    !hasExactKeys(value, [
      'version',
      'receiptId',
      'receiptIdentityDigest',
      'policyId',
      'policyVersion',
      'policyDigest',
      'context',
      'manifestDigests',
      'manifestSetDigest',
      'semanticMetadataSetDigest',
      'rules',
      'ruleResolutionDigest',
      'enabledRuleSetDigest',
      'disabledRuleSetDigest',
      'pathExclusions',
      'pathExclusionDigest',
      'severityFloors',
      'policyMatched',
      'manifestMetadataMatched',
      'semanticIdentityVerified',
      'mandatoryRulesPreserved',
      'executableConfigurationAccepted',
      'customerInputStored',
      'evaluatedAt',
      'receiptDigest'
    ])
  ) {
    return false;
  }
  const receipt =
    value as unknown as SastTenantRulePolicyResolutionReceipt;
  const rulesValid =
    Array.isArray(receipt.rules) &&
    receipt.rules.length > 0 &&
    receipt.rules.length <= SAST_RULE_POLICY_LIMITS.maximumResolvedRules &&
    receipt.rules.every(isResolvedRuleValid) &&
    receipt.rules.every(
      (rule, index, values) =>
        index === 0 || compareResolvedRules(values[index - 1]!, rule) < 0
    );
  if (
    !rulesValid ||
    !Array.isArray(receipt.manifestDigests) ||
    !Array.isArray(receipt.pathExclusions) ||
    !isResolutionContextValid(receipt.context) ||
    !isSeverityFloorsValid(receipt.severityFloors)
  ) {
    return false;
  }
  const core = resolutionReceiptCore(receipt);
  const derivedManifestDigests = [
    ...new Set(receipt.rules.map((rule) => rule.manifestDigest))
  ].sort(compareStrings);
  const derivedSemanticMetadataSet = receipt.rules.map((rule) => ({
    bindingDigest: rule.bindingDigest,
    metadataDigest: rule.metadataDigest,
    ruleSemanticId: rule.ruleSemanticId,
    semanticIdentityDigest: rule.semanticIdentityDigest
  }));
  const derivedIdentityDigest = digestCanonical(
    stableJson({
      version: SAST_TENANT_RULE_POLICY_RESOLUTION_VERSION,
      policyDigest: receipt.policyDigest,
      repositoryBindingId: receipt.context.repositoryBindingId,
      scannerSetDigest: receipt.context.scannerSetDigest,
      profileDigest: receipt.context.profileDigest,
      manifestSetDigest: receipt.manifestSetDigest,
      semanticMetadataSetDigest: receipt.semanticMetadataSetDigest
    })
  );
  return (
    receipt.version === SAST_TENANT_RULE_POLICY_RESOLUTION_VERSION &&
    RESOLUTION_ID_PATTERN.test(receipt.receiptId) &&
    isDigest(receipt.receiptIdentityDigest) &&
    receipt.receiptIdentityDigest === derivedIdentityDigest &&
    receipt.receiptId ===
      `sast-tenant-rule-policy-resolution://${digestSuffix(receipt.receiptIdentityDigest)}` &&
    POLICY_ID_PATTERN.test(receipt.policyId) &&
    VERSION_PATTERN.test(receipt.policyVersion) &&
    isDigest(receipt.policyDigest) &&
    isResolutionContextValid(receipt.context) &&
    receipt.evaluatedAt === receipt.context.evaluatedAt &&
    isCanonicalStringSet(
      receipt.manifestDigests,
      SAST_RULE_POLICY_LIMITS.maximumManifestDigests,
      isDigest
    ) &&
    stableJson(receipt.manifestDigests) ===
      stableJson(derivedManifestDigests) &&
    isDigest(receipt.manifestSetDigest) &&
    receipt.manifestSetDigest ===
      digestCanonical(stableJson(receipt.manifestDigests)) &&
    isDigest(receipt.semanticMetadataSetDigest) &&
    receipt.semanticMetadataSetDigest ===
      digestCanonical(stableJson(derivedSemanticMetadataSet)) &&
    rulesValid &&
    isDigest(receipt.ruleResolutionDigest) &&
    receipt.ruleResolutionDigest === digestCanonical(stableJson(receipt.rules)) &&
    isDigest(receipt.enabledRuleSetDigest) &&
    receipt.enabledRuleSetDigest ===
      digestCanonical(
        stableJson(
          receipt.rules
            .filter((rule) => rule.state === 'ENABLED')
            .map((rule) => ({
              bindingId: rule.bindingId,
              ruleSemanticId: rule.ruleSemanticId
            }))
        )
      ) &&
    isDigest(receipt.disabledRuleSetDigest) &&
    receipt.disabledRuleSetDigest ===
      digestCanonical(
        stableJson(
          receipt.rules
            .filter((rule) => rule.state === 'DISABLED')
            .map((rule) => ({
              bindingId: rule.bindingId,
              ruleSemanticId: rule.ruleSemanticId
            }))
        )
      ) &&
    isCanonicalStringSet(
      receipt.pathExclusions,
      SAST_RULE_POLICY_LIMITS.maximumPathExclusions * 2,
      isSafePathPrefix
    ) &&
    isDigest(receipt.pathExclusionDigest) &&
    receipt.pathExclusionDigest ===
      digestCanonical(stableJson(receipt.pathExclusions)) &&
    isSeverityFloorsValid(receipt.severityFloors) &&
    receipt.policyMatched === true &&
    receipt.manifestMetadataMatched === true &&
    receipt.semanticIdentityVerified === true &&
    receipt.mandatoryRulesPreserved === true &&
    receipt.executableConfigurationAccepted === false &&
    receipt.customerInputStored === false &&
    !receipt.rules.some(
      (rule) =>
        rule.tenantControl === 'MANDATORY' && rule.state === 'DISABLED'
    ) &&
    isDigest(receipt.receiptDigest) &&
    receipt.receiptDigest === digestCanonical(stableJson(core))
  );
}

export function isVerifiedSastTenantRulePolicyDescriptorValid(
  value: unknown
): value is VerifiedSastTenantRulePolicyDescriptor {
  return (
    hasExactKeys(value, [
      'policyId',
      'policyVersion',
      'policyDigest',
      'resolutionReceiptId',
      'resolutionIdentityDigest',
      'resolutionReceiptDigest',
      'semanticMetadataSetDigest',
      'ruleResolutionDigest',
      'enabledRuleSetDigest',
      'disabledRuleSetDigest',
      'pathExclusionDigest',
      'severityFloors'
    ]) &&
    POLICY_ID_PATTERN.test(value.policyId as string) &&
    value.policyId ===
      `sast-tenant-rule-policy://${digestSuffix(value.policyDigest)}` &&
    VERSION_PATTERN.test(value.policyVersion as string) &&
    isDigest(value.policyDigest) &&
    RESOLUTION_ID_PATTERN.test(value.resolutionReceiptId as string) &&
    isDigest(value.resolutionIdentityDigest) &&
    value.resolutionReceiptId ===
      `sast-tenant-rule-policy-resolution://${digestSuffix(value.resolutionIdentityDigest)}` &&
    isDigest(value.resolutionReceiptDigest) &&
    isDigest(value.semanticMetadataSetDigest) &&
    isDigest(value.ruleResolutionDigest) &&
    isDigest(value.enabledRuleSetDigest) &&
    isDigest(value.disabledRuleSetDigest) &&
    isDigest(value.pathExclusionDigest) &&
    isSeverityFloorsValid(value.severityFloors)
  );
}

export function toVerifiedSastTenantRulePolicyDescriptor(
  receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
): VerifiedSastTenantRulePolicyDescriptor {
  return {
    policyId: receipt.policyId,
    policyVersion: receipt.policyVersion,
    policyDigest: receipt.policyDigest,
    resolutionReceiptId: receipt.receiptId,
    resolutionIdentityDigest: receipt.receiptIdentityDigest,
    resolutionReceiptDigest: receipt.receiptDigest,
    semanticMetadataSetDigest: receipt.semanticMetadataSetDigest,
    ruleResolutionDigest: receipt.ruleResolutionDigest,
    enabledRuleSetDigest: receipt.enabledRuleSetDigest,
    disabledRuleSetDigest: receipt.disabledRuleSetDigest,
    pathExclusionDigest: receipt.pathExclusionDigest,
    severityFloors: { ...receipt.severityFloors }
  };
}

export function canonicalizeSastRuleDefinitionMetadata(
  value: Readonly<SastRuleDefinitionMetadata>
): string {
  return stableJson(value);
}

export function canonicalizeSastRuleDefinitionMetadataBinding(
  value: Readonly<SastRuleDefinitionMetadataBinding>
): string {
  return stableJson(value);
}

export function canonicalizeSastTenantRulePolicy(
  value: Readonly<SastTenantRulePolicy>
): string {
  return stableJson(value);
}

export function canonicalizeSastTenantRulePolicyResolutionReceipt(
  value: Readonly<SastTenantRulePolicyResolutionReceipt>
): string {
  return stableJson(value);
}

function isSemanticIdentityCoreValid(
  identity: Readonly<SastRuleSemanticIdentityCore>
): boolean {
  return (
    identity.version === SAST_RULE_SEMANTIC_IDENTITY_VERSION &&
    isSemanticRuleId(identity.ruleSemanticId) &&
    SAST_RULE_METADATA_CAPABILITIES.includes(identity.capability) &&
    isCategory(identity.category) &&
    isCanonicalStringSet(
      identity.languages,
      SAST_RULE_POLICY_LIMITS.maximumLanguages,
      isLanguageOrFormat
    ) &&
    isCanonicalStringSet(
      identity.formats,
      SAST_RULE_POLICY_LIMITS.maximumFormats,
      isLanguageOrFormat
    ) &&
    identity.languages.length + identity.formats.length > 0 &&
    isDigestBoundReference(identity.vulnerabilityPredicateRef) &&
    isCanonicalStringSet(
      identity.sourceKinds,
      SAST_RULE_POLICY_LIMITS.maximumTaxonomyValues,
      isTaxonomy
    ) &&
    isCanonicalStringSet(
      identity.sinkKinds,
      SAST_RULE_POLICY_LIMITS.maximumTaxonomyValues,
      isTaxonomy
    ) &&
    SEVERITIES.includes(identity.defaultSeverity) &&
    SAST_RULE_CONFIDENCE_LEVELS.includes(identity.defaultConfidence) &&
    isDigestBoundReference(identity.findingIdentityRef) &&
    SAST_RULE_TENANT_CONTROLS.includes(identity.tenantControl)
  );
}

function isDefinitionMetadataCoreValid(
  metadata: Readonly<SastRuleDefinitionMetadataCore>,
  digestCanonical: SastRulePolicyCanonicalDigester
): boolean {
  return (
    metadata.version === SAST_RULE_DEFINITION_METADATA_VERSION &&
    (metadata.scanner === 'OPENGREP' || metadata.scanner === 'TRIVY') &&
    isBoundedIdentifier(metadata.ruleId) &&
    isBoundedIdentifier(metadata.ruleRevision) &&
    isSemanticRuleId(metadata.ruleSemanticId) &&
    isSastRuleSemanticIdentityShapeValid(
      metadata.semanticIdentity,
      digestCanonical
    ) &&
    metadata.ruleSemanticId === metadata.semanticIdentity.ruleSemanticId &&
    isDigestBoundReference(metadata.ownerRef) &&
    ((metadata.scanner === 'OPENGREP' &&
      metadata.semanticIdentity.capability === 'SAST') ||
      (metadata.scanner === 'TRIVY' &&
        (metadata.semanticIdentity.capability === 'SECRET_DETECTION' ||
          metadata.semanticIdentity.capability ===
            'IAC_MISCONFIGURATION'))) &&
    isCanonicalStringSet(
      metadata.cweIds,
      SAST_RULE_POLICY_LIMITS.maximumMappings,
      (value) => CWE_PATTERN.test(value)
    ) &&
    isCanonicalStringSet(
      metadata.owaspMappings,
      SAST_RULE_POLICY_LIMITS.maximumMappings,
      (value) => OWASP_PATTERN.test(value)
    ) &&
    isDigestBoundReference(metadata.documentationRef) &&
    isCanonicalStringSet(
      metadata.fixtureRefs,
      SAST_RULE_POLICY_LIMITS.maximumFixtureReferences,
      isDigestBoundReference
    ) &&
    metadata.fixtureRefs.length > 0 &&
    isBoundedIdentifier(metadata.introducedInBundleVersion) &&
    SEMANTIC_VERSION_PATTERN.test(metadata.introducedInBundleVersion) &&
    isBoundedIdentifier(metadata.firstSupportedScannerVersion) &&
    SEMANTIC_VERSION_PATTERN.test(metadata.firstSupportedScannerVersion) &&
    (metadata.lastSupportedScannerVersion === null ||
      (isBoundedIdentifier(metadata.lastSupportedScannerVersion) &&
        SEMANTIC_VERSION_PATTERN.test(metadata.lastSupportedScannerVersion) &&
        compareSastRuleSemanticVersions(
          metadata.lastSupportedScannerVersion,
          metadata.firstSupportedScannerVersion
        )! >= 0)) &&
    SAST_RULE_DEPRECATION_STATES.includes(metadata.deprecationState) &&
    ((metadata.deprecationState === 'ACTIVE' &&
      metadata.replacementSemanticRuleId === null) ||
      (metadata.deprecationState === 'DEPRECATED' &&
        (metadata.replacementSemanticRuleId === null ||
          (isSemanticRuleId(metadata.replacementSemanticRuleId) &&
            metadata.replacementSemanticRuleId !==
              metadata.ruleSemanticId))) ||
      (metadata.deprecationState === 'RETIRED' &&
        typeof metadata.replacementSemanticRuleId === 'string' &&
        isSemanticRuleId(metadata.replacementSemanticRuleId) &&
        metadata.replacementSemanticRuleId !== metadata.ruleSemanticId)) &&
    metadata.source === 'PLATFORM_MANAGED' &&
    metadata.immutable === true &&
    metadata.executableRuleContentStored === false &&
    metadata.customerExecutableConfigAllowed === false &&
    metadata.customerSourceStored === false &&
    metadata.secretValueStored === false
  );
}

function isDefinitionMetadataBindingCoreValid(
  binding: Readonly<SastRuleDefinitionMetadataBindingCore>,
  metadata: Readonly<SastRuleDefinitionMetadata>
): boolean {
  return (
    binding.version === SAST_RULE_DEFINITION_METADATA_BINDING_VERSION &&
    MANIFEST_ID_PATTERN.test(binding.manifestId) &&
    isDigest(binding.manifestDigest) &&
    BUNDLE_ID_PATTERN.test(binding.bundleId) &&
    isDigest(binding.bundleDigest) &&
    binding.scanner === metadata.scanner &&
    binding.ruleId === metadata.ruleId &&
    binding.ruleRevision === metadata.ruleRevision &&
    binding.ruleSemanticId === metadata.ruleSemanticId &&
    binding.metadataId === metadata.metadataId &&
    binding.metadataDigest === metadata.metadataDigest &&
    binding.semanticIdentityDigest ===
      metadata.semanticIdentity.semanticIdentityDigest &&
    binding.source === 'PLATFORM_MANAGED' &&
    binding.immutable === true &&
    binding.executableRuleContentStored === false &&
    binding.customerExecutableConfigAllowed === false &&
    binding.customerSourceStored === false &&
    binding.secretValueStored === false
  );
}

function isTenantRulePolicyCoreValid(
  policy: Readonly<SastTenantRulePolicyCore>,
  digestCanonical: SastRulePolicyCanonicalDigester
): boolean {
  const effectiveAt = Date.parse(policy.effectiveAt);
  const expiresAt = Date.parse(policy.expiresAt);
  return (
    policy.version === SAST_TENANT_RULE_POLICY_VERSION &&
    isResourceId(policy.tenantId) &&
    VERSION_PATTERN.test(policy.policyVersion) &&
    isIsoInstant(policy.effectiveAt) &&
    isIsoInstant(policy.expiresAt) &&
    expiresAt > effectiveAt &&
    expiresAt - effectiveAt <=
      SAST_RULE_POLICY_LIMITS.maximumPolicyLifetimeMilliseconds &&
    isCategoryDecisionsValid(policy.categoryDecisions) &&
    isDigest(policy.categoryDecisionDigest) &&
    policy.categoryDecisionDigest ===
      digestCanonical(stableJson(policy.categoryDecisions)) &&
    isRuleDecisionsValid(policy.ruleDecisions) &&
    isDigest(policy.ruleDecisionDigest) &&
    policy.ruleDecisionDigest ===
      digestCanonical(stableJson(policy.ruleDecisions)) &&
    isCanonicalStringSet(
      policy.pathExclusions,
      SAST_RULE_POLICY_LIMITS.maximumPathExclusions,
      isSafePathPrefix
    ) &&
    isDigest(policy.pathExclusionDigest) &&
    policy.pathExclusionDigest ===
      digestCanonical(stableJson(policy.pathExclusions)) &&
    isSeverityFloorsValid(policy.severityFloors) &&
    isRepositoryOverridesValid(policy.repositoryOverrides) &&
    policy.repositoryOverrides.every(
      (override) =>
        severityRank(override.severityFloors.dashboard) >=
          severityRank(policy.severityFloors.dashboard) &&
        severityRank(override.severityFloors.publication) >=
          severityRank(policy.severityFloors.publication)
    ) &&
    isDigest(policy.repositoryOverrideDigest) &&
    policy.repositoryOverrideDigest ===
      digestCanonical(stableJson(policy.repositoryOverrides)) &&
    isCanonicalStringSet(
      policy.approvedWaiverRefs,
      SAST_RULE_POLICY_LIMITS.maximumApprovedReferences,
      (value) => WAIVER_REFERENCE_PATTERN.test(value)
    ) &&
    isCanonicalStringSet(
      policy.approvedSuppressionRefs,
      SAST_RULE_POLICY_LIMITS.maximumApprovedReferences,
      (value) => SUPPRESSION_REFERENCE_PATTERN.test(value)
    ) &&
    isDigest(policy.approvedReferenceDigest) &&
    policy.approvedReferenceDigest ===
      digestCanonical(
        stableJson({
          approvedSuppressionRefs: policy.approvedSuppressionRefs,
          approvedWaiverRefs: policy.approvedWaiverRefs
        })
      ) &&
    typeof policy.actorRef === 'string' &&
    utf8ByteLength(policy.actorRef) <= SAST_RULE_POLICY_LIMITS.referenceBytes &&
    ACTOR_REFERENCE_PATTERN.test(policy.actorRef) &&
    isDigestBoundReference(policy.auditRef) &&
    policy.source === 'TENANT_ADMIN_METADATA' &&
    policy.immutable === true &&
    policy.executableRulesAccepted === false &&
    policy.cliFlagsAccepted === false &&
    policy.pluginsAccepted === false &&
    policy.arbitraryConfigurationAccepted === false &&
    policy.customerSourceStored === false &&
    policy.secretValueStored === false
  );
}

function isCategoryDecisionsValid(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= SAST_RULE_POLICY_LIMITS.maximumCategoryDecisions &&
    value.every(
      (decision, index) =>
        hasExactKeys(decision, ['category', 'state']) &&
        isCategory(decision.category) &&
        SAST_TENANT_RULE_POLICY_STATES.includes(
          decision.state as SastTenantRulePolicyState
        ) &&
        (index === 0 || value[index - 1].category < decision.category)
    )
  );
}

function isRuleDecisionsValid(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= SAST_RULE_POLICY_LIMITS.maximumRuleDecisions &&
    value.every(
      (decision, index) =>
        hasExactKeys(decision, ['ruleSemanticId', 'state']) &&
        isSemanticRuleId(decision.ruleSemanticId) &&
        SAST_TENANT_RULE_POLICY_STATES.includes(
          decision.state as SastTenantRulePolicyState
        ) &&
        (index === 0 ||
          value[index - 1].ruleSemanticId < decision.ruleSemanticId)
    )
  );
}

function isRepositoryOverridesValid(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= SAST_RULE_POLICY_LIMITS.maximumRepositoryOverrides &&
    value.every(
      (override, index) =>
        hasExactKeys(override, [
          'repositoryBindingId',
          'categoryDecisions',
          'ruleDecisions',
          'pathExclusions',
          'severityFloors'
        ]) &&
        isResourceId(override.repositoryBindingId) &&
        isCategoryDecisionsValid(override.categoryDecisions) &&
        isRuleDecisionsValid(override.ruleDecisions) &&
        isCanonicalStringSet(
          override.pathExclusions,
          SAST_RULE_POLICY_LIMITS.maximumPathExclusions,
          isSafePathPrefix
        ) &&
        isSeverityFloorsValid(override.severityFloors) &&
        (index === 0 ||
          value[index - 1].repositoryBindingId <
            override.repositoryBindingId)
    )
  );
}

function isSeverityFloorsValid(
  value: unknown
): value is SastTenantRulePolicySeverityFloors {
  if (!hasExactKeys(value, ['dashboard', 'publication'])) return false;
  const floors =
    value as unknown as SastTenantRulePolicySeverityFloors;
  return (
    SEVERITIES.includes(floors.dashboard) &&
    SEVERITIES.includes(floors.publication) &&
    severityRank(floors.dashboard) >=
      severityRank(SAST_PLATFORM_RULE_POLICY_SEVERITY_FLOORS.dashboard) &&
    severityRank(floors.publication) >=
      severityRank(
        SAST_PLATFORM_RULE_POLICY_SEVERITY_FLOORS.publication
      ) &&
    severityRank(floors.publication) >= severityRank(floors.dashboard)
  );
}

function isResolutionContextValid(
  value: unknown
): value is SastTenantRulePolicyResolutionContext {
  if (
    !hasExactKeys(value, [
      'tenantId',
      'repositoryBindingId',
      'scannerSetDigest',
      'profileId',
      'profileDigest',
      'evaluatedAt'
    ])
  ) {
    return false;
  }
  const context =
    value as unknown as SastTenantRulePolicyResolutionContext;
  return (
    isResourceId(context.tenantId) &&
    isResourceId(context.repositoryBindingId) &&
    isDigest(context.scannerSetDigest) &&
    PROFILES.includes(context.profileId) &&
    isDigest(context.profileDigest) &&
    isIsoInstant(context.evaluatedAt)
  );
}

function isResolvedRuleValid(
  value: unknown
): value is SastTenantRulePolicyResolvedRule {
  if (
    !hasExactKeys(value, [
      'bindingId',
      'bindingDigest',
      'manifestId',
      'manifestDigest',
      'bundleDigest',
      'ruleId',
      'ruleRevision',
      'ruleSemanticId',
      'metadataId',
      'metadataDigest',
      'semanticIdentityDigest',
      'category',
      'tenantControl',
      'state'
    ])
  ) {
    return false;
  }
  const rule = value as unknown as SastTenantRulePolicyResolvedRule;
  return (
    METADATA_BINDING_ID_PATTERN.test(rule.bindingId) &&
    isDigest(rule.bindingDigest) &&
    MANIFEST_ID_PATTERN.test(rule.manifestId) &&
    isDigest(rule.manifestDigest) &&
    isDigest(rule.bundleDigest) &&
    isBoundedIdentifier(rule.ruleId) &&
    isBoundedIdentifier(rule.ruleRevision) &&
    isSemanticRuleId(rule.ruleSemanticId) &&
    METADATA_ID_PATTERN.test(rule.metadataId) &&
    isDigest(rule.metadataDigest) &&
    isDigest(rule.semanticIdentityDigest) &&
    isCategory(rule.category) &&
    SAST_RULE_TENANT_CONTROLS.includes(rule.tenantControl) &&
    SAST_TENANT_RULE_POLICY_STATES.includes(rule.state)
  );
}

function wouldDisableMandatoryRule(input: {
  policy: Readonly<SastTenantRulePolicy>;
  context: Readonly<SastTenantRulePolicyResolutionContext>;
  selectedMetadata: readonly Readonly<SastRuleDefinitionMetadataBinding>[];
}): boolean {
  const override = input.policy.repositoryOverrides.find(
    (candidate) =>
      candidate.repositoryBindingId === input.context.repositoryBindingId
  );
  const category = new Map(
    input.policy.categoryDecisions.map((decision) => [
      decision.category,
      decision.state
    ])
  );
  const rules = new Map(
    input.policy.ruleDecisions.map((decision) => [
      decision.ruleSemanticId,
      decision.state
    ])
  );
  const repositoryCategory = new Map(
    (override?.categoryDecisions ?? []).map((decision) => [
      decision.category,
      decision.state
    ])
  );
  const repositoryRules = new Map(
    (override?.ruleDecisions ?? []).map((decision) => [
      decision.ruleSemanticId,
      decision.state
    ])
  );
  return input.selectedMetadata.some((binding) => {
    const metadata = binding.metadata;
    if (metadata.semanticIdentity.tenantControl !== 'MANDATORY') {
      return false;
    }
    return [
      category.get(metadata.semanticIdentity.category),
      rules.get(metadata.ruleSemanticId),
      repositoryCategory.get(metadata.semanticIdentity.category),
      repositoryRules.get(metadata.ruleSemanticId)
    ].includes('DISABLED');
  });
}

function semanticIdentityCore(
  identity: Readonly<SastRuleSemanticIdentity>
): SastRuleSemanticIdentityCore {
  return {
    version: identity.version,
    ruleSemanticId: identity.ruleSemanticId,
    capability: identity.capability,
    category: identity.category,
    languages: [...identity.languages],
    formats: [...identity.formats],
    vulnerabilityPredicateRef: identity.vulnerabilityPredicateRef,
    sourceKinds: [...identity.sourceKinds],
    sinkKinds: [...identity.sinkKinds],
    defaultSeverity: identity.defaultSeverity,
    defaultConfidence: identity.defaultConfidence,
    findingIdentityRef: identity.findingIdentityRef,
    tenantControl: identity.tenantControl
  };
}

function definitionMetadataCore(
  metadata: Readonly<SastRuleDefinitionMetadata>
): SastRuleDefinitionMetadataCore {
  return {
    version: metadata.version,
    scanner: metadata.scanner,
    ruleId: metadata.ruleId,
    ruleRevision: metadata.ruleRevision,
    ruleSemanticId: metadata.ruleSemanticId,
    semanticIdentity: {
      ...metadata.semanticIdentity,
      languages: [...metadata.semanticIdentity.languages],
      formats: [...metadata.semanticIdentity.formats],
      sourceKinds: [...metadata.semanticIdentity.sourceKinds],
      sinkKinds: [...metadata.semanticIdentity.sinkKinds]
    },
    ownerRef: metadata.ownerRef,
    cweIds: [...metadata.cweIds],
    owaspMappings: [...metadata.owaspMappings],
    documentationRef: metadata.documentationRef,
    fixtureRefs: [...metadata.fixtureRefs],
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

function definitionMetadataBindingCore(
  binding: Readonly<SastRuleDefinitionMetadataBinding>
): SastRuleDefinitionMetadataBindingCore {
  return {
    version: binding.version,
    manifestId: binding.manifestId,
    manifestDigest: binding.manifestDigest,
    bundleId: binding.bundleId,
    bundleDigest: binding.bundleDigest,
    scanner: binding.scanner,
    ruleId: binding.ruleId,
    ruleRevision: binding.ruleRevision,
    ruleSemanticId: binding.ruleSemanticId,
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

function cloneDefinitionMetadata(
  metadata: Readonly<SastRuleDefinitionMetadata>
): SastRuleDefinitionMetadata {
  return {
    ...metadata,
    semanticIdentity: {
      ...metadata.semanticIdentity,
      languages: [...metadata.semanticIdentity.languages],
      formats: [...metadata.semanticIdentity.formats],
      sourceKinds: [...metadata.semanticIdentity.sourceKinds],
      sinkKinds: [...metadata.semanticIdentity.sinkKinds]
    },
    cweIds: [...metadata.cweIds],
    owaspMappings: [...metadata.owaspMappings],
    fixtureRefs: [...metadata.fixtureRefs]
  };
}

function tenantRulePolicyCore(
  policy: Readonly<SastTenantRulePolicy>
): SastTenantRulePolicyCore {
  return {
    version: policy.version,
    tenantId: policy.tenantId,
    policyVersion: policy.policyVersion,
    effectiveAt: policy.effectiveAt,
    expiresAt: policy.expiresAt,
    categoryDecisions: cloneCategoryDecisions(policy.categoryDecisions),
    categoryDecisionDigest: policy.categoryDecisionDigest,
    ruleDecisions: cloneRuleDecisions(policy.ruleDecisions),
    ruleDecisionDigest: policy.ruleDecisionDigest,
    pathExclusions: [...policy.pathExclusions],
    pathExclusionDigest: policy.pathExclusionDigest,
    severityFloors: { ...policy.severityFloors },
    repositoryOverrides: cloneRepositoryOverrides(
      policy.repositoryOverrides
    ),
    repositoryOverrideDigest: policy.repositoryOverrideDigest,
    approvedWaiverRefs: [...policy.approvedWaiverRefs],
    approvedSuppressionRefs: [...policy.approvedSuppressionRefs],
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

function resolutionReceiptCore(
  receipt: Readonly<SastTenantRulePolicyResolutionReceipt>
): Omit<SastTenantRulePolicyResolutionReceipt, 'receiptDigest'> {
  const mutable = {
    ...receipt
  } as Partial<SastTenantRulePolicyResolutionReceipt>;
  delete mutable.receiptDigest;
  const core = mutable as Omit<
    SastTenantRulePolicyResolutionReceipt,
    'receiptDigest'
  >;
  return {
    ...core,
    context: { ...core.context },
    manifestDigests: [...core.manifestDigests],
    rules: core.rules.map((rule) => ({ ...rule })),
    pathExclusions: [...core.pathExclusions],
    severityFloors: { ...core.severityFloors }
  };
}

function cloneCategoryDecisions(
  value: readonly Readonly<SastTenantRuleCategoryDecision>[]
): SastTenantRuleCategoryDecision[] {
  return Array.isArray(value)
    ? value.map((decision) => ({ ...decision }))
    : [];
}

function cloneRuleDecisions(
  value: readonly Readonly<SastTenantRuleDecision>[]
): SastTenantRuleDecision[] {
  return Array.isArray(value)
    ? value.map((decision) => ({ ...decision }))
    : [];
}

function cloneRepositoryOverrides(
  value: readonly Readonly<SastTenantRulePolicyRepositoryOverride>[]
): SastTenantRulePolicyRepositoryOverride[] {
  return Array.isArray(value)
    ? value.map((override) => ({
        repositoryBindingId: override.repositoryBindingId,
        categoryDecisions: cloneCategoryDecisions(
          override.categoryDecisions
        ),
        ruleDecisions: cloneRuleDecisions(override.ruleDecisions),
        pathExclusions: cloneArray(override.pathExclusions),
        severityFloors: { ...override.severityFloors }
      }))
    : [];
}

function cloneArray<T>(value: readonly T[]): T[] {
  return Array.isArray(value) ? [...value] : [];
}

function compareDefinitionMetadata(
  left: Readonly<SastRuleDefinitionMetadataBinding>,
  right: Readonly<SastRuleDefinitionMetadataBinding>
): number {
  return compareStrings(
    `${left.manifestId}\u0000${left.ruleId}\u0000${left.bindingDigest}`,
    `${right.manifestId}\u0000${right.ruleId}\u0000${right.bindingDigest}`
  );
}

function compareResolvedRules(
  left: Readonly<SastTenantRulePolicyResolvedRule>,
  right: Readonly<SastTenantRulePolicyResolvedRule>
): number {
  return compareStrings(
    `${left.ruleSemanticId}\u0000${left.manifestId}\u0000${left.ruleId}`,
    `${right.ruleSemanticId}\u0000${right.manifestId}\u0000${right.ruleId}`
  );
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isCanonicalStringSet<T extends string>(
  value: unknown,
  maximum: number,
  predicate: (candidate: T) => boolean
): value is T[] {
  return (
    Array.isArray(value) &&
    value.length <= maximum &&
    value.every(
      (candidate, index) =>
        typeof candidate === 'string' &&
        predicate(candidate as T) &&
        (index === 0 || value[index - 1] < candidate)
    )
  );
}

function isSemanticRuleId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.normalize('NFC') === value &&
    SEMANTIC_RULE_ID_PATTERN.test(value)
  );
}

function isCategory(value: unknown): value is string {
  return typeof value === 'string' && CATEGORY_PATTERN.test(value);
}

function isTaxonomy(value: unknown): value is string {
  return typeof value === 'string' && TAXONOMY_PATTERN.test(value);
}

function isLanguageOrFormat(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.normalize('NFC') === value &&
    LANGUAGE_FORMAT_PATTERN.test(value)
  );
}

function isBoundedIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    utf8ByteLength(value) <= SAST_RULE_POLICY_LIMITS.identifierBytes &&
    value.normalize('NFC') === value &&
    !hasUnsafeControl(value)
  );
}

function isSafePathPrefix(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    utf8ByteLength(value) > 1_024 ||
    value.normalize('NFC') !== value ||
    hasUnsafeControl(value) ||
    value.startsWith('/') ||
    value.endsWith('/') ||
    value.includes('\\') ||
    [...value].some((character) => '*?[]{}()|'.includes(character))
  ) {
    return false;
  }
  const segments = value.split('/');
  return segments.every(
    (segment) => segment.length > 0 && segment !== '.' && segment !== '..'
  );
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    utf8ByteLength(value) <= SAST_RULE_POLICY_LIMITS.referenceBytes &&
    value.normalize('NFC') === value &&
    !/^https?:\/\//iu.test(value) &&
    DIGEST_BOUND_REFERENCE_PATTERN.test(value)
  );
}

function isResourceId(value: unknown): value is string {
  return typeof value === 'string' && RESOURCE_ID_PATTERN.test(value);
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function utf8ByteLength(value: string): number {
  return UTF8_ENCODER.encode(value).byteLength;
}

function digestSuffix(value: unknown): string | null {
  return isDigest(value) ? value.slice('sha256:'.length) : null;
}

function isIsoInstant(value: unknown): value is string {
  if (typeof value !== 'string' || !ISO_INSTANT_PATTERN.test(value)) {
    return false;
  }
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function severityRank(value: FindingSeverity): number {
  return SEVERITIES.length - SEVERITIES.indexOf(value);
}

export function compareSastRuleSemanticVersions(
  left: string,
  right: string
): number | null {
  if (
    !isBoundedIdentifier(left) ||
    !isBoundedIdentifier(right) ||
    !SEMANTIC_VERSION_PATTERN.test(left) ||
    !SEMANTIC_VERSION_PATTERN.test(right)
  ) {
    return null;
  }
  const leftSeparator = left.indexOf('-');
  const rightSeparator = right.indexOf('-');
  const leftCore = (leftSeparator < 0 ? left : left.slice(0, leftSeparator))
    .split('.')
    .map((value) => BigInt(value));
  const rightCore = (
    rightSeparator < 0 ? right : right.slice(0, rightSeparator)
  )
    .split('.')
    .map((value) => BigInt(value));
  for (let index = 0; index < 3; index += 1) {
    if (leftCore[index]! < rightCore[index]!) return -1;
    if (leftCore[index]! > rightCore[index]!) return 1;
  }
  if (leftSeparator < 0 && rightSeparator < 0) return 0;
  if (leftSeparator < 0) return 1;
  if (rightSeparator < 0) return -1;
  const leftPre = left.slice(leftSeparator + 1).split(/[.-]/u);
  const rightPre = right.slice(rightSeparator + 1).split(/[.-]/u);
  const maximum = Math.max(leftPre.length, rightPre.length);
  for (let index = 0; index < maximum; index += 1) {
    const leftValue = leftPre[index];
    const rightValue = rightPre[index];
    if (leftValue === undefined) return -1;
    if (rightValue === undefined) return 1;
    if (leftValue === rightValue) continue;
    const leftNumeric = /^\d+$/u.test(leftValue);
    const rightNumeric = /^\d+$/u.test(rightValue);
    if (leftNumeric && rightNumeric) {
      const leftNumber = BigInt(leftValue);
      const rightNumber = BigInt(rightValue);
      return leftNumber < rightNumber ? -1 : 1;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftValue < rightValue ? -1 : 1;
  }
  return 0;
}

function hasUnsafeControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x2028 ||
      codePoint === 0x2029
    ) {
      return true;
    }
  }
  return false;
}

function hasExactKeys(
  value: unknown,
  keys: readonly string[]
): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort(compareStrings);
  const expected = [...keys].sort(compareStrings);
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function uniqueReasons(
  values: readonly SastTenantRulePolicyResolutionReasonCode[]
): SastTenantRulePolicyResolutionReasonCode[] {
  return SAST_TENANT_RULE_POLICY_RESOLUTION_REASON_CODES.filter((reason) =>
    values.includes(reason)
  );
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
