import type {
  RuleBundleRuleDescriptor,
  RuleBundleState,
  SastProfileId
} from './sast-runtime';

export const SAST_RULE_BUNDLE_MANIFEST_VERSION =
  'sast-rule-bundle-manifest-v1' as const;
export const SAST_RULE_BUNDLE_SUPPLY_CHAIN_ATTESTATION_VERSION =
  'sast-rule-bundle-supply-chain-attestation-v1' as const;
export const SAST_RULE_BUNDLE_COMPATIBILITY_RECEIPT_VERSION =
  'sast-rule-bundle-compatibility-receipt-v1' as const;

export const SAST_RULE_BUNDLE_SELECTABLE_STATES = [
  'CANARY',
  'ACTIVE'
] as const satisfies readonly RuleBundleState[];

export const SAST_RULE_BUNDLE_MANIFEST_LIMITS = Object.freeze({
  identifierBytes: 512,
  referenceBytes: 2_048,
  maximumMembers: 25_000,
  maximumRules: 25_000,
  maximumCompatibilityValues: 64
});

const PROFILE_IDS = [
  'JAVA_FAST_V1',
  'JAVA_DEEP_V1',
  'COMMON_DEEP_V1'
] as const satisfies readonly SastProfileId[];

const MANIFEST_ID_PATTERN =
  /^sast-rule-bundle-manifest:\/\/[a-f0-9]{64}$/u;
const VERIFICATION_ID_PATTERN =
  /^sast-rule-bundle-verification:\/\/[a-f0-9]{64}$/u;
const COMPATIBILITY_ID_PATTERN =
  /^sast-rule-bundle-compatibility:\/\/[a-f0-9]{64}$/u;
const BUNDLE_ID_PATTERN =
  /^sast-rule-bundle:\/\/(?:opengrep|trivy)\/[a-z0-9][a-z0-9._-]{0,127}$/u;
const SEMANTIC_VERSION_PATTERN =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/u;
const SOURCE_REVISION_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u;
const MEMBER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/u;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const DIGEST_BOUND_REFERENCE_PATTERN =
  /^[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\/sha256:[a-f0-9]{64}$/u;
const SIGNER_IDENTITY_PATTERN =
  /^(?:spiffe|sast-signer):\/\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$/u;
const KILL_SWITCH_NAMESPACE_PATTERN =
  /^sast-kill-switch:\/\/[a-z0-9][a-z0-9._/-]{0,255}$/u;

type Sha256Digest = `sha256:${string}`;
export type SastRuleBundleScanner = 'OPENGREP' | 'TRIVY';
export type SastRuleBundleCanonicalDigester = (
  canonicalValue: string
) => Sha256Digest;

export interface SastRuleBundleManifestMember {
  memberId: string;
  digest: Sha256Digest;
}

export interface SastRuleBundleCompatibilityMatrix {
  scannerVersions: string[];
  scannerImageDigests: Sha256Digest[];
  wrapperDigests: Sha256Digest[];
  schemaBundleDigests: Sha256Digest[];
  normalizerBundleDigests: Sha256Digest[];
  profileIds: SastProfileId[];
}

export interface SastRuleBundleQualityEvidenceReferences {
  goldenCorpusResultRef: string;
  regressionCorpusResultRef: string;
  maliciousCorpusResultRef: string;
  performanceCorpusResultRef: string;
}

export interface SastRuleBundleManifestCore {
  version: typeof SAST_RULE_BUNDLE_MANIFEST_VERSION;
  bundleId: string;
  bundleVersion: string;
  lifecycleState: RuleBundleState;
  scanner: SastRuleBundleScanner;
  builtAt: string;
  sourceRevision: string;
  bundleDigest: Sha256Digest;
  members: SastRuleBundleManifestMember[];
  memberSetDigest: Sha256Digest;
  rules: RuleBundleRuleDescriptor[];
  ruleSetDigest: Sha256Digest;
  compatibility: SastRuleBundleCompatibilityMatrix;
  compatibilityDigest: Sha256Digest;
  qualityEvidence: SastRuleBundleQualityEvidenceReferences;
  qualityEvidenceDigest: Sha256Digest;
  signerIdentity: string;
  signatureRef: string;
  provenanceRef: string;
  compatibilityRef: string;
  rolloutPolicyRef: string;
  killSwitchNamespace: string;
  killSwitchRef: string;
  rollbackTargetDigest: Sha256Digest;
  source: 'PLATFORM_MANAGED';
  immutable: true;
  customerExecutableConfigAllowed: false;
}

export interface SastRuleBundleManifest
  extends SastRuleBundleManifestCore {
  manifestId: string;
  manifestDigest: Sha256Digest;
}

export type SastRuleBundleManifestInput = Omit<
  SastRuleBundleManifestCore,
  | 'version'
  | 'memberSetDigest'
  | 'ruleSetDigest'
  | 'compatibilityDigest'
  | 'qualityEvidenceDigest'
  | 'source'
  | 'immutable'
  | 'customerExecutableConfigAllowed'
>;

export interface SastRuleBundleSupplyChainAttestation {
  version: typeof SAST_RULE_BUNDLE_SUPPLY_CHAIN_ATTESTATION_VERSION;
  verificationId: string;
  manifestId: string;
  manifestDigest: Sha256Digest;
  bundleDigest: Sha256Digest;
  memberSetDigest: Sha256Digest;
  signerIdentity: string;
  signatureRef: string;
  provenanceRef: string;
  signatureVerified: true;
  provenanceVerified: true;
  trustedSigner: true;
  subjectDigestsVerified: true;
  signatureBytesStored: false;
  provenancePayloadStored: false;
  executableRuleContentStored: false;
  verifiedAt: string;
  attestationDigest: Sha256Digest;
}

export interface SastRuleBundleCompatibilityContext {
  scannerSetDigest: Sha256Digest;
  profileId: SastProfileId;
  profileDigest: Sha256Digest;
  scanner: SastRuleBundleScanner;
  scannerVersion: string;
  scannerImageDigest: Sha256Digest;
  wrapperDigest: Sha256Digest;
  schemaBundleDigest: Sha256Digest;
  normalizerBundleDigest: Sha256Digest;
}

export const SAST_RULE_BUNDLE_COMPATIBILITY_REASON_CODES = [
  'BUNDLE_STATE_NOT_SELECTABLE',
  'SCANNER_KIND_MISMATCH',
  'SCANNER_VERSION_UNSUPPORTED',
  'SCANNER_IMAGE_UNSUPPORTED',
  'WRAPPER_UNSUPPORTED',
  'SCHEMA_BUNDLE_UNSUPPORTED',
  'NORMALIZER_BUNDLE_UNSUPPORTED',
  'PROFILE_UNSUPPORTED'
] as const;
export type SastRuleBundleCompatibilityReasonCode =
  (typeof SAST_RULE_BUNDLE_COMPATIBILITY_REASON_CODES)[number];

export interface SastRuleBundleCompatibilityReceipt {
  version: typeof SAST_RULE_BUNDLE_COMPATIBILITY_RECEIPT_VERSION;
  receiptId: string;
  manifestId: string;
  manifestDigest: Sha256Digest;
  verificationId: string;
  verificationDigest: Sha256Digest;
  bundleDigest: Sha256Digest;
  context: SastRuleBundleCompatibilityContext;
  compatible: true;
  reasonCodes: [];
  manifestProjectionMatched: true;
  signatureVerified: true;
  provenanceVerified: true;
  trustedSigner: true;
  customerInputAccepted: false;
  executableRuleContentStored: false;
  evaluatedAt: string;
  receiptDigest: Sha256Digest;
}

export function buildSastRuleBundleManifest(
  input: Readonly<SastRuleBundleManifestInput>,
  digestCanonical: SastRuleBundleCanonicalDigester
): SastRuleBundleManifest | null {
  if (
    !hasExactKeys(input, [
      'bundleId',
      'bundleVersion',
      'lifecycleState',
      'scanner',
      'builtAt',
      'sourceRevision',
      'bundleDigest',
      'members',
      'rules',
      'compatibility',
      'qualityEvidence',
      'signerIdentity',
      'signatureRef',
      'provenanceRef',
      'compatibilityRef',
      'rolloutPolicyRef',
      'killSwitchNamespace',
      'killSwitchRef',
      'rollbackTargetDigest'
    ]) ||
    !Array.isArray(input.members) ||
    !Array.isArray(input.rules)
  ) {
    return null;
  }
  const members = input.members.map((member) => ({ ...member }));
  const rules = input.rules.map((rule) => ({ ...rule }));
  const compatibility = cloneCompatibility(input.compatibility);
  const qualityEvidence = { ...input.qualityEvidence };
  if (
    !isManifestInputValid({
      ...input,
      members,
      rules,
      compatibility,
      qualityEvidence
    })
  ) {
    return null;
  }

  const core: SastRuleBundleManifestCore = {
    version: SAST_RULE_BUNDLE_MANIFEST_VERSION,
    bundleId: input.bundleId,
    bundleVersion: input.bundleVersion,
    lifecycleState: input.lifecycleState,
    scanner: input.scanner,
    builtAt: input.builtAt,
    sourceRevision: input.sourceRevision,
    bundleDigest: input.bundleDigest,
    members,
    memberSetDigest: digestCanonical(stableJson(members)),
    rules,
    ruleSetDigest: digestCanonical(stableJson(rules)),
    compatibility,
    compatibilityDigest: digestCanonical(stableJson(compatibility)),
    qualityEvidence,
    qualityEvidenceDigest: digestCanonical(stableJson(qualityEvidence)),
    signerIdentity: input.signerIdentity,
    signatureRef: input.signatureRef,
    provenanceRef: input.provenanceRef,
    compatibilityRef: input.compatibilityRef,
    rolloutPolicyRef: input.rolloutPolicyRef,
    killSwitchNamespace: input.killSwitchNamespace,
    killSwitchRef: input.killSwitchRef,
    rollbackTargetDigest: input.rollbackTargetDigest,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    customerExecutableConfigAllowed: false
  };
  const manifestDigest = digestCanonical(stableJson(core));
  const suffix = digestSuffix(manifestDigest);
  if (!suffix) return null;
  const manifest: SastRuleBundleManifest = {
    ...core,
    manifestId: `sast-rule-bundle-manifest://${suffix}`,
    manifestDigest
  };
  return isSastRuleBundleManifestShapeValid(manifest, digestCanonical)
    ? manifest
    : null;
}

export function buildSastRuleBundleSupplyChainAttestation(input: {
  manifest: Readonly<SastRuleBundleManifest>;
  verifiedAt: string;
  digestCanonical: SastRuleBundleCanonicalDigester;
}): SastRuleBundleSupplyChainAttestation | null {
  if (
    !isSastRuleBundleManifestShapeValid(
      input.manifest,
      input.digestCanonical
    ) ||
    !isIsoInstant(input.verifiedAt)
  ) {
    return null;
  }
  const suffix = digestSuffix(input.manifest.manifestDigest);
  if (!suffix) return null;
  const core = {
    version: SAST_RULE_BUNDLE_SUPPLY_CHAIN_ATTESTATION_VERSION,
    verificationId: `sast-rule-bundle-verification://${suffix}`,
    manifestId: input.manifest.manifestId,
    manifestDigest: input.manifest.manifestDigest,
    bundleDigest: input.manifest.bundleDigest,
    memberSetDigest: input.manifest.memberSetDigest,
    signerIdentity: input.manifest.signerIdentity,
    signatureRef: input.manifest.signatureRef,
    provenanceRef: input.manifest.provenanceRef,
    signatureVerified: true as const,
    provenanceVerified: true as const,
    trustedSigner: true as const,
    subjectDigestsVerified: true as const,
    signatureBytesStored: false as const,
    provenancePayloadStored: false as const,
    executableRuleContentStored: false as const,
    verifiedAt: input.verifiedAt
  };
  const attestation: SastRuleBundleSupplyChainAttestation = {
    ...core,
    attestationDigest: input.digestCanonical(stableJson(core))
  };
  return isSastRuleBundleSupplyChainAttestationShapeValid(
    attestation,
    input.digestCanonical
  )
    ? attestation
    : null;
}

export function findSastRuleBundleCompatibilityReasonCodes(
  manifest: Readonly<SastRuleBundleManifest>,
  context: Readonly<SastRuleBundleCompatibilityContext>
): SastRuleBundleCompatibilityReasonCode[] {
  const reasons: SastRuleBundleCompatibilityReasonCode[] = [];
  if (!SAST_RULE_BUNDLE_SELECTABLE_STATES.includes(
    manifest.lifecycleState as (typeof SAST_RULE_BUNDLE_SELECTABLE_STATES)[number]
  )) {
    reasons.push('BUNDLE_STATE_NOT_SELECTABLE');
  }
  if (manifest.scanner !== context.scanner) {
    reasons.push('SCANNER_KIND_MISMATCH');
  }
  if (!manifest.compatibility.scannerVersions.includes(context.scannerVersion)) {
    reasons.push('SCANNER_VERSION_UNSUPPORTED');
  }
  if (!manifest.compatibility.scannerImageDigests.includes(context.scannerImageDigest)) {
    reasons.push('SCANNER_IMAGE_UNSUPPORTED');
  }
  if (!manifest.compatibility.wrapperDigests.includes(context.wrapperDigest)) {
    reasons.push('WRAPPER_UNSUPPORTED');
  }
  if (!manifest.compatibility.schemaBundleDigests.includes(context.schemaBundleDigest)) {
    reasons.push('SCHEMA_BUNDLE_UNSUPPORTED');
  }
  if (!manifest.compatibility.normalizerBundleDigests.includes(context.normalizerBundleDigest)) {
    reasons.push('NORMALIZER_BUNDLE_UNSUPPORTED');
  }
  if (!manifest.compatibility.profileIds.includes(context.profileId)) {
    reasons.push('PROFILE_UNSUPPORTED');
  }
  return reasons;
}

export function buildSastRuleBundleCompatibilityReceipt(input: {
  manifest: Readonly<SastRuleBundleManifest>;
  attestation: Readonly<SastRuleBundleSupplyChainAttestation>;
  context: Readonly<SastRuleBundleCompatibilityContext>;
  evaluatedAt: string;
  digestCanonical: SastRuleBundleCanonicalDigester;
}): SastRuleBundleCompatibilityReceipt | null {
  if (
    !isSastRuleBundleManifestShapeValid(
      input.manifest,
      input.digestCanonical
    ) ||
    !isSastRuleBundleSupplyChainAttestationShapeValid(
      input.attestation,
      input.digestCanonical
    ) ||
    !isSastRuleBundleCompatibilityContextShapeValid(input.context) ||
    !isIsoInstant(input.evaluatedAt) ||
    Date.parse(input.evaluatedAt) <
      Date.parse(input.attestation.verifiedAt) ||
    !isAttestationBoundToManifest(input.attestation, input.manifest) ||
    findSastRuleBundleCompatibilityReasonCodes(
      input.manifest,
      input.context
    ).length > 0
  ) {
    return null;
  }
  const identityDigest = input.digestCanonical(
    stableJson({
      version: SAST_RULE_BUNDLE_COMPATIBILITY_RECEIPT_VERSION,
      manifestDigest: input.manifest.manifestDigest,
      scannerSetDigest: input.context.scannerSetDigest,
      profileDigest: input.context.profileDigest
    })
  );
  const suffix = digestSuffix(identityDigest);
  if (!suffix) return null;
  const core = {
    version: SAST_RULE_BUNDLE_COMPATIBILITY_RECEIPT_VERSION,
    receiptId: `sast-rule-bundle-compatibility://${suffix}`,
    manifestId: input.manifest.manifestId,
    manifestDigest: input.manifest.manifestDigest,
    verificationId: input.attestation.verificationId,
    verificationDigest: input.attestation.attestationDigest,
    bundleDigest: input.manifest.bundleDigest,
    context: { ...input.context },
    compatible: true as const,
    reasonCodes: [] as [],
    manifestProjectionMatched: true as const,
    signatureVerified: true as const,
    provenanceVerified: true as const,
    trustedSigner: true as const,
    customerInputAccepted: false as const,
    executableRuleContentStored: false as const,
    evaluatedAt: input.evaluatedAt
  };
  const receipt: SastRuleBundleCompatibilityReceipt = {
    ...core,
    receiptDigest: input.digestCanonical(stableJson(core))
  };
  return isSastRuleBundleCompatibilityReceiptShapeValid(
    receipt,
    input.digestCanonical
  )
    ? receipt
    : null;
}

export function isSastRuleBundleManifestShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundleCanonicalDigester
): value is SastRuleBundleManifest {
  if (
    !hasExactKeys(value, [
      'version',
      'bundleId',
      'bundleVersion',
      'lifecycleState',
      'scanner',
      'builtAt',
      'sourceRevision',
      'bundleDigest',
      'members',
      'memberSetDigest',
      'rules',
      'ruleSetDigest',
      'compatibility',
      'compatibilityDigest',
      'qualityEvidence',
      'qualityEvidenceDigest',
      'signerIdentity',
      'signatureRef',
      'provenanceRef',
      'compatibilityRef',
      'rolloutPolicyRef',
      'killSwitchNamespace',
      'killSwitchRef',
      'rollbackTargetDigest',
      'source',
      'immutable',
      'customerExecutableConfigAllowed',
      'manifestId',
      'manifestDigest'
    ])
  ) {
    return false;
  }
  const manifest = value as unknown as SastRuleBundleManifest;
  if (
    manifest.version !== SAST_RULE_BUNDLE_MANIFEST_VERSION ||
    !isManifestInputValid(manifest) ||
    !MANIFEST_ID_PATTERN.test(manifest.manifestId) ||
    !isDigest(manifest.manifestDigest) ||
    !isDigest(manifest.memberSetDigest) ||
    !isDigest(manifest.ruleSetDigest) ||
    !isDigest(manifest.compatibilityDigest) ||
    !isDigest(manifest.qualityEvidenceDigest)
  ) {
    return false;
  }
  const core = manifestCore(manifest);
  return (
    manifest.memberSetDigest === digestCanonical(stableJson(manifest.members)) &&
    manifest.ruleSetDigest === digestCanonical(stableJson(manifest.rules)) &&
    manifest.compatibilityDigest ===
      digestCanonical(stableJson(manifest.compatibility)) &&
    manifest.qualityEvidenceDigest ===
      digestCanonical(stableJson(manifest.qualityEvidence)) &&
    manifest.manifestDigest === digestCanonical(stableJson(core)) &&
    manifest.manifestId ===
      `sast-rule-bundle-manifest://${digestSuffix(manifest.manifestDigest)}`
  );
}

export function isSastRuleBundleSupplyChainAttestationShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundleCanonicalDigester
): value is SastRuleBundleSupplyChainAttestation {
  if (
    !hasExactKeys(value, [
      'version',
      'verificationId',
      'manifestId',
      'manifestDigest',
      'bundleDigest',
      'memberSetDigest',
      'signerIdentity',
      'signatureRef',
      'provenanceRef',
      'signatureVerified',
      'provenanceVerified',
      'trustedSigner',
      'subjectDigestsVerified',
      'signatureBytesStored',
      'provenancePayloadStored',
      'executableRuleContentStored',
      'verifiedAt',
      'attestationDigest'
    ])
  ) {
    return false;
  }
  const attestation =
    value as unknown as SastRuleBundleSupplyChainAttestation;
  const core = { ...attestation } as Record<string, unknown>;
  delete core.attestationDigest;
  return (
    attestation.version ===
      SAST_RULE_BUNDLE_SUPPLY_CHAIN_ATTESTATION_VERSION &&
    VERIFICATION_ID_PATTERN.test(attestation.verificationId) &&
    MANIFEST_ID_PATTERN.test(attestation.manifestId) &&
    isDigest(attestation.manifestDigest) &&
    isDigest(attestation.bundleDigest) &&
    isDigest(attestation.memberSetDigest) &&
    isSignerIdentity(attestation.signerIdentity) &&
    isDigestBoundReference(attestation.signatureRef) &&
    isDigestBoundReference(attestation.provenanceRef) &&
    attestation.signatureVerified === true &&
    attestation.provenanceVerified === true &&
    attestation.trustedSigner === true &&
    attestation.subjectDigestsVerified === true &&
    attestation.signatureBytesStored === false &&
    attestation.provenancePayloadStored === false &&
    attestation.executableRuleContentStored === false &&
    isIsoInstant(attestation.verifiedAt) &&
    isDigest(attestation.attestationDigest) &&
    attestation.verificationId ===
      `sast-rule-bundle-verification://${digestSuffix(attestation.manifestDigest)}` &&
    attestation.attestationDigest === digestCanonical(stableJson(core))
  );
}

export function isSastRuleBundleCompatibilityContextShapeValid(
  value: unknown
): value is SastRuleBundleCompatibilityContext {
  if (
    !hasExactKeys(value, [
      'scannerSetDigest',
      'profileId',
      'profileDigest',
      'scanner',
      'scannerVersion',
      'scannerImageDigest',
      'wrapperDigest',
      'schemaBundleDigest',
      'normalizerBundleDigest'
    ])
  ) {
    return false;
  }
  const context = value as unknown as SastRuleBundleCompatibilityContext;
  return (
    isDigest(context.scannerSetDigest) &&
    PROFILE_IDS.includes(context.profileId) &&
    isDigest(context.profileDigest) &&
    isScanner(context.scanner) &&
    isBoundedText(context.scannerVersion, 255) &&
    isDigest(context.scannerImageDigest) &&
    isDigest(context.wrapperDigest) &&
    isDigest(context.schemaBundleDigest) &&
    isDigest(context.normalizerBundleDigest)
  );
}

export function isSastRuleBundleCompatibilityReceiptShapeValid(
  value: unknown,
  digestCanonical: SastRuleBundleCanonicalDigester
): value is SastRuleBundleCompatibilityReceipt {
  if (
    !hasExactKeys(value, [
      'version',
      'receiptId',
      'manifestId',
      'manifestDigest',
      'verificationId',
      'verificationDigest',
      'bundleDigest',
      'context',
      'compatible',
      'reasonCodes',
      'manifestProjectionMatched',
      'signatureVerified',
      'provenanceVerified',
      'trustedSigner',
      'customerInputAccepted',
      'executableRuleContentStored',
      'evaluatedAt',
      'receiptDigest'
    ])
  ) {
    return false;
  }
  const receipt = value as unknown as SastRuleBundleCompatibilityReceipt;
  const core = { ...receipt } as Record<string, unknown>;
  delete core.receiptDigest;
  const identityDigest = digestCanonical(
    stableJson({
      version: SAST_RULE_BUNDLE_COMPATIBILITY_RECEIPT_VERSION,
      manifestDigest: receipt.manifestDigest,
      scannerSetDigest: receipt.context?.scannerSetDigest,
      profileDigest: receipt.context?.profileDigest
    })
  );
  return (
    receipt.version === SAST_RULE_BUNDLE_COMPATIBILITY_RECEIPT_VERSION &&
    COMPATIBILITY_ID_PATTERN.test(receipt.receiptId) &&
    MANIFEST_ID_PATTERN.test(receipt.manifestId) &&
    isDigest(receipt.manifestDigest) &&
    VERIFICATION_ID_PATTERN.test(receipt.verificationId) &&
    isDigest(receipt.verificationDigest) &&
    isDigest(receipt.bundleDigest) &&
    isSastRuleBundleCompatibilityContextShapeValid(receipt.context) &&
    receipt.compatible === true &&
    Array.isArray(receipt.reasonCodes) &&
    receipt.reasonCodes.length === 0 &&
    receipt.manifestProjectionMatched === true &&
    receipt.signatureVerified === true &&
    receipt.provenanceVerified === true &&
    receipt.trustedSigner === true &&
    receipt.customerInputAccepted === false &&
    receipt.executableRuleContentStored === false &&
    isIsoInstant(receipt.evaluatedAt) &&
    isDigest(receipt.receiptDigest) &&
    receipt.receiptId ===
      `sast-rule-bundle-compatibility://${digestSuffix(identityDigest)}` &&
    receipt.receiptDigest === digestCanonical(stableJson(core))
  );
}

export function isAttestationBoundToManifest(
  attestation: Readonly<SastRuleBundleSupplyChainAttestation>,
  manifest: Readonly<SastRuleBundleManifest>
): boolean {
  return (
    attestation.manifestId === manifest.manifestId &&
    attestation.manifestDigest === manifest.manifestDigest &&
    attestation.bundleDigest === manifest.bundleDigest &&
    attestation.memberSetDigest === manifest.memberSetDigest &&
    attestation.signerIdentity === manifest.signerIdentity &&
    attestation.signatureRef === manifest.signatureRef &&
    attestation.provenanceRef === manifest.provenanceRef
  );
}

export function canonicalizeSastRuleBundleManifest(
  manifest: Readonly<SastRuleBundleManifest>
): string {
  return stableJson(manifest);
}

export function canonicalizeSastRuleBundleSupplyChainAttestation(
  attestation: Readonly<SastRuleBundleSupplyChainAttestation>
): string {
  return stableJson(attestation);
}

export function canonicalizeSastRuleBundleCompatibilityReceipt(
  receipt: Readonly<SastRuleBundleCompatibilityReceipt>
): string {
  return stableJson(receipt);
}

function isManifestInputValid(
  input: Readonly<SastRuleBundleManifestInput>
): boolean {
  return (
    BUNDLE_ID_PATTERN.test(input.bundleId) &&
    SEMANTIC_VERSION_PATTERN.test(input.bundleVersion) &&
    isRuleBundleState(input.lifecycleState) &&
    isScanner(input.scanner) &&
    input.bundleId.startsWith(
      `sast-rule-bundle://${input.scanner.toLowerCase()}/`
    ) &&
    isIsoInstant(input.builtAt) &&
    SOURCE_REVISION_PATTERN.test(input.sourceRevision) &&
    isDigest(input.bundleDigest) &&
    isCanonicalMembers(input.members) &&
    isCanonicalRules(input.rules) &&
    isCompatibilityMatrixValid(input.compatibility) &&
    isQualityEvidenceValid(input.qualityEvidence) &&
    isSignerIdentity(input.signerIdentity) &&
    isDigestBoundReference(input.signatureRef) &&
    isDigestBoundReference(input.provenanceRef) &&
    isDigestBoundReference(input.compatibilityRef) &&
    isDigestBoundReference(input.rolloutPolicyRef) &&
    KILL_SWITCH_NAMESPACE_PATTERN.test(input.killSwitchNamespace) &&
    isDigestBoundReference(input.killSwitchRef) &&
    isDigest(input.rollbackTargetDigest) &&
    input.rollbackTargetDigest !== input.bundleDigest
  );
}

function isCanonicalMembers(value: unknown): value is SastRuleBundleManifestMember[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > SAST_RULE_BUNDLE_MANIFEST_LIMITS.maximumMembers
  ) {
    return false;
  }
  const ids = new Set<string>();
  return value.every((member, index) => {
    if (!hasExactKeys(member, ['memberId', 'digest'])) return false;
    const candidate = member as SastRuleBundleManifestMember;
    const valid =
      MEMBER_ID_PATTERN.test(candidate.memberId) &&
      isCanonicalMemberId(candidate.memberId) &&
      isDigest(candidate.digest) &&
      !ids.has(candidate.memberId) &&
      (index === 0 ||
        (value[index - 1] as SastRuleBundleManifestMember).memberId <
          candidate.memberId);
    ids.add(candidate.memberId);
    return valid;
  });
}

function isCanonicalRules(value: unknown): value is RuleBundleRuleDescriptor[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > SAST_RULE_BUNDLE_MANIFEST_LIMITS.maximumRules
  ) {
    return false;
  }
  const ids = new Set<string>();
  return value.every((rule, index) => {
    if (
      !hasExactKeys(rule, [
        'ruleId',
        'ruleRevision',
        'ruleSemanticId',
        'metadataDigest'
      ])
    ) {
      return false;
    }
    const candidate = rule as RuleBundleRuleDescriptor;
    const valid =
      isBoundedText(candidate.ruleId, 256) &&
      isBoundedText(candidate.ruleRevision, 256) &&
      isBoundedText(candidate.ruleSemanticId, 256) &&
      isDigest(candidate.metadataDigest) &&
      !ids.has(candidate.ruleId) &&
      (index === 0 ||
        (value[index - 1] as RuleBundleRuleDescriptor).ruleId <
          candidate.ruleId);
    ids.add(candidate.ruleId);
    return valid;
  });
}

function isCompatibilityMatrixValid(
  value: unknown
): value is SastRuleBundleCompatibilityMatrix {
  if (
    !hasExactKeys(value, [
      'scannerVersions',
      'scannerImageDigests',
      'wrapperDigests',
      'schemaBundleDigests',
      'normalizerBundleDigests',
      'profileIds'
    ])
  ) {
    return false;
  }
  const matrix = value as unknown as SastRuleBundleCompatibilityMatrix;
  return (
    isCanonicalStringSet(
      matrix.scannerVersions,
      (entry) =>
        isBoundedText(entry, 255) &&
        SEMANTIC_VERSION_PATTERN.test(entry)
    ) &&
    isCanonicalStringSet(matrix.scannerImageDigests, isDigest) &&
    isCanonicalStringSet(matrix.wrapperDigests, isDigest) &&
    isCanonicalStringSet(matrix.schemaBundleDigests, isDigest) &&
    isCanonicalStringSet(matrix.normalizerBundleDigests, isDigest) &&
    isCanonicalStringSet(
      matrix.profileIds,
      (entry) => PROFILE_IDS.includes(entry as SastProfileId)
    )
  );
}

function isQualityEvidenceValid(
  value: unknown
): value is SastRuleBundleQualityEvidenceReferences {
  if (
    !hasExactKeys(value, [
      'goldenCorpusResultRef',
      'regressionCorpusResultRef',
      'maliciousCorpusResultRef',
      'performanceCorpusResultRef'
    ])
  ) {
    return false;
  }
  return Object.values(value as Record<string, unknown>).every(
    (entry) =>
      typeof entry === 'string' && isDigestBoundReference(entry)
  );
}

function isCanonicalStringSet<T extends string>(
  value: unknown,
  validate: (entry: T) => boolean
): value is T[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length >
      SAST_RULE_BUNDLE_MANIFEST_LIMITS.maximumCompatibilityValues
  ) {
    return false;
  }
  return value.every(
    (entry, index) =>
      typeof entry === 'string' &&
      validate(entry as T) &&
      (index === 0 || (value[index - 1] as string) < entry)
  );
}

function cloneCompatibility(
  value: Readonly<SastRuleBundleCompatibilityMatrix>
): SastRuleBundleCompatibilityMatrix {
  return {
    scannerVersions: [...value.scannerVersions],
    scannerImageDigests: [...value.scannerImageDigests],
    wrapperDigests: [...value.wrapperDigests],
    schemaBundleDigests: [...value.schemaBundleDigests],
    normalizerBundleDigests: [...value.normalizerBundleDigests],
    profileIds: [...value.profileIds]
  };
}

function manifestCore(
  manifest: Readonly<SastRuleBundleManifest>
): SastRuleBundleManifestCore {
  return {
    version: manifest.version,
    bundleId: manifest.bundleId,
    bundleVersion: manifest.bundleVersion,
    lifecycleState: manifest.lifecycleState,
    scanner: manifest.scanner,
    builtAt: manifest.builtAt,
    sourceRevision: manifest.sourceRevision,
    bundleDigest: manifest.bundleDigest,
    members: manifest.members.map((member) => ({ ...member })),
    memberSetDigest: manifest.memberSetDigest,
    rules: manifest.rules.map((rule) => ({ ...rule })),
    ruleSetDigest: manifest.ruleSetDigest,
    compatibility: cloneCompatibility(manifest.compatibility),
    compatibilityDigest: manifest.compatibilityDigest,
    qualityEvidence: { ...manifest.qualityEvidence },
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
      manifest.customerExecutableConfigAllowed
  };
}

function isRuleBundleState(value: unknown): value is RuleBundleState {
  return [
    'DRAFT',
    'VALIDATED',
    'CANARY',
    'ACTIVE',
    'SUSPENDED',
    'ROLLED_BACK',
    'RETIRED'
  ].includes(value as RuleBundleState);
}

function isScanner(value: unknown): value is SastRuleBundleScanner {
  return value === 'OPENGREP' || value === 'TRIVY';
}

function isCanonicalMemberId(value: string): boolean {
  return (
    value.normalize('NFC') === value &&
    !value.startsWith('/') &&
    !value.endsWith('/') &&
    !value.includes('//') &&
    value.split('/').every((segment) => segment !== '.' && segment !== '..')
  );
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedText(
      value,
      SAST_RULE_BUNDLE_MANIFEST_LIMITS.referenceBytes
    ) &&
    DIGEST_BOUND_REFERENCE_PATTERN.test(value) &&
    !/^https?:/u.test(value)
  );
}

function isSignerIdentity(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    isBoundedText(
      value,
      SAST_RULE_BUNDLE_MANIFEST_LIMITS.identifierBytes
    ) &&
    SIGNER_IDENTITY_PATTERN.test(value)
  );
}

function isBoundedText(value: unknown, maximumBytes: number): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.normalize('NFC') === value &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    }) &&
    new TextEncoder().encode(value).length <= maximumBytes
  );
}

function isDigest(value: unknown): value is Sha256Digest {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function digestSuffix(value: unknown): string | null {
  return isDigest(value) ? value.slice('sha256:'.length) : null;
}

function isIsoInstant(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function hasExactKeys(value: unknown, keys: readonly string[]): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return stableJson(actual) === stableJson(expected);
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map(
        (key) => `${JSON.stringify(key)}:${stableJson(object[key])}`
      )
      .join(',')}}`;
  }
  return JSON.stringify(value);
}
