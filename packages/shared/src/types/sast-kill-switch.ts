import type {
  SastCapability,
  SastProfileId,
  SastScannerKind
} from './sast-runtime';
import { SAST_KILL_SWITCH_SCOPES } from './sast-kill-switch-scopes';

export const SAST_KILL_SWITCH_CONTEXT_VERSION =
  'sast-kill-switch-context-v1' as const;
export const SAST_KILL_SWITCH_DECISION_VERSION =
  'sast-kill-switch-decision-v1' as const;
export const SAST_KILL_SWITCH_VERIFICATION_VERSION =
  'sast-kill-switch-verification-v1' as const;
export const SAST_KILL_SWITCH_EVALUATION_VERSION =
  'sast-kill-switch-evaluation-v1' as const;
export const SAST_KILL_SWITCH_PLANNING_VERSION =
  'sast-kill-switch-planning-v1' as const;
export const SAST_KILL_SWITCH_EMERGENCY_SUSPENSION_VERSION =
  'sast-kill-switch-emergency-suspension-v1' as const;
export const SAST_KILL_SWITCH_CANARY_SUSPENSION_REQUEST_VERSION =
  'sast-kill-switch-canary-suspension-request-v1' as const;
export const SAST_KILL_SWITCH_CANARY_SUSPENSION_SIGNAL_VERSION =
  'sast-kill-switch-canary-suspension-signal-v1' as const;
export const SAST_KILL_SWITCH_MAX_SELECTOR_BINDINGS = 50_020;

export const SAST_KILL_SWITCH_ACTIONS = [
  'ACTIVATE',
  'DEACTIVATE'
] as const;
export type SastKillSwitchAction =
  (typeof SAST_KILL_SWITCH_ACTIONS)[number];

export const SAST_KILL_SWITCH_ACTOR_ROLES = [
  'SECURITY_ON_CALL',
  'PLATFORM_ON_CALL'
] as const;
export type SastKillSwitchActorRole =
  (typeof SAST_KILL_SWITCH_ACTOR_ROLES)[number];

export const SAST_KILL_SWITCH_REASON_CODES = [
  'SECURITY_INCIDENT',
  'SCANNER_DEFECT',
  'SUPPLY_CHAIN_RISK',
  'FALSE_POSITIVE_REGRESSION',
  'RELIABILITY_REGRESSION',
  'PRIVACY_RISK',
  'POLICY_EMERGENCY',
  'OPERATOR_DRILL'
] as const;
export type SastKillSwitchReasonCode =
  (typeof SAST_KILL_SWITCH_REASON_CODES)[number];

export const SAST_KILL_SWITCH_GATES = [
  'PLANNING',
  'QUEUE_ADMISSION',
  'SCANNER_START',
  'ARTIFACT_ACCEPTANCE',
  'RETRY_ADMISSION',
  'COVERAGE',
  'EXTERNAL_PUBLICATION',
  'AI_ADVISORY'
] as const;
export type SastKillSwitchGate =
  (typeof SAST_KILL_SWITCH_GATES)[number];

export const SAST_KILL_SWITCH_EVALUATION_OUTCOMES = [
  'CLEAR',
  'ACTIVE'
] as const;
export type SastKillSwitchEvaluationOutcome =
  (typeof SAST_KILL_SWITCH_EVALUATION_OUTCOMES)[number];

export const SAST_KILL_SWITCH_COVERAGE_EFFECTS = [
  'UNCHANGED',
  'PARTIAL',
  'FAILED'
] as const;
export type SastKillSwitchCoverageEffect =
  (typeof SAST_KILL_SWITCH_COVERAGE_EFFECTS)[number];

export type SastKillSwitchSelector =
  | { scope: 'GLOBAL'; runtime: 'SAST' }
  | {
      scope: 'SCANNER_VERSION';
      scanner: SastScannerKind;
      scannerVersion: string;
    }
  | { scope: 'RULE_BUNDLE'; bundleDigest: `sha256:${string}` }
  | { scope: 'SEMANTIC_RULE'; ruleSemanticId: string }
  | {
      scope: 'PROFILE';
      profileId: SastProfileId;
      profileDigest: `sha256:${string}`;
    }
  | { scope: 'TENANT'; tenantId: string }
  | {
      scope: 'REPOSITORY_BINDING';
      tenantId: string;
      repositoryBindingId: string;
    }
  | { scope: 'CAPABILITY'; capability: SastCapability }
  | {
      scope: 'EXTERNAL_PUBLICATION';
      targetScope: 'GLOBAL';
      tenantId: null;
      repositoryBindingId: null;
    }
  | {
      scope: 'EXTERNAL_PUBLICATION';
      targetScope: 'TENANT';
      tenantId: string;
      repositoryBindingId: null;
    }
  | {
      scope: 'EXTERNAL_PUBLICATION';
      targetScope: 'REPOSITORY_BINDING';
      tenantId: string;
      repositoryBindingId: string;
    };

export interface SastKillSwitchScannerBinding {
  scanner: SastScannerKind;
  scannerVersion: string;
}

export interface SastKillSwitchRuleBundleBinding {
  bundleDigest: `sha256:${string}`;
  ruleSemanticIds: string[];
}

export interface SastKillSwitchEvaluationContext {
  version: typeof SAST_KILL_SWITCH_CONTEXT_VERSION;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  scanners: SastKillSwitchScannerBinding[];
  ruleBundles: SastKillSwitchRuleBundleBinding[];
  requiredCapabilities: SastCapability[];
  source: 'TRUSTED_RUNTIME_BINDING';
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  arbitraryPayloadStored: false;
  contextDigest: `sha256:${string}`;
}

export type SastKillSwitchEvaluationContextCore = Omit<
  SastKillSwitchEvaluationContext,
  'contextDigest'
>;

export interface SastKillSwitchControlDecision {
  version: typeof SAST_KILL_SWITCH_DECISION_VERSION;
  decisionId: string;
  selectorKey: string;
  selector: SastKillSwitchSelector;
  sequence: number;
  previousDecisionId: string | null;
  previousDecisionDigest: `sha256:${string}` | null;
  action: SastKillSwitchAction;
  reasonCode: SastKillSwitchReasonCode;
  incidentRef: string;
  actorRef: string;
  actorRole: SastKillSwitchActorRole;
  effectiveAt: string;
  reviewBy: string;
  expiresAt: string;
  rollbackTargetRef: string;
  signatureRef: string;
  provenanceRef: string;
  auditRef: string;
  source: 'PLATFORM_MANAGED';
  immutable: true;
  customerInputAccepted: false;
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  arbitraryPayloadStored: false;
  decisionDigest: `sha256:${string}`;
}

export type SastKillSwitchControlDecisionCore = Omit<
  SastKillSwitchControlDecision,
  'decisionDigest'
>;

export type SastKillSwitchControlDecisionInput = Omit<
  SastKillSwitchControlDecisionCore,
  | 'version'
  | 'decisionId'
  | 'selectorKey'
  | 'source'
  | 'immutable'
  | 'customerInputAccepted'
  | 'repositoryContentStored'
  | 'findingContentStored'
  | 'secretValueStored'
  | 'arbitraryPayloadStored'
>;

export interface SastKillSwitchVerification {
  version: typeof SAST_KILL_SWITCH_VERIFICATION_VERSION;
  verificationId: string;
  decisionId: string;
  decisionDigest: `sha256:${string}`;
  selectorKey: string;
  signerIdentity: string;
  signatureRef: string;
  provenanceRef: string;
  signatureVerified: true;
  provenanceVerified: true;
  trustedSigner: true;
  signatureBytesStored: false;
  provenancePayloadStored: false;
  repositoryContentStored: false;
  secretValueStored: false;
  verifiedAt: string;
  verificationDigest: `sha256:${string}`;
}

export type SastKillSwitchVerificationCore = Omit<
  SastKillSwitchVerification,
  'verificationDigest'
>;

export interface SastKillSwitchHeadBinding {
  selectorKey: string;
  scope: SastKillSwitchSelector['scope'];
  sequence: number;
  decisionId: string | null;
  decisionDigest: `sha256:${string}` | null;
  action: SastKillSwitchAction | null;
  active: boolean;
  effectiveAt: string | null;
  expiresAt: string | null;
  bindingDigest: `sha256:${string}`;
}

export type SastKillSwitchHeadBindingCore = Omit<
  SastKillSwitchHeadBinding,
  'bindingDigest'
>;

export interface SastKillSwitchEvaluationMatch {
  selectorKey: string;
  scope: SastKillSwitchSelector['scope'];
  decisionId: string;
  decisionDigest: `sha256:${string}`;
  bindingDigest: `sha256:${string}`;
}

export type SastKillSwitchEvaluationMatchCore = Omit<
  SastKillSwitchEvaluationMatch,
  'bindingDigest'
>;

export interface SastKillSwitchEvaluationReceipt {
  version: typeof SAST_KILL_SWITCH_EVALUATION_VERSION;
  evaluationId: string;
  gate: SastKillSwitchGate;
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  scannerSetDigest: `sha256:${string}`;
  contextDigest: `sha256:${string}`;
  snapshotDigest: `sha256:${string}`;
  headCount: number;
  headSetDigest: `sha256:${string}`;
  matchedDecisionCount: number;
  matchedDecisionSetDigest: `sha256:${string}`;
  outcome: SastKillSwitchEvaluationOutcome;
  coverageEffect: SastKillSwitchCoverageEffect;
  evaluatedAt: string;
  customerInputAccepted: false;
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  arbitraryPayloadStored: false;
  receiptDigest: `sha256:${string}`;
}

export type SastKillSwitchEvaluationReceiptCore = Omit<
  SastKillSwitchEvaluationReceipt,
  'receiptDigest'
>;

export interface SastKillSwitchEvaluationResult {
  receipt: SastKillSwitchEvaluationReceipt;
  heads: SastKillSwitchHeadBinding[];
  matches: SastKillSwitchEvaluationMatch[];
  replayed: boolean;
}

export interface SastKillSwitchPlanningDescriptor {
  version: typeof SAST_KILL_SWITCH_PLANNING_VERSION;
  evaluationId: string;
  evaluationReceiptDigest: `sha256:${string}`;
  contextDigest: `sha256:${string}`;
  snapshotDigest: `sha256:${string}`;
  headSetDigest: `sha256:${string}`;
  evaluatedAt: string;
  outcome: 'CLEAR';
}

export interface SastKillSwitchEmergencySuspensionReceipt {
  version: typeof SAST_KILL_SWITCH_EMERGENCY_SUSPENSION_VERSION;
  receiptId: string;
  receiptRef: string;
  manifestId: string;
  manifestDigest: `sha256:${string}`;
  bundleId: string;
  bundleDigest: `sha256:${string}`;
  fromState: 'CANARY' | 'ACTIVE';
  toState: 'SUSPENDED';
  lifecycleSequence: number;
  lifecycleTransitionId: string;
  lifecycleTransitionDigest: `sha256:${string}`;
  promotionEvidenceId: string;
  promotionEvidenceDigest: `sha256:${string}`;
  triggerSelectorKey: string;
  triggerDecisionId: string;
  triggerDecisionDigest: `sha256:${string}`;
  activeDecisionCount: number;
  activeDecisionSetDigest: `sha256:${string}`;
  requestedAt: string;
  verifiedAt: string;
  customerInputAccepted: false;
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  receiptDigest: `sha256:${string}`;
}

export type SastKillSwitchEmergencySuspensionReceiptCore = Omit<
  SastKillSwitchEmergencySuspensionReceipt,
  'receiptDigest'
>;

export type SastKillSwitchEmergencySuspensionReceiptDigestCore = Omit<
  SastKillSwitchEmergencySuspensionReceiptCore,
  'receiptId' | 'receiptRef'
>;

export type SastKillSwitchEmergencySuspensionReceiptInput = Omit<
  SastKillSwitchEmergencySuspensionReceiptDigestCore,
  | 'version'
  | 'customerInputAccepted'
  | 'repositoryContentStored'
  | 'findingContentStored'
  | 'secretValueStored'
>;

export const SAST_KILL_SWITCH_CANARY_SUSPENSION_REASON_CODES = [
  'TELEMETRY_MISSING',
  'COVERAGE_INCOMPLETE',
  'PROFILE_SIZE_COMPARISON_INCOMPLETE',
  'FALSE_POSITIVE_GATE_FAILED',
  'SCANNER_FAILURE_GATE_FAILED',
  'LATENCY_GATE_FAILED',
  'CRITICAL_HIGH_VOLUME_GATE_FAILED',
  'ZERO_TOLERANCE_EVENT_RECORDED'
] as const;
export type SastKillSwitchCanarySuspensionReasonCode =
  (typeof SAST_KILL_SWITCH_CANARY_SUSPENSION_REASON_CODES)[number];

export interface SastKillSwitchCanarySuspensionRequest {
  version: typeof SAST_KILL_SWITCH_CANARY_SUSPENSION_REQUEST_VERSION;
  canaryDecisionId: string;
  canaryDecisionDigest: `sha256:${string}`;
}

export interface SastKillSwitchCanarySuspensionSignal {
  version: typeof SAST_KILL_SWITCH_CANARY_SUSPENSION_SIGNAL_VERSION;
  signalId: string;
  source: 'DURABLE_T048_CANARY_DECISION';
  trigger: 'CANARY_PAUSED' | 'ZERO_TOLERANCE';
  canaryDecisionId: string;
  canaryDecisionDigest: `sha256:${string}`;
  rolloutId: string;
  rolloutDigest: `sha256:${string}`;
  candidateManifestId: string;
  candidateManifestDigest: `sha256:${string}`;
  candidateBundleId: string;
  candidateBundleDigest: `sha256:${string}`;
  profileId: SastProfileId;
  profileDigest: `sha256:${string}`;
  lifecycleTransitionId: string;
  lifecycleTransitionDigest: `sha256:${string}`;
  lifecycleState: 'CANARY';
  reasonCodes: SastKillSwitchCanarySuspensionReasonCode[];
  observedAt: string;
  customerTargetAccepted: false;
  repositoryContentStored: false;
  findingContentStored: false;
  secretValueStored: false;
  arbitraryPayloadStored: false;
  signalDigest: `sha256:${string}`;
}

export type SastKillSwitchCanarySuspensionSignalCore = Omit<
  SastKillSwitchCanarySuspensionSignal,
  'signalId' | 'signalDigest'
>;

export type SastKillSwitchCanarySuspensionSignalInput = Omit<
  SastKillSwitchCanarySuspensionSignalCore,
  | 'version'
  | 'source'
  | 'trigger'
  | 'customerTargetAccepted'
  | 'repositoryContentStored'
  | 'findingContentStored'
  | 'secretValueStored'
  | 'arbitraryPayloadStored'
>;

export type SastKillSwitchCanonicalDigester = (
  value: string
) => `sha256:${string}`;

const SCANNERS: readonly SastScannerKind[] = [
  'OPENGREP',
  'TRIVY',
  'SYFT'
];
const PROFILES: readonly SastProfileId[] = [
  'JAVA_FAST_V1',
  'JAVA_DEEP_V1',
  'COMMON_DEEP_V1'
];
const CAPABILITIES: readonly SastCapability[] = [
  'SAST',
  'DEPENDENCY_VULNERABILITY',
  'SECRET_DETECTION',
  'IAC_MISCONFIGURATION',
  'SBOM'
];
export function canonicalizeSastKillSwitchSelector(
  selector: Readonly<SastKillSwitchSelector>
): string {
  return stableJson(selector);
}

export function buildSastKillSwitchSelectorKey(
  selector: Readonly<SastKillSwitchSelector>,
  digestCanonical: SastKillSwitchCanonicalDigester
): string {
  return `sast-kill-switch-selector://${digestCanonical(
    canonicalizeSastKillSwitchSelector(selector)
  ).slice('sha256:'.length)}`;
}

export function canonicalizeSastKillSwitchEvaluationContext(
  context: Readonly<SastKillSwitchEvaluationContextCore>
): string {
  return stableJson(context);
}

export function buildSastKillSwitchEvaluationContext(
  input: Omit<
    SastKillSwitchEvaluationContextCore,
    | 'version'
    | 'source'
    | 'repositoryContentStored'
    | 'findingContentStored'
    | 'secretValueStored'
    | 'arbitraryPayloadStored'
  >,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchEvaluationContext | null {
  const core: SastKillSwitchEvaluationContextCore = {
    version: SAST_KILL_SWITCH_CONTEXT_VERSION,
    tenantId: input.tenantId,
    repositoryBindingId: input.repositoryBindingId,
    scanRequestId: input.scanRequestId,
    profileId: input.profileId,
    profileDigest: input.profileDigest,
    scannerSetDigest: input.scannerSetDigest,
    scanners: input.scanners.map((scanner) => ({ ...scanner })),
    ruleBundles: input.ruleBundles.map((bundle) => ({
      bundleDigest: bundle.bundleDigest,
      ruleSemanticIds: [...bundle.ruleSemanticIds]
    })),
    requiredCapabilities: [...input.requiredCapabilities],
    source: 'TRUSTED_RUNTIME_BINDING',
    repositoryContentStored: false,
    findingContentStored: false,
    secretValueStored: false,
    arbitraryPayloadStored: false
  };
  const context: SastKillSwitchEvaluationContext = {
    ...core,
    contextDigest: digestCanonical(
      canonicalizeSastKillSwitchEvaluationContext(core)
    )
  };
  return isSastKillSwitchEvaluationContextValid(
    context,
    digestCanonical
  )
    ? context
    : null;
}

export function isSastKillSwitchEvaluationContextValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchEvaluationContext {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'profileId',
      'profileDigest',
      'scannerSetDigest',
      'scanners',
      'ruleBundles',
      'requiredCapabilities',
      'source',
      'repositoryContentStored',
      'findingContentStored',
      'secretValueStored',
      'arbitraryPayloadStored',
      'contextDigest'
    ]) ||
    value.version !== SAST_KILL_SWITCH_CONTEXT_VERSION ||
    !isBoundedIdentity(value.tenantId) ||
    !isBoundedIdentity(value.repositoryBindingId) ||
    !isBoundedIdentity(value.scanRequestId) ||
    !PROFILES.includes(value.profileId as SastProfileId) ||
    !isDigest(value.profileDigest) ||
    !isDigest(value.scannerSetDigest) ||
    !Array.isArray(value.scanners) ||
    value.scanners.length < 1 ||
    value.scanners.length > SCANNERS.length ||
    !Array.isArray(value.ruleBundles) ||
    value.ruleBundles.length > 2 ||
    !Array.isArray(value.requiredCapabilities) ||
    value.source !== 'TRUSTED_RUNTIME_BINDING' ||
    value.repositoryContentStored !== false ||
    value.findingContentStored !== false ||
    value.secretValueStored !== false ||
    value.arbitraryPayloadStored !== false ||
    !isDigest(value.contextDigest)
  ) {
    return false;
  }
  const context = value as unknown as SastKillSwitchEvaluationContext;
  if (
    context.scanners.some(
      (scanner) =>
        !isRecord(scanner) ||
        !hasExactKeys(scanner, ['scanner', 'scannerVersion']) ||
        !SCANNERS.includes(scanner.scanner as SastScannerKind) ||
        !isBoundedIdentity(scanner.scannerVersion)
    ) ||
    !isCanonicalBy(
      context.scanners,
      (scanner) => `${scanner.scanner}\u0000${scanner.scannerVersion}`
    ) ||
    context.ruleBundles.some(
      (bundle) =>
        !isRecord(bundle) ||
        !hasExactKeys(bundle, ['bundleDigest', 'ruleSemanticIds']) ||
        !isDigest(bundle.bundleDigest) ||
        !Array.isArray(bundle.ruleSemanticIds) ||
        bundle.ruleSemanticIds.length > 25_000 ||
        bundle.ruleSemanticIds.some(
          (rule) => !isBoundedIdentity(rule)
        ) ||
        !isCanonicalStrings(bundle.ruleSemanticIds)
    ) ||
    !isCanonicalBy(
      context.ruleBundles,
      (bundle) => bundle.bundleDigest
    ) ||
    context.requiredCapabilities.some(
      (capability) => !CAPABILITIES.includes(capability)
    ) ||
    !isCanonicalBy(
      context.requiredCapabilities,
      (capability) => String(CAPABILITIES.indexOf(capability))
    )
  ) {
    return false;
  }
  const { contextDigest, ...core } = context;
  return (
    digestCanonical(
      canonicalizeSastKillSwitchEvaluationContext(core)
    ) === contextDigest
  );
}

export function buildApplicableSastKillSwitchSelectors(
  context: Readonly<SastKillSwitchEvaluationContext>,
  gate: SastKillSwitchGate,
  digestCanonical: SastKillSwitchCanonicalDigester
): Array<{ selectorKey: string; selector: SastKillSwitchSelector }> {
  if (
    !isSastKillSwitchEvaluationContextValid(context, digestCanonical) ||
    !SAST_KILL_SWITCH_GATES.includes(gate)
  ) {
    return [];
  }
  const selectors: SastKillSwitchSelector[] = [
    { scope: 'GLOBAL', runtime: 'SAST' },
    { scope: 'TENANT', tenantId: context.tenantId },
    {
      scope: 'REPOSITORY_BINDING',
      tenantId: context.tenantId,
      repositoryBindingId: context.repositoryBindingId
    },
    {
      scope: 'PROFILE',
      profileId: context.profileId,
      profileDigest: context.profileDigest
    },
    ...context.scanners.map<SastKillSwitchSelector>((scanner) => ({
      scope: 'SCANNER_VERSION',
      scanner: scanner.scanner,
      scannerVersion: scanner.scannerVersion
    })),
    ...context.ruleBundles.flatMap<SastKillSwitchSelector>((bundle) => [
      { scope: 'RULE_BUNDLE', bundleDigest: bundle.bundleDigest },
      ...bundle.ruleSemanticIds.map((ruleSemanticId) => ({
        scope: 'SEMANTIC_RULE' as const,
        ruleSemanticId
      }))
    ]),
    ...context.requiredCapabilities.map<SastKillSwitchSelector>(
      (capability) => ({ scope: 'CAPABILITY', capability })
    )
  ];
  if (gate === 'EXTERNAL_PUBLICATION' || gate === 'AI_ADVISORY') {
    selectors.push(
      {
        scope: 'EXTERNAL_PUBLICATION',
        targetScope: 'GLOBAL',
        tenantId: null,
        repositoryBindingId: null
      },
      {
        scope: 'EXTERNAL_PUBLICATION',
        targetScope: 'TENANT',
        tenantId: context.tenantId,
        repositoryBindingId: null
      },
      {
        scope: 'EXTERNAL_PUBLICATION',
        targetScope: 'REPOSITORY_BINDING',
        tenantId: context.tenantId,
        repositoryBindingId: context.repositoryBindingId
      }
    );
  }
  const keyed = selectors.map((selector) => ({
    selectorKey: buildSastKillSwitchSelectorKey(
      selector,
      digestCanonical
    ),
    selector
  }));
  const unique = [
    ...new Map(keyed.map((entry) => [entry.selectorKey, entry])).values()
  ].sort((left, right) => compare(left.selectorKey, right.selectorKey));
  return unique.length <= SAST_KILL_SWITCH_MAX_SELECTOR_BINDINGS ? unique : [];
}

export function isSastKillSwitchSelectorValid(
  value: unknown
): value is SastKillSwitchSelector {
  if (!isRecord(value) || !SAST_KILL_SWITCH_SCOPES.includes(value.scope as never)) {
    return false;
  }
  switch (value.scope) {
    case 'GLOBAL':
      return hasExactKeys(value, ['scope', 'runtime']) && value.runtime === 'SAST';
    case 'SCANNER_VERSION':
      return (
        hasExactKeys(value, ['scope', 'scanner', 'scannerVersion']) &&
        SCANNERS.includes(value.scanner as SastScannerKind) &&
        isBoundedIdentity(value.scannerVersion)
      );
    case 'RULE_BUNDLE':
      return hasExactKeys(value, ['scope', 'bundleDigest']) && isDigest(value.bundleDigest);
    case 'SEMANTIC_RULE':
      return hasExactKeys(value, ['scope', 'ruleSemanticId']) && isBoundedIdentity(value.ruleSemanticId);
    case 'PROFILE':
      return (
        hasExactKeys(value, ['scope', 'profileId', 'profileDigest']) &&
        PROFILES.includes(value.profileId as SastProfileId) &&
        isDigest(value.profileDigest)
      );
    case 'TENANT':
      return hasExactKeys(value, ['scope', 'tenantId']) && isBoundedIdentity(value.tenantId);
    case 'REPOSITORY_BINDING':
      return (
        hasExactKeys(value, ['scope', 'tenantId', 'repositoryBindingId']) &&
        isBoundedIdentity(value.tenantId) &&
        isBoundedIdentity(value.repositoryBindingId)
      );
    case 'CAPABILITY':
      return hasExactKeys(value, ['scope', 'capability']) && CAPABILITIES.includes(value.capability as SastCapability);
    case 'EXTERNAL_PUBLICATION':
      if (
        !hasExactKeys(value, [
          'scope',
          'targetScope',
          'tenantId',
          'repositoryBindingId'
        ])
      ) {
        return false;
      }
      if (value.targetScope === 'GLOBAL') {
        return value.tenantId === null && value.repositoryBindingId === null;
      }
      if (value.targetScope === 'TENANT') {
        return isBoundedIdentity(value.tenantId) && value.repositoryBindingId === null;
      }
      return (
        value.targetScope === 'REPOSITORY_BINDING' &&
        isBoundedIdentity(value.tenantId) &&
        isBoundedIdentity(value.repositoryBindingId)
      );
    default:
      return false;
  }
}

export function canonicalizeSastKillSwitchDecision(
  decision: Readonly<SastKillSwitchControlDecisionCore>
): string {
  return stableJson(decision);
}

export function buildSastKillSwitchDecision(
  input: Readonly<SastKillSwitchControlDecisionInput>,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchControlDecision | null {
  if (!isSastKillSwitchSelectorValid(input.selector)) return null;
  const selectorKey = buildSastKillSwitchSelectorKey(
    input.selector,
    digestCanonical
  );
  const identityDigest = digestCanonical(
    stableJson({
      version: SAST_KILL_SWITCH_DECISION_VERSION,
      selectorKey,
      sequence: input.sequence,
      action: input.action,
      effectiveAt: input.effectiveAt,
      incidentRef: input.incidentRef
    })
  );
  const core: SastKillSwitchControlDecisionCore = {
    version: SAST_KILL_SWITCH_DECISION_VERSION,
    decisionId: `sast-kill-switch-decision://${identityDigest.slice('sha256:'.length)}`,
    selectorKey,
    selector: structuredClone(input.selector),
    sequence: input.sequence,
    previousDecisionId: input.previousDecisionId,
    previousDecisionDigest: input.previousDecisionDigest,
    action: input.action,
    reasonCode: input.reasonCode,
    incidentRef: input.incidentRef,
    actorRef: input.actorRef,
    actorRole: input.actorRole,
    effectiveAt: input.effectiveAt,
    reviewBy: input.reviewBy,
    expiresAt: input.expiresAt,
    rollbackTargetRef: input.rollbackTargetRef,
    signatureRef: input.signatureRef,
    provenanceRef: input.provenanceRef,
    auditRef: input.auditRef,
    source: 'PLATFORM_MANAGED',
    immutable: true,
    customerInputAccepted: false,
    repositoryContentStored: false,
    findingContentStored: false,
    secretValueStored: false,
    arbitraryPayloadStored: false
  };
  const decision: SastKillSwitchControlDecision = {
    ...core,
    decisionDigest: digestCanonical(
      canonicalizeSastKillSwitchDecision(core)
    )
  };
  return isSastKillSwitchDecisionShapeValid(decision, digestCanonical)
    ? decision
    : null;
}

export function isSastKillSwitchDecisionShapeValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchControlDecision {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'decisionId',
      'selectorKey',
      'selector',
      'sequence',
      'previousDecisionId',
      'previousDecisionDigest',
      'action',
      'reasonCode',
      'incidentRef',
      'actorRef',
      'actorRole',
      'effectiveAt',
      'reviewBy',
      'expiresAt',
      'rollbackTargetRef',
      'signatureRef',
      'provenanceRef',
      'auditRef',
      'source',
      'immutable',
      'customerInputAccepted',
      'repositoryContentStored',
      'findingContentStored',
      'secretValueStored',
      'arbitraryPayloadStored',
      'decisionDigest'
    ]) ||
    value.version !== SAST_KILL_SWITCH_DECISION_VERSION ||
    !isContractId(value.decisionId, 'sast-kill-switch-decision') ||
    !isContractId(value.selectorKey, 'sast-kill-switch-selector') ||
    !isSastKillSwitchSelectorValid(value.selector) ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) < 1 ||
    !SAST_KILL_SWITCH_ACTIONS.includes(value.action as SastKillSwitchAction) ||
    !SAST_KILL_SWITCH_REASON_CODES.includes(value.reasonCode as SastKillSwitchReasonCode) ||
    !isDigestBoundReference(value.incidentRef) ||
    !isDigestBoundReference(value.actorRef) ||
    !SAST_KILL_SWITCH_ACTOR_ROLES.includes(value.actorRole as SastKillSwitchActorRole) ||
    !isCanonicalTimestamp(value.effectiveAt) ||
    !isCanonicalTimestamp(value.reviewBy) ||
    !isCanonicalTimestamp(value.expiresAt) ||
    !isDigestBoundReference(value.rollbackTargetRef) ||
    !isDigestBoundReference(value.signatureRef) ||
    !isDigestBoundReference(value.provenanceRef) ||
    !isDigestBoundReference(value.auditRef) ||
    value.source !== 'PLATFORM_MANAGED' ||
    value.immutable !== true ||
    value.customerInputAccepted !== false ||
    value.repositoryContentStored !== false ||
    value.findingContentStored !== false ||
    value.secretValueStored !== false ||
    value.arbitraryPayloadStored !== false ||
    !isDigest(value.decisionDigest)
  ) {
    return false;
  }
  const decision = value as unknown as SastKillSwitchControlDecision;
  const effective = Date.parse(decision.effectiveAt);
  const review = Date.parse(decision.reviewBy);
  const expires = Date.parse(decision.expiresAt);
  if (
    decision.selectorKey !== buildSastKillSwitchSelectorKey(decision.selector, digestCanonical) ||
    (decision.sequence === 1
      ? decision.previousDecisionId !== null || decision.previousDecisionDigest !== null
      : !isContractId(decision.previousDecisionId, 'sast-kill-switch-decision') ||
        !isDigest(decision.previousDecisionDigest)) ||
    review <= effective ||
    review - effective > 24 * 60 * 60 * 1_000 ||
    expires < review ||
    expires - effective > 30 * 24 * 60 * 60 * 1_000
  ) {
    return false;
  }
  const { decisionDigest, ...core } = decision;
  return digestCanonical(canonicalizeSastKillSwitchDecision(core)) === decisionDigest;
}

export function canonicalizeSastKillSwitchVerification(
  verification: Readonly<SastKillSwitchVerificationCore>
): string {
  return stableJson(verification);
}

export function buildSastKillSwitchVerification(
  input: Omit<
    SastKillSwitchVerificationCore,
    | 'version'
    | 'verificationId'
    | 'signatureVerified'
    | 'provenanceVerified'
    | 'trustedSigner'
    | 'signatureBytesStored'
    | 'provenancePayloadStored'
    | 'repositoryContentStored'
    | 'secretValueStored'
  >,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchVerification | null {
  const identity = digestCanonical(
    stableJson({
      version: SAST_KILL_SWITCH_VERIFICATION_VERSION,
      decisionId: input.decisionId,
      decisionDigest: input.decisionDigest,
      signerIdentity: input.signerIdentity,
      verifiedAt: input.verifiedAt
    })
  );
  const core: SastKillSwitchVerificationCore = {
    version: SAST_KILL_SWITCH_VERIFICATION_VERSION,
    verificationId: `sast-kill-switch-verification://${identity.slice('sha256:'.length)}`,
    decisionId: input.decisionId,
    decisionDigest: input.decisionDigest,
    selectorKey: input.selectorKey,
    signerIdentity: input.signerIdentity,
    signatureRef: input.signatureRef,
    provenanceRef: input.provenanceRef,
    signatureVerified: true,
    provenanceVerified: true,
    trustedSigner: true,
    signatureBytesStored: false,
    provenancePayloadStored: false,
    repositoryContentStored: false,
    secretValueStored: false,
    verifiedAt: input.verifiedAt
  };
  const verification: SastKillSwitchVerification = {
    ...core,
    verificationDigest: digestCanonical(
      canonicalizeSastKillSwitchVerification(core)
    )
  };
  return isSastKillSwitchVerificationShapeValid(verification, digestCanonical)
    ? verification
    : null;
}

export function isSastKillSwitchVerificationShapeValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchVerification {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'verificationId',
      'decisionId',
      'decisionDigest',
      'selectorKey',
      'signerIdentity',
      'signatureRef',
      'provenanceRef',
      'signatureVerified',
      'provenanceVerified',
      'trustedSigner',
      'signatureBytesStored',
      'provenancePayloadStored',
      'repositoryContentStored',
      'secretValueStored',
      'verifiedAt',
      'verificationDigest'
    ]) ||
    value.version !== SAST_KILL_SWITCH_VERIFICATION_VERSION ||
    !isContractId(value.verificationId, 'sast-kill-switch-verification') ||
    !isContractId(value.decisionId, 'sast-kill-switch-decision') ||
    !isDigest(value.decisionDigest) ||
    !isContractId(value.selectorKey, 'sast-kill-switch-selector') ||
    !isBoundedIdentity(value.signerIdentity) ||
    !isDigestBoundReference(value.signatureRef) ||
    !isDigestBoundReference(value.provenanceRef) ||
    value.signatureVerified !== true ||
    value.provenanceVerified !== true ||
    value.trustedSigner !== true ||
    value.signatureBytesStored !== false ||
    value.provenancePayloadStored !== false ||
    value.repositoryContentStored !== false ||
    value.secretValueStored !== false ||
    !isCanonicalTimestamp(value.verifiedAt) ||
    !isDigest(value.verificationDigest)
  ) {
    return false;
  }
  const verification = value as unknown as SastKillSwitchVerification;
  const { verificationDigest, ...core } = verification;
  return digestCanonical(canonicalizeSastKillSwitchVerification(core)) === verificationDigest;
}

export function canonicalizeSastKillSwitchHeadBinding(
  binding: Readonly<SastKillSwitchHeadBindingCore>
): string {
  return stableJson(binding);
}

export function buildSastKillSwitchHeadBinding(
  core: Readonly<SastKillSwitchHeadBindingCore>,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchHeadBinding | null {
  const binding: SastKillSwitchHeadBinding = {
    ...core,
    bindingDigest: digestCanonical(
      canonicalizeSastKillSwitchHeadBinding(core)
    )
  };
  return isSastKillSwitchHeadBindingValid(binding, digestCanonical)
    ? binding
    : null;
}

export function isSastKillSwitchHeadBindingValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchHeadBinding {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'selectorKey',
      'scope',
      'sequence',
      'decisionId',
      'decisionDigest',
      'action',
      'active',
      'effectiveAt',
      'expiresAt',
      'bindingDigest'
    ]) ||
    !isContractId(value.selectorKey, 'sast-kill-switch-selector') ||
    !SAST_KILL_SWITCH_SCOPES.includes(value.scope as never) ||
    !Number.isSafeInteger(value.sequence) ||
    (value.sequence as number) < 0 ||
    typeof value.active !== 'boolean' ||
    !isDigest(value.bindingDigest)
  ) {
    return false;
  }
  const binding = value as unknown as SastKillSwitchHeadBinding;
  const empty = binding.sequence === 0;
  if (
    (empty &&
      (binding.decisionId !== null ||
        binding.decisionDigest !== null ||
        binding.action !== null ||
        binding.active ||
        binding.effectiveAt !== null ||
        binding.expiresAt !== null)) ||
    (!empty &&
      (!isContractId(binding.decisionId, 'sast-kill-switch-decision') ||
        !isDigest(binding.decisionDigest) ||
        !SAST_KILL_SWITCH_ACTIONS.includes(binding.action as SastKillSwitchAction) ||
        !isCanonicalTimestamp(binding.effectiveAt) ||
        !isCanonicalTimestamp(binding.expiresAt) ||
        binding.active !== (binding.action === 'ACTIVATE')))
  ) {
    return false;
  }
  const { bindingDigest, ...core } = binding;
  return digestCanonical(canonicalizeSastKillSwitchHeadBinding(core)) === bindingDigest;
}

export function canonicalizeSastKillSwitchEvaluationMatch(
  match: Readonly<SastKillSwitchEvaluationMatchCore>
): string {
  return stableJson(match);
}

export function buildSastKillSwitchEvaluationMatch(
  core: Readonly<SastKillSwitchEvaluationMatchCore>,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchEvaluationMatch | null {
  const match: SastKillSwitchEvaluationMatch = {
    ...core,
    bindingDigest: digestCanonical(
      canonicalizeSastKillSwitchEvaluationMatch(core)
    )
  };
  return isSastKillSwitchEvaluationMatchValid(match, digestCanonical)
    ? match
    : null;
}

export function isSastKillSwitchEvaluationMatchValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchEvaluationMatch {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'selectorKey',
      'scope',
      'decisionId',
      'decisionDigest',
      'bindingDigest'
    ]) ||
    !isContractId(value.selectorKey, 'sast-kill-switch-selector') ||
    !SAST_KILL_SWITCH_SCOPES.includes(value.scope as never) ||
    !isContractId(value.decisionId, 'sast-kill-switch-decision') ||
    !isDigest(value.decisionDigest) ||
    !isDigest(value.bindingDigest)
  ) {
    return false;
  }
  const match = value as unknown as SastKillSwitchEvaluationMatch;
  const { bindingDigest, ...core } = match;
  return digestCanonical(canonicalizeSastKillSwitchEvaluationMatch(core)) === bindingDigest;
}

export function canonicalizeSastKillSwitchEvaluationReceipt(
  receipt: Readonly<SastKillSwitchEvaluationReceiptCore>
): string {
  return stableJson(receipt);
}

export function buildSastKillSwitchEvaluation(
  input: {
    context: Readonly<SastKillSwitchEvaluationContext>;
    gate: SastKillSwitchGate;
    heads: readonly Readonly<SastKillSwitchHeadBinding>[];
    evaluatedAt: string;
  },
  digestCanonical: SastKillSwitchCanonicalDigester
): Omit<SastKillSwitchEvaluationResult, 'replayed'> | null {
  if (
    !isSastKillSwitchEvaluationContextValid(input.context, digestCanonical) ||
    !SAST_KILL_SWITCH_GATES.includes(input.gate) ||
    !isCanonicalTimestamp(input.evaluatedAt) ||
    input.heads.length < 1 ||
    input.heads.length > SAST_KILL_SWITCH_MAX_SELECTOR_BINDINGS ||
    input.heads.some((head) => !isSastKillSwitchHeadBindingValid(head, digestCanonical)) ||
    !isCanonicalBy(input.heads, (head) => head.selectorKey) ||
    input.heads.some(
      (head) => head.active && Date.parse(head.expiresAt!) <= Date.parse(input.evaluatedAt)
    )
  ) {
    return null;
  }
  const heads = input.heads.map((head) => ({ ...head }));
  const matches = heads
    .filter((head) => head.active)
    .map((head) =>
      buildSastKillSwitchEvaluationMatch(
        {
          selectorKey: head.selectorKey,
          scope: head.scope,
          decisionId: head.decisionId!,
          decisionDigest: head.decisionDigest!
        },
        digestCanonical
      )
    );
  if (matches.some((match) => match === null)) return null;
  const exactMatches = matches as SastKillSwitchEvaluationMatch[];
  const headSetDigest = digestCanonical(
    stableJson(heads.map((head) => ({
      selectorKey: head.selectorKey,
      bindingDigest: head.bindingDigest
    })))
  );
  const matchedDecisionSetDigest = digestCanonical(
    stableJson(exactMatches.map((match) => ({
      selectorKey: match.selectorKey,
      decisionId: match.decisionId,
      decisionDigest: match.decisionDigest,
      bindingDigest: match.bindingDigest
    })))
  );
  const snapshotDigest = digestCanonical(
    stableJson({
      version: SAST_KILL_SWITCH_EVALUATION_VERSION,
      gate: input.gate,
      contextDigest: input.context.contextDigest,
      headSetDigest,
      matchedDecisionSetDigest
    })
  );
  const identity = digestCanonical(
    stableJson({
      gate: input.gate,
      contextDigest: input.context.contextDigest,
      snapshotDigest,
      evaluatedAt: input.evaluatedAt
    })
  );
  const activeScopes = exactMatches.map((match) => match.scope);
  const coverageEffect: SastKillSwitchCoverageEffect =
    exactMatches.length === 0 ||
    activeScopes.every((scope) => scope === 'EXTERNAL_PUBLICATION')
      ? 'UNCHANGED'
      : activeScopes.every(
            (scope) => scope === 'SEMANTIC_RULE' || scope === 'CAPABILITY'
          )
        ? 'PARTIAL'
        : 'FAILED';
  const core: SastKillSwitchEvaluationReceiptCore = {
    version: SAST_KILL_SWITCH_EVALUATION_VERSION,
    evaluationId: `sast-kill-switch-evaluation://${identity.slice('sha256:'.length)}`,
    gate: input.gate,
    tenantId: input.context.tenantId,
    repositoryBindingId: input.context.repositoryBindingId,
    scanRequestId: input.context.scanRequestId,
    profileId: input.context.profileId,
    profileDigest: input.context.profileDigest,
    scannerSetDigest: input.context.scannerSetDigest,
    contextDigest: input.context.contextDigest,
    snapshotDigest,
    headCount: heads.length,
    headSetDigest,
    matchedDecisionCount: exactMatches.length,
    matchedDecisionSetDigest,
    outcome: exactMatches.length === 0 ? 'CLEAR' : 'ACTIVE',
    coverageEffect,
    evaluatedAt: input.evaluatedAt,
    customerInputAccepted: false,
    repositoryContentStored: false,
    findingContentStored: false,
    secretValueStored: false,
    arbitraryPayloadStored: false
  };
  const receipt: SastKillSwitchEvaluationReceipt = {
    ...core,
    receiptDigest: digestCanonical(
      canonicalizeSastKillSwitchEvaluationReceipt(core)
    )
  };
  return isSastKillSwitchEvaluationReceiptValid(receipt, digestCanonical)
    ? { receipt, heads, matches: exactMatches }
    : null;
}

export function isSastKillSwitchEvaluationReceiptValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchEvaluationReceipt {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'evaluationId',
      'gate',
      'tenantId',
      'repositoryBindingId',
      'scanRequestId',
      'profileId',
      'profileDigest',
      'scannerSetDigest',
      'contextDigest',
      'snapshotDigest',
      'headCount',
      'headSetDigest',
      'matchedDecisionCount',
      'matchedDecisionSetDigest',
      'outcome',
      'coverageEffect',
      'evaluatedAt',
      'customerInputAccepted',
      'repositoryContentStored',
      'findingContentStored',
      'secretValueStored',
      'arbitraryPayloadStored',
      'receiptDigest'
    ]) ||
    value.version !== SAST_KILL_SWITCH_EVALUATION_VERSION ||
    !isContractId(value.evaluationId, 'sast-kill-switch-evaluation') ||
    !SAST_KILL_SWITCH_GATES.includes(value.gate as SastKillSwitchGate) ||
    !isBoundedIdentity(value.tenantId) ||
    !isBoundedIdentity(value.repositoryBindingId) ||
    !isBoundedIdentity(value.scanRequestId) ||
    !PROFILES.includes(value.profileId as SastProfileId) ||
    !isDigest(value.profileDigest) ||
    !isDigest(value.scannerSetDigest) ||
    !isDigest(value.contextDigest) ||
    !isDigest(value.snapshotDigest) ||
    !Number.isSafeInteger(value.headCount) ||
    (value.headCount as number) < 1 ||
    (value.headCount as number) > SAST_KILL_SWITCH_MAX_SELECTOR_BINDINGS ||
    !isDigest(value.headSetDigest) ||
    !Number.isSafeInteger(value.matchedDecisionCount) ||
    (value.matchedDecisionCount as number) < 0 ||
    (value.matchedDecisionCount as number) > (value.headCount as number) ||
    !isDigest(value.matchedDecisionSetDigest) ||
    !SAST_KILL_SWITCH_EVALUATION_OUTCOMES.includes(value.outcome as SastKillSwitchEvaluationOutcome) ||
    !SAST_KILL_SWITCH_COVERAGE_EFFECTS.includes(value.coverageEffect as SastKillSwitchCoverageEffect) ||
    !isCanonicalTimestamp(value.evaluatedAt) ||
    value.customerInputAccepted !== false ||
    value.repositoryContentStored !== false ||
    value.findingContentStored !== false ||
    value.secretValueStored !== false ||
    value.arbitraryPayloadStored !== false ||
    !isDigest(value.receiptDigest)
  ) {
    return false;
  }
  const receipt = value as unknown as SastKillSwitchEvaluationReceipt;
  if (
    (receipt.outcome === 'CLEAR') !== (receipt.matchedDecisionCount === 0) ||
    (receipt.outcome === 'CLEAR' && receipt.coverageEffect !== 'UNCHANGED')
  ) {
    return false;
  }
  const { receiptDigest, ...core } = receipt;
  return digestCanonical(canonicalizeSastKillSwitchEvaluationReceipt(core)) === receiptDigest;
}

export function toSastKillSwitchPlanningDescriptor(
  receipt: Readonly<SastKillSwitchEvaluationReceipt>
): SastKillSwitchPlanningDescriptor | null {
  if (receipt.gate !== 'PLANNING' || receipt.outcome !== 'CLEAR') return null;
  const descriptor: SastKillSwitchPlanningDescriptor = {
    version: SAST_KILL_SWITCH_PLANNING_VERSION,
    evaluationId: receipt.evaluationId,
    evaluationReceiptDigest: receipt.receiptDigest,
    contextDigest: receipt.contextDigest,
    snapshotDigest: receipt.snapshotDigest,
    headSetDigest: receipt.headSetDigest,
    evaluatedAt: receipt.evaluatedAt,
    outcome: 'CLEAR'
  };
  return isSastKillSwitchPlanningDescriptorValid(descriptor)
    ? descriptor
    : null;
}

export function isSastKillSwitchPlanningDescriptorValid(
  value: unknown
): value is SastKillSwitchPlanningDescriptor {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'evaluationId',
      'evaluationReceiptDigest',
      'contextDigest',
      'snapshotDigest',
      'headSetDigest',
      'evaluatedAt',
      'outcome'
    ]) &&
    value.version === SAST_KILL_SWITCH_PLANNING_VERSION &&
    isContractId(value.evaluationId, 'sast-kill-switch-evaluation') &&
    isDigest(value.evaluationReceiptDigest) &&
    isDigest(value.contextDigest) &&
    isDigest(value.snapshotDigest) &&
    isDigest(value.headSetDigest) &&
    isCanonicalTimestamp(value.evaluatedAt) &&
    value.outcome === 'CLEAR'
  );
}

export function isSastKillSwitchCanarySuspensionRequestValid(
  value: unknown
): value is SastKillSwitchCanarySuspensionRequest {
  return (
    isRecord(value) &&
    hasExactKeys(value, [
      'version',
      'canaryDecisionId',
      'canaryDecisionDigest'
    ]) &&
    value.version === SAST_KILL_SWITCH_CANARY_SUSPENSION_REQUEST_VERSION &&
    isContractId(
      value.canaryDecisionId,
      'sast-rule-bundle-canary-step-decision'
    ) &&
    isDigest(value.canaryDecisionDigest)
  );
}

export function canonicalizeSastKillSwitchCanarySuspensionSignal(
  signal: Readonly<SastKillSwitchCanarySuspensionSignalCore>
): string {
  return stableJson(signal);
}

export function buildSastKillSwitchCanarySuspensionSignal(
  input: Readonly<SastKillSwitchCanarySuspensionSignalInput>,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchCanarySuspensionSignal | null {
  const reasonCodes = [...input.reasonCodes];
  const core: SastKillSwitchCanarySuspensionSignalCore = {
    version: SAST_KILL_SWITCH_CANARY_SUSPENSION_SIGNAL_VERSION,
    source: 'DURABLE_T048_CANARY_DECISION',
    trigger: reasonCodes.includes('ZERO_TOLERANCE_EVENT_RECORDED')
      ? 'ZERO_TOLERANCE'
      : 'CANARY_PAUSED',
    ...input,
    reasonCodes,
    customerTargetAccepted: false,
    repositoryContentStored: false,
    findingContentStored: false,
    secretValueStored: false,
    arbitraryPayloadStored: false
  };
  const signalDigest = digestCanonical(
    canonicalizeSastKillSwitchCanarySuspensionSignal(core)
  );
  const signal: SastKillSwitchCanarySuspensionSignal = {
    ...core,
    signalId:
      `sast-kill-switch-canary-suspension://${signalDigest.slice('sha256:'.length)}`,
    signalDigest
  };
  return isSastKillSwitchCanarySuspensionSignalValid(signal, digestCanonical)
    ? signal
    : null;
}

export function isSastKillSwitchCanarySuspensionSignalValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchCanarySuspensionSignal {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'signalId',
      'source',
      'trigger',
      'canaryDecisionId',
      'canaryDecisionDigest',
      'rolloutId',
      'rolloutDigest',
      'candidateManifestId',
      'candidateManifestDigest',
      'candidateBundleId',
      'candidateBundleDigest',
      'profileId',
      'profileDigest',
      'lifecycleTransitionId',
      'lifecycleTransitionDigest',
      'lifecycleState',
      'reasonCodes',
      'observedAt',
      'customerTargetAccepted',
      'repositoryContentStored',
      'findingContentStored',
      'secretValueStored',
      'arbitraryPayloadStored',
      'signalDigest'
    ]) ||
    value.version !== SAST_KILL_SWITCH_CANARY_SUSPENSION_SIGNAL_VERSION ||
    !isContractId(value.signalId, 'sast-kill-switch-canary-suspension') ||
    value.source !== 'DURABLE_T048_CANARY_DECISION' ||
    (value.trigger !== 'CANARY_PAUSED' && value.trigger !== 'ZERO_TOLERANCE') ||
    !isContractId(
      value.canaryDecisionId,
      'sast-rule-bundle-canary-step-decision'
    ) ||
    !isDigest(value.canaryDecisionDigest) ||
    !isBoundedIdentity(value.rolloutId) ||
    !isDigest(value.rolloutDigest) ||
    !isBoundedIdentity(value.candidateManifestId) ||
    !isDigest(value.candidateManifestDigest) ||
    !isBoundedIdentity(value.candidateBundleId) ||
    !isDigest(value.candidateBundleDigest) ||
    !PROFILES.includes(value.profileId as SastProfileId) ||
    !isDigest(value.profileDigest) ||
    !isBoundedIdentity(value.lifecycleTransitionId) ||
    !isDigest(value.lifecycleTransitionDigest) ||
    value.lifecycleState !== 'CANARY' ||
    !Array.isArray(value.reasonCodes) ||
    value.reasonCodes.length < 1 ||
    value.reasonCodes.some(
      (reason) =>
        !SAST_KILL_SWITCH_CANARY_SUSPENSION_REASON_CODES.includes(
          reason as SastKillSwitchCanarySuspensionReasonCode
        )
    ) ||
    !isCanonicalBy(value.reasonCodes, (reason) =>
      String(SAST_KILL_SWITCH_CANARY_SUSPENSION_REASON_CODES.indexOf(
        reason as SastKillSwitchCanarySuspensionReasonCode
      ))
    ) ||
    !isCanonicalTimestamp(value.observedAt) ||
    value.customerTargetAccepted !== false ||
    value.repositoryContentStored !== false ||
    value.findingContentStored !== false ||
    value.secretValueStored !== false ||
    value.arbitraryPayloadStored !== false ||
    !isDigest(value.signalDigest)
  ) {
    return false;
  }
  const signal = value as unknown as SastKillSwitchCanarySuspensionSignal;
  const zeroTolerance = signal.reasonCodes.includes(
    'ZERO_TOLERANCE_EVENT_RECORDED'
  );
  if (
    (signal.trigger === 'ZERO_TOLERANCE') !== zeroTolerance ||
    signal.signalId !==
      `sast-kill-switch-canary-suspension://${signal.signalDigest.slice('sha256:'.length)}`
  ) {
    return false;
  }
  const { signalId: _signalId, signalDigest, ...core } = signal;
  void _signalId;
  return (
    digestCanonical(
      canonicalizeSastKillSwitchCanarySuspensionSignal(core)
    ) === signalDigest
  );
}

export function canonicalizeSastKillSwitchEmergencySuspensionReceipt(
  receipt: Readonly<SastKillSwitchEmergencySuspensionReceiptCore>
): string {
  const { receiptId: _receiptId, receiptRef: _receiptRef, ...digestCore } =
    receipt;
  void _receiptId;
  void _receiptRef;
  return stableJson(digestCore);
}

export function buildSastKillSwitchEmergencySuspensionReceipt(
  input: Readonly<SastKillSwitchEmergencySuspensionReceiptInput>,
  digestCanonical: SastKillSwitchCanonicalDigester
): SastKillSwitchEmergencySuspensionReceipt | null {
  const digestCore: SastKillSwitchEmergencySuspensionReceiptDigestCore = {
    version: SAST_KILL_SWITCH_EMERGENCY_SUSPENSION_VERSION,
    ...input,
    customerInputAccepted: false,
    repositoryContentStored: false,
    findingContentStored: false,
    secretValueStored: false
  };
  const receiptDigest = digestCanonical(stableJson(digestCore));
  const receiptRef =
    `sast-kill-switch-suspension://authority/${receiptDigest}`;
  const receipt: SastKillSwitchEmergencySuspensionReceipt = {
    ...digestCore,
    receiptId: receiptRef,
    receiptRef,
    receiptDigest
  };
  return isSastKillSwitchEmergencySuspensionReceiptValid(
    receipt,
    digestCanonical
  )
    ? receipt
    : null;
}

export function isSastKillSwitchEmergencySuspensionReceiptValid(
  value: unknown,
  digestCanonical: SastKillSwitchCanonicalDigester
): value is SastKillSwitchEmergencySuspensionReceipt {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'version',
      'receiptId',
      'receiptRef',
      'manifestId',
      'manifestDigest',
      'bundleId',
      'bundleDigest',
      'fromState',
      'toState',
      'lifecycleSequence',
      'lifecycleTransitionId',
      'lifecycleTransitionDigest',
      'promotionEvidenceId',
      'promotionEvidenceDigest',
      'triggerSelectorKey',
      'triggerDecisionId',
      'triggerDecisionDigest',
      'activeDecisionCount',
      'activeDecisionSetDigest',
      'requestedAt',
      'verifiedAt',
      'customerInputAccepted',
      'repositoryContentStored',
      'findingContentStored',
      'secretValueStored',
      'receiptDigest'
    ]) ||
    value.version !== SAST_KILL_SWITCH_EMERGENCY_SUSPENSION_VERSION ||
    value.receiptId !==
      `sast-kill-switch-suspension://authority/${String(value.receiptDigest)}` ||
    value.receiptRef !== value.receiptId ||
    !isBoundedIdentity(value.manifestId) ||
    !isDigest(value.manifestDigest) ||
    !isBoundedIdentity(value.bundleId) ||
    !isDigest(value.bundleDigest) ||
    (value.fromState !== 'CANARY' && value.fromState !== 'ACTIVE') ||
    value.toState !== 'SUSPENDED' ||
    !Number.isSafeInteger(value.lifecycleSequence) ||
    (value.lifecycleSequence as number) < 1 ||
    !isBoundedIdentity(value.lifecycleTransitionId) ||
    !isDigest(value.lifecycleTransitionDigest) ||
    !isBoundedIdentity(value.promotionEvidenceId) ||
    !isDigest(value.promotionEvidenceDigest) ||
    !isContractId(value.triggerSelectorKey, 'sast-kill-switch-selector') ||
    !isContractId(value.triggerDecisionId, 'sast-kill-switch-decision') ||
    !isDigest(value.triggerDecisionDigest) ||
    !Number.isSafeInteger(value.activeDecisionCount) ||
    (value.activeDecisionCount as number) < 1 ||
    !isDigest(value.activeDecisionSetDigest) ||
    !isCanonicalTimestamp(value.requestedAt) ||
    !isCanonicalTimestamp(value.verifiedAt) ||
    value.verifiedAt !== value.requestedAt ||
    value.customerInputAccepted !== false ||
    value.repositoryContentStored !== false ||
    value.findingContentStored !== false ||
    value.secretValueStored !== false ||
    !isDigest(value.receiptDigest)
  ) {
    return false;
  }
  const receipt = value as unknown as SastKillSwitchEmergencySuspensionReceipt;
  const { receiptDigest, ...core } = receipt;
  return digestCanonical(canonicalizeSastKillSwitchEmergencySuspensionReceipt(core)) === receiptDigest;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isBoundedIdentity(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= 512 &&
    value.trim() === value &&
    !/\p{Cc}/u.test(value)
  );
}

function isDigest(value: unknown): value is `sha256:${string}` {
  return typeof value === 'string' && /^sha256:[a-f0-9]{64}$/u.test(value);
}

function isContractId(value: unknown, prefix: string): value is string {
  return typeof value === 'string' && new RegExp(`^${prefix}://[a-f0-9]{64}$`, 'u').test(value);
}

function isDigestBoundReference(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= 2048 &&
    /^[a-z][a-z0-9+.-]*:\/\/[^\s]+\/sha256:[a-f0-9]{64}$/u.test(value) &&
    !/^https?:\/\//u.test(value)
  );
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function isCanonicalStrings(values: readonly string[]): boolean {
  return isCanonicalBy(values, (value) => value);
}

function isCanonicalBy<T>(values: readonly T[], key: (value: T) => string): boolean {
  const keys = values.map(key);
  return keys.every((value, index) => index === 0 || keys[index - 1]! < value);
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
