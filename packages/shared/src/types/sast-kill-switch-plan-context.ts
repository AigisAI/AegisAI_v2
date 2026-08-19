import {
  SAST_SCANNER_KINDS,
  SAST_SCANNER_RESPONSIBILITIES,
  type SastCapability,
  type SastProfileId,
  type SastScannerKind
} from './sast-runtime';
import {
  buildSastKillSwitchEvaluationContext,
  type SastKillSwitchCanonicalDigester,
  type SastKillSwitchEvaluationContext
} from './sast-kill-switch';

export interface SastKillSwitchPlanContextParts {
  tenantId: string;
  repositoryBindingId: string;
  scanRequestId: string;
  profile: {
    id: SastProfileId;
    requiredCapabilities: readonly SastCapability[];
  };
  profileDigest: `sha256:${string}`;
  scannerSet: {
    scannerSetDigest: `sha256:${string}`;
    scanners: Record<SastScannerKind, { version: string }>;
    ruleBundles: readonly {
      scanner: SastScannerKind;
      digest: `sha256:${string}`;
      rules: readonly { ruleSemanticId: string }[];
    }[];
  };
}

export function buildSastKillSwitchContextFromPlanParts(
  parts: Readonly<SastKillSwitchPlanContextParts>,
  digestCanonical: SastKillSwitchCanonicalDigester,
  onlyScanner?: SastScannerKind
): SastKillSwitchEvaluationContext | null {
  if (
    onlyScanner !== undefined &&
    !SAST_SCANNER_KINDS.includes(onlyScanner)
  ) {
    return null;
  }

  const selectedScanners = SAST_SCANNER_KINDS.filter(
    (scanner) => onlyScanner === undefined || scanner === onlyScanner
  );
  const scanners: Array<{
    scanner: SastScannerKind;
    scannerVersion: string;
  }> = [];
  for (const scanner of selectedScanners) {
    const descriptor = parts.scannerSet.scanners[scanner];
    if (!descriptor || typeof descriptor.version !== 'string') {
      return null;
    }
    scanners.push({ scanner, scannerVersion: descriptor.version });
  }
  scanners.sort((left, right) => compare(left.scanner, right.scanner));
  const ruleBundles = parts.scannerSet.ruleBundles
    .filter(
      (bundle) => onlyScanner === undefined || bundle.scanner === onlyScanner
    )
    .map((bundle) => ({
      bundleDigest: bundle.digest,
      ruleSemanticIds: [
        ...new Set(bundle.rules.map((rule) => rule.ruleSemanticId))
      ].sort(compare)
    }))
    .sort((left, right) => compare(left.bundleDigest, right.bundleDigest));
  const ownedCapabilities = onlyScanner
    ? (SAST_SCANNER_RESPONSIBILITIES[onlyScanner]
        .authoritativeCapabilities as readonly SastCapability[])
    : parts.profile.requiredCapabilities;
  const requiredCapabilities = parts.profile.requiredCapabilities.filter(
    (capability) => ownedCapabilities.includes(capability)
  );

  return buildSastKillSwitchEvaluationContext(
    {
      tenantId: parts.tenantId,
      repositoryBindingId: parts.repositoryBindingId,
      scanRequestId: parts.scanRequestId,
      profileId: parts.profile.id,
      profileDigest: parts.profileDigest,
      scannerSetDigest: parts.scannerSet.scannerSetDigest,
      scanners,
      ruleBundles,
      requiredCapabilities
    },
    digestCanonical
  );
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
