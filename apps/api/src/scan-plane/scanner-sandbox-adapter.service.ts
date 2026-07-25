import {
  SAST_ARTIFACT_SCHEMA_VERSIONS,
  SAST_SCANNER_ASSET_ROOT,
  SAST_SCANNER_OUTPUT_ROOT,
  SAST_SCANNER_SELECTED_WORKSPACE_ROOT,
  SAST_SCANNER_WORKING_DIRECTORY,
  SAST_SCANNER_WORKSPACE_ROOT,
  SAST_SCANNER_WRAPPER_SCHEMA_VERSION,
  isSastScannerInvocationBoundToPlan,
  isSastScannerWrapperExecutionRequestValid,
  scannerRuntimeLimits,
  type RuleBundleDescriptor,
  type SastArtifactSchema,
  type SastSandboxRuntimePolicy,
  type SastScannerInvocation,
  type SastScannerKind,
  type SastScannerWrapperExecutionRequest,
  type SastScanPlan
} from '@aegisai/shared';
import { BadRequestException, Injectable } from '@nestjs/common';

const SCANNER_BINARIES: Readonly<Record<SastScannerKind, string>> =
  Object.freeze({
    OPENGREP: '/opt/aegis/scanners/opengrep',
    TRIVY: '/opt/aegis/scanners/trivy',
    SYFT: '/opt/aegis/scanners/syft'
  });

const COMMON_ENVIRONMENT: Readonly<Record<string, string>> = Object.freeze({
  HOME: '/nonexistent',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  NO_COLOR: '1',
  TMPDIR: `${SAST_SCANNER_OUTPUT_ROOT}/tmp`,
  TZ: 'UTC',
  XDG_CONFIG_HOME: '/nonexistent'
});

@Injectable()
export class ScannerSandboxAdapterService {
  buildPolicy(plan: SastScanPlan): SastSandboxRuntimePolicy {
    return this.deepFreeze({
      sandboxProvider: 'MICROVM',
      isolationClass: plan.isolationClass,
      runAsNonRoot: true,
      readOnlyRootFilesystem: true,
      readOnlyRepository: true,
      privateWritableOutput: true,
      shellInterpolationAllowed: false,
      customerEnvironmentAllowed: false,
      customerExecutableConfigAllowed: false,
      customerSuppressionConfigAllowed: false,
      repositoryToolConfigDiscoveryAllowed: false,
      packageInstallAllowed: false,
      repositoryBuildAllowed: false,
      dynamicExecutionAllowed: false,
      runtimeAssetUpdateAllowed: false,
      publicInternetEgressAllowed: false,
      cloudMetadataAccessAllowed: false,
      networkEgressPolicy: 'RESULT_INGRESS_AND_TELEMETRY_ONLY',
      resourceLimits: scannerRuntimeLimits(plan.profile.limits)
    });
  }

  buildInvocations(
    request: SastScannerWrapperExecutionRequest
  ): SastScannerInvocation[] {
    if (!isSastScannerWrapperExecutionRequestValid(request)) {
      throw new BadRequestException(
        'Scanner wrapper request is not bound to an approved immutable plan.'
      );
    }

    const policy = this.buildPolicy(request.plan);
    return request.plan.profile.requiredScanners.map((scanner) => {
      const invocation = this.buildInvocation(
        scanner,
        request.plan,
        policy,
        request.preflight
      );
      if (
        !isSastScannerInvocationBoundToPlan(
          invocation,
          request.plan,
          request.preflight
        )
      ) {
        throw new BadRequestException(
          `Generated ${scanner} invocation is not bound to the immutable plan.`
        );
      }
      return this.deepFreeze(invocation);
    });
  }

  private buildInvocation(
    scanner: SastScannerKind,
    plan: SastScanPlan,
    policy: SastSandboxRuntimePolicy,
    preflight: SastScannerWrapperExecutionRequest['preflight']
  ): SastScannerInvocation {
    const descriptor = plan.scannerSet.scanners[scanner];
    const ruleBundle =
      scanner === 'SYFT'
        ? undefined
        : this.requiredRuleBundle(plan, scanner);
    const outputPath = this.outputPath(scanner);
    const scannerInputPath = this.scannerInputPath(plan, preflight);
    const artifactSchema = this.artifactSchema(scanner);

    return {
      wrapperSchemaVersion: SAST_SCANNER_WRAPPER_SCHEMA_VERSION,
      scanner,
      required: true,
      executable: SCANNER_BINARIES[scanner],
      args: this.argumentsFor(
        scanner,
        plan,
        ruleBundle,
        outputPath,
        scannerInputPath
      ),
      environment: this.environmentFor(scanner, plan),
      workingDirectory: SAST_SCANNER_WORKING_DIRECTORY,
      scannerInputPath,
      outputPath,
      artifactSchema,
      artifactSchemaVersion:
        SAST_ARTIFACT_SCHEMA_VERSIONS[artifactSchema],
      schemaBundleDigest: plan.scannerSet.schemaBundle.digest,
      normalizerBundleDigest: plan.scannerSet.normalizerBundle.digest,
      scannerVersion: descriptor.version,
      scannerImageDigest: descriptor.digest,
      wrapperDigest: descriptor.wrapper.digest,
      ruleBundleDigest: ruleBundle?.digest,
      vulnerabilityDatabaseDigest:
        scanner === 'TRIVY'
          ? plan.scannerSet.vulnerabilityDatabase.digest
          : undefined,
      scannerSetDigest: plan.scannerSet.scannerSetDigest,
      profileId: plan.profile.id,
      profileDigest: plan.profileDigest,
      preflightAttestationRef: preflight.attestationRef,
      preflightInventoryDigest: preflight.inventoryDigest,
      sandboxPolicy: policy
    };
  }

  private argumentsFor(
    scanner: SastScannerKind,
    plan: SastScanPlan,
    ruleBundle: RuleBundleDescriptor | undefined,
    outputPath: string,
    scannerInputPath: string
  ): readonly string[] {
    if (scanner === 'OPENGREP') {
      return Object.freeze([
        'scan',
        '-f',
        this.ruleAssetPath('opengrep', ruleBundle!),
        `--sarif-output=${outputPath}`,
        '--no-autofix',
        '--disable-nosem',
        '--no-git-ignore',
        '--x-ignore-semgrepignore-files',
        '--disable-version-check',
        '--strict',
        '--jobs=1',
        `--max-memory=${plan.profile.limits.memoryMiB}`,
        `--max-target-bytes=${plan.profile.limits.maxSingleFileBytes}`,
        scannerInputPath
      ]);
    }

    if (scanner === 'TRIVY') {
      const cachePath = [
        SAST_SCANNER_ASSET_ROOT,
        'trivy',
        this.digestId(plan.scannerSet.vulnerabilityDatabase.digest),
        this.digestId(ruleBundle!.digest)
      ].join('/');
      const wrapperAssetRoot = this.wrapperAssetRoot(
        scanner,
        plan.scannerSet.scanners.TRIVY.wrapper.digest
      );
      return Object.freeze([
        'filesystem',
        '--config',
        `${wrapperAssetRoot}/config.yaml`,
        '--format',
        'json',
        '--output',
        outputPath,
        '--scanners',
        'vuln,misconfig,secret',
        '--cache-dir',
        cachePath,
        '--ignorefile',
        `${wrapperAssetRoot}/empty.trivyignore`,
        '--secret-config',
        `${SAST_SCANNER_ASSET_ROOT}/rules/trivy/${this.digestId(
          ruleBundle!.digest
        )}/secret.yaml`,
        '--show-suppressed',
        '--timeout',
        `${plan.profile.limits.wallClockTimeoutSeconds}s`,
        '--parallel',
        '1',
        '--quiet',
        '--no-progress',
        '--offline-scan',
        '--skip-db-update',
        '--skip-java-db-update',
        '--skip-check-update',
        '--skip-vex-repo-update',
        '--disable-telemetry',
        '--skip-version-check',
        scannerInputPath
      ]);
    }

    const wrapperAssetRoot = this.wrapperAssetRoot(
      scanner,
      plan.scannerSet.scanners.SYFT.wrapper.digest
    );
    return Object.freeze([
      `dir:${scannerInputPath}`,
      '--config',
      `${wrapperAssetRoot}/config.yaml`,
      '--output',
      `cyclonedx-json=${outputPath}`
    ]);
  }

  private environmentFor(
    scanner: SastScannerKind,
    plan: SastScanPlan
  ): Readonly<Record<string, string>> {
    if (scanner !== 'SYFT') {
      return COMMON_ENVIRONMENT;
    }

    return Object.freeze({
      ...COMMON_ENVIRONMENT,
      SYFT_CHECK_FOR_APP_UPDATE: 'false',
      SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES: 'false',
      SYFT_GOLANG_SEARCH_REMOTE_LICENSES: 'false',
      SYFT_GOLANG_USE_PACKAGES_LIB: 'false',
      SYFT_JAVA_USE_NETWORK: 'false',
      SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY: 'false',
      SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES: 'false',
      SYFT_LICENSE_CONTENT: 'none',
      SYFT_LOG_QUIET: 'true',
      SYFT_PACKAGE_SEARCH_INDEXED_ARCHIVES: 'false',
      SYFT_PACKAGE_SEARCH_UNINDEXED_ARCHIVES: 'false',
      SYFT_PARALLELISM: '1',
      SYFT_PYTHON_SEARCH_REMOTE_LICENSES: 'false',
      SYFT_FILE_CONTENT_SKIP_FILES_ABOVE_SIZE:
        String(plan.profile.limits.maxSingleFileBytes)
    });
  }

  private scannerInputPath(
    plan: SastScanPlan,
    preflight: SastScannerWrapperExecutionRequest['preflight']
  ): string {
    return plan.profile.scope === 'CHANGED_FILES_WITH_CONTEXT'
      ? `${SAST_SCANNER_SELECTED_WORKSPACE_ROOT}/${this.digestId(
          preflight.inventoryDigest
        )}`
      : SAST_SCANNER_WORKSPACE_ROOT;
  }

  private requiredRuleBundle(
    plan: SastScanPlan,
    scanner: Exclude<SastScannerKind, 'SYFT'>
  ): RuleBundleDescriptor {
    const bundles = plan.scannerSet.ruleBundles.filter(
      (bundle) => bundle.scanner === scanner
    );
    if (bundles.length !== 1) {
      throw new BadRequestException(
        `${scanner} requires exactly one immutable rule bundle.`
      );
    }
    return bundles[0];
  }

  private ruleAssetPath(
    scanner: 'opengrep',
    bundle: RuleBundleDescriptor
  ): string {
    return `${SAST_SCANNER_ASSET_ROOT}/rules/${scanner}/${this.digestId(
      bundle.digest
    )}`;
  }

  private outputPath(scanner: SastScannerKind): string {
    if (scanner === 'OPENGREP') {
      return `${SAST_SCANNER_OUTPUT_ROOT}/opengrep.sarif`;
    }
    if (scanner === 'TRIVY') {
      return `${SAST_SCANNER_OUTPUT_ROOT}/trivy.json`;
    }
    return `${SAST_SCANNER_OUTPUT_ROOT}/syft.cdx.json`;
  }

  private artifactSchema(scanner: SastScannerKind): SastArtifactSchema {
    return scanner === 'OPENGREP'
      ? 'OPENGREP_SARIF'
      : scanner === 'TRIVY'
        ? 'TRIVY_JSON'
        : 'CYCLONEDX_JSON';
  }

  private digestId(digest: `sha256:${string}`): string {
    return digest.slice('sha256:'.length);
  }

  private wrapperAssetRoot(
    scanner: SastScannerKind,
    wrapperDigest: `sha256:${string}`
  ): string {
    return `${SAST_SCANNER_ASSET_ROOT}/wrappers/${scanner.toLowerCase()}/${this.digestId(
      wrapperDigest
    )}`;
  }

  private deepFreeze<T>(value: T): T {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      for (const nested of Object.values(value)) {
        this.deepFreeze(nested);
      }
      Object.freeze(value);
    }
    return value;
  }
}
