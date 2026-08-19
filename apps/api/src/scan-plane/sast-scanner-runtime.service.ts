import { createHash, randomUUID } from 'node:crypto';

import {
  SAST_SANDBOX_CLEANUP_TIMEOUT_SECONDS,
  deriveScannerExecutionStatus,
  isSastScannerProcessObservationValid,
  isSastScannerWrapperExecutionRequestValid,
  type SastScannerExecutionRecord,
  type SastScannerInvocation,
  type SastScannerProcessObservation,
  type SastScannerRuntimeAuditSignal,
  type SastScannerRuntimeExecutionResult,
  type SastScannerWrapperExecutionRequest,
  type SastSignedSandboxCleanupObservation
} from '@aegisai/shared';
import { Injectable } from '@nestjs/common';

import { ControlPlaneService } from '../control-plane/control-plane.service';
import { SastKillSwitchGate } from '../rule-governance/sast-kill-switch.gate';
import { SandboxRuntimeAttestationService } from './sandbox-runtime-attestation.service';
import {
  retryableInfrastructureFailure,
  SastScannerRuntimeError,
  scannerDefect,
  securityViolation
} from './scanner-runtime.errors';
import { ScannerSandboxAdapterService } from './scanner-sandbox-adapter.service';
import { ScannerSandboxRuntimeProvider } from './scanner-sandbox-runtime.provider';
import { ScannerWorkspaceManifestService } from './scanner-workspace-manifest.service';
import { SastScannerRuntimeStore } from './sast-scanner-runtime.store';
import {
  SastRetryAdmissionGate,
  UnavailableSastRetryAdmissionGate
} from './sast-retry-admission.gate';

@Injectable()
export class SastScannerRuntimeService {
  constructor(
    private readonly controlPlane: ControlPlaneService,
    private readonly adapter: ScannerSandboxAdapterService,
    private readonly attestation: SandboxRuntimeAttestationService,
    private readonly manifestVerifier: ScannerWorkspaceManifestService,
    private readonly provider: ScannerSandboxRuntimeProvider,
    private readonly store: SastScannerRuntimeStore,
    private readonly killSwitch: SastKillSwitchGate,
    private readonly retryAdmission: SastRetryAdmissionGate =
      new UnavailableSastRetryAdmissionGate()
  ) {}

  async execute(
    request: SastScannerWrapperExecutionRequest
  ): Promise<SastScannerRuntimeExecutionResult> {
    let immutableRequest: SastScannerWrapperExecutionRequest;
    try {
      immutableRequest = this.deepFreeze(structuredClone(request));
    } catch {
      throw securityViolation(
        'SCANNER_EXECUTION_REQUEST_INVALID',
        'Scanner execution request is not serializable.'
      );
    }
    return this.executeImmutable(immutableRequest);
  }

  private async executeImmutable(
    request: SastScannerWrapperExecutionRequest
  ): Promise<SastScannerRuntimeExecutionResult> {
    if (!isSastScannerWrapperExecutionRequestValid(request)) {
      throw securityViolation(
        'SCANNER_EXECUTION_REQUEST_INVALID',
        'Scanner execution request is not bound to an approved plan.'
      );
    }

    await this.assertControlPlaneScope(request);
    this.manifestVerifier.verifyPreflight(request);
    const policy = this.adapter.buildPolicy(request.plan);
    if (
      !this.attestation.verify(request.sandboxAttestation, {
        plan: request.plan,
        attemptId: request.attemptId,
        attemptNumber: request.attemptNumber,
        sandboxId: request.sandboxId,
        workloadIdentityRef: request.workloadIdentityRef,
        policy,
        preflight: request.preflight
      })
    ) {
      throw securityViolation(
        'SANDBOX_ATTESTATION_INVALID',
        'Sandbox runtime attestation is invalid, expired, or plan-mismatched.'
      );
    }

    let startedAt = new Date().toISOString();
    const attemptDeadlineAt =
      request.sandboxAttestation.claims.attemptDeadlineAt;
    if (request.attemptNumber === 2) {
      const admission = await this.retryAdmission.authorize(
        request,
        startedAt
      );
      if (admission.outcome !== 'AUTHORIZED') {
        throw securityViolation(
          'SCAN_ATTEMPT_RETRY_NOT_ELIGIBLE',
          'Attempt two requires a durable T040 infrastructure-only retry decision.'
        );
      }
      startedAt = admission.startedAt;
    }
    await this.store.beginAttempt(request, startedAt);

    const auditSignals: SastScannerRuntimeAuditSignal[] = [];
    const scannerRuns: SastScannerExecutionRecord[] = [];
    let runtimeFailure: SastScannerRuntimeError | undefined;
    let cleanupFailure: SastScannerRuntimeError | undefined;
    let cleanup: SastSignedSandboxCleanupObservation | undefined;
    let activeInvocation: SastScannerInvocation | undefined;
    let activeScannerRunId: string | undefined;
    let activeScannerTerminalAuditRecorded = false;

    try {
      if (!(await this.store.isCredentialHandoffTerminal(request))) {
        throw securityViolation(
          'CREDENTIAL_HANDOFF_NOT_TERMINAL',
          'Repository credential handoff must be wiped or revoked before a scanner starts.'
        );
      }
      await this.emitAudit(
        request,
        auditSignals,
        'sandbox.ready',
        { stage: 'VALIDATING', attemptDeadlineAt }
      );
      const invocations = this.adapter.buildInvocations(request);
      await this.store.markStage(request, 'SCANNING');

      for (const invocation of invocations) {
        activeInvocation = invocation;
        activeScannerRunId = `scanner_run_${randomUUID()}`;
        activeScannerTerminalAuditRecorded = false;
        const controller = new AbortController();
        const operation = {
          request,
          invocation,
          scannerRunId: activeScannerRunId,
          attemptDeadlineAt,
          signal: controller.signal
        };
        await this.store.beginScannerRun(
          request,
          activeScannerRunId,
          invocation,
          new Date().toISOString()
        );

        const killSwitchEvaluatedAt = new Date().toISOString();
        try {
          const killSwitch = await this.killSwitch.evaluatePlan({
            gate: 'SCANNER_START',
            plan: request.plan,
            scanner: invocation.scanner,
            evaluatedAt: killSwitchEvaluatedAt
          });
          if (killSwitch.receipt.outcome !== 'CLEAR') {
            throw securityViolation(
              'SAST_KILL_SWITCH_ACTIVE',
              'Scanner start was denied by an active SAST kill switch.'
            );
          }
        } catch (error) {
          if (
            error instanceof SastScannerRuntimeError &&
            error.reasonCode === 'SAST_KILL_SWITCH_ACTIVE'
          ) {
            throw error;
          }
          throw securityViolation(
            'SAST_KILL_SWITCH_AUTHORITY_UNAVAILABLE',
            'Scanner start requires current SAST kill-switch authority.'
          );
        }

        const manifest = await this.runBeforeDeadline(
          attemptDeadlineAt,
          controller,
          () => this.provider.readRepositoryManifest(operation),
          invocation.scanner
        );
        this.manifestVerifier.verify(request, invocation, manifest);

        await this.emitAudit(
          request,
          auditSignals,
          'scanner.started',
          {
            scanner: invocation.scanner,
            scannerImageDigest: invocation.scannerImageDigest,
            wrapperDigest: invocation.wrapperDigest
          },
          {
            scanner: invocation.scanner,
            scannerRunId: activeScannerRunId
          }
        );

        const providerObservation = await this.runBeforeDeadline(
          attemptDeadlineAt,
          controller,
          () => this.provider.executeScanner(operation),
          invocation.scanner
        );
        const observation = this.sanitizeObservation(providerObservation);
        const observationStartedAt = Date.parse(observation.startedAt);
        const observationCompletedAt = Date.parse(observation.completedAt);
        const maximumObservedTime = Date.now() + 5_000;
        if (
          !this.hasExactObservationShape(providerObservation) ||
          !isSastScannerProcessObservationValid(
            observation,
            invocation,
            request.plan
          ) ||
          observationStartedAt < Date.parse(manifest.observedAt) ||
          observationStartedAt > maximumObservedTime ||
          observationCompletedAt > maximumObservedTime
        ) {
          throw this.observationFailure(
            invocation.scanner,
            providerObservation,
            invocation
          );
        }

        const status = deriveScannerExecutionStatus(observation);
        const record: SastScannerExecutionRecord = {
          scannerRunId: activeScannerRunId,
          attemptId: request.attemptId,
          invocation,
          status,
          observation
        };
        await this.store.recordScannerRun(request, record);
        scannerRuns.push(record);

        await this.emitAudit(
          request,
          auditSignals,
          status === 'SUCCEEDED'
            ? 'scanner.completed'
            : 'scanner.failed',
          {
            scanner: invocation.scanner,
            status,
            exitCode: observation.exitCode,
            timedOut: observation.timedOut,
            outputLimitExceeded: observation.outputLimitExceeded,
            artifactDigest: observation.artifact?.contentDigest
          },
          {
            scanner: invocation.scanner,
            scannerRunId: record.scannerRunId,
            executionStatus: status,
            reasonCode:
              status === 'SUCCEEDED'
                ? undefined
                : this.scannerFailureReason(status)
          }
        );
        activeScannerTerminalAuditRecorded = true;
        activeInvocation = undefined;
        activeScannerRunId = undefined;

        if (status !== 'SUCCEEDED') {
          throw this.scannerExecutionFailure(status, invocation.scanner);
        }
      }
    } catch (error) {
      runtimeFailure = this.normalizeFailure(error);
      if (activeInvocation && activeScannerRunId) {
        try {
          await this.store.failScannerRun(
            request,
            activeScannerRunId,
            activeInvocation,
            runtimeFailure.reasonCode,
            new Date().toISOString()
          );
        } catch {
          runtimeFailure = retryableInfrastructureFailure(
            'SCANNER_RUN_PERSISTENCE_FAILED',
            'Scanner failure state could not be persisted.'
          );
        }
      }
      if (activeInvocation && !activeScannerTerminalAuditRecorded) {
        try {
          await this.emitAudit(
            request,
            auditSignals,
            'scanner.failed',
            {
              scanner: activeInvocation.scanner,
              reasonCode: runtimeFailure.reasonCode
            },
            {
              scanner: activeInvocation.scanner,
              scannerRunId: activeScannerRunId,
              reasonCode: runtimeFailure.reasonCode
            }
          );
        } catch {
          runtimeFailure = retryableInfrastructureFailure(
            'SCANNER_AUDIT_PERSISTENCE_FAILED',
            'Scanner failure audit signal could not be persisted.'
          );
        }
      }
    }

    try {
      await this.store.markStage(request, 'CLEANUP_PENDING');
      await this.emitAudit(
        request,
        auditSignals,
        'sandbox.cleanup_pending',
        {
          scannerRunCount: scannerRuns.length,
          runtimeFailure: runtimeFailure?.reasonCode
        },
        {
          reasonCode: runtimeFailure?.reasonCode
        }
      );
    } catch (error) {
      runtimeFailure ??= this.normalizeFailure(error);
    }

    try {
      const cleanupController = new AbortController();
      const cleanupDeadlineAt = new Date(
        Date.now() + SAST_SANDBOX_CLEANUP_TIMEOUT_SECONDS * 1_000
      ).toISOString();
      const providerCleanup = await this.runCleanupBeforeDeadline(
        cleanupDeadlineAt,
        cleanupController,
        () =>
          this.provider.cleanup({
            request,
            cleanupDeadlineAt,
            signal: cleanupController.signal
          })
      );
      cleanup = this.sanitizeCleanup(providerCleanup);
      const cleanupValid =
        this.hasExactCleanupShape(providerCleanup) &&
        Date.parse(cleanup.observation.completedAt) >=
          Date.parse(startedAt) &&
        this.attestation.verifyCleanup(cleanup, {
          tenantId: request.plan.tenantId,
          repositoryBindingId:
            request.plan.repositoryState.repositoryBindingId,
          scanRequestId: request.plan.scanRequestId,
          attemptId: request.attemptId,
          sandboxId: request.sandboxId,
          workloadIdentityRef: request.workloadIdentityRef
        });
      const credentialCleanupDurable =
        cleanupValid &&
        (await this.store.isCredentialHandoffTerminal(request));

      if (!cleanupValid || !credentialCleanupDurable) {
        cleanupFailure = securityViolation(
          cleanupValid
            ? 'CREDENTIAL_CLEANUP_NOT_DURABLE'
            : 'SANDBOX_CLEANUP_EVIDENCE_INVALID',
          cleanupValid
            ? 'Durable credential cleanup evidence is missing.'
            : 'Sandbox destruction evidence is missing, incomplete, or invalid.'
        );
      }
    } catch (error) {
      cleanupFailure =
        error instanceof SastScannerRuntimeError
          ? error
          : securityViolation(
              'SANDBOX_CLEANUP_EVIDENCE_MISSING',
              'Sandbox cleanup did not return verifiable destruction evidence.'
            );
    }

    const terminalFailure = cleanupFailure ?? runtimeFailure;
    const terminalEventType = cleanupFailure
      ? 'sandbox.cleanup_failed'
      : 'sandbox.terminated';
    const terminalStage = cleanupFailure
      ? 'CLEANUP_FAILED'
      : runtimeFailure
        ? 'FAILED'
        : 'COMPLETED';
    const completedAt = new Date().toISOString();
    const terminalSignal = await this.emitAudit(
      request,
      auditSignals,
      terminalEventType,
      {
        stage: terminalStage,
        scannerRunCount: scannerRuns.length,
        cleanupDigest: cleanup?.signature,
        failureClass: terminalFailure?.failureClass,
        reasonCode: terminalFailure?.reasonCode
      },
      {
        reasonCode: terminalFailure?.reasonCode
      },
      completedAt
    );

    await this.store.finishAttempt({
      request,
      stage: terminalStage,
      failureClass: terminalFailure?.failureClass,
      reasonCode: terminalFailure?.reasonCode,
      retryEligible:
        !cleanupFailure &&
        runtimeFailure?.retryAllowed === true &&
        request.attemptNumber < 2,
      cleanup,
      finalAuditEventId: terminalSignal.eventId,
      completedAt
    });

    if (terminalFailure) {
      throw terminalFailure;
    }
    if (!cleanup) {
      throw securityViolation(
        'SANDBOX_CLEANUP_EVIDENCE_MISSING',
        'Completed attempt is missing sandbox cleanup evidence.'
      );
    }

    return {
      tenantId: request.plan.tenantId,
      repositoryBindingId:
        request.plan.repositoryState.repositoryBindingId,
      scanRequestId: request.plan.scanRequestId,
      attemptId: request.attemptId,
      attemptNumber: request.attemptNumber,
      sandboxId: request.sandboxId,
      workloadIdentityRef: request.workloadIdentityRef,
      stage: 'COMPLETED',
      scannerRuns,
      cleanup,
      auditSignals
    };
  }

  private async assertControlPlaneScope(
    request: SastScannerWrapperExecutionRequest
  ): Promise<void> {
    const scanRequest = await this.controlPlane.getScanRequest(
      request.plan.tenantId,
      request.plan.scanRequestId
    );
    const expectedIsolationClass =
      scanRequest.isolationClass === 'RESTRICTED'
        ? 'RESTRICTED'
        : 'HARDENED';
    if (
      scanRequest.repositoryBindingId !==
        request.plan.repositoryState.repositoryBindingId ||
      scanRequest.commitSha.toLowerCase() !==
        request.plan.repositoryState.fixedCommitSha.toLowerCase() ||
      scanRequest.scannerSetVersion !==
        request.plan.scannerSet.scannerSetVersion ||
      scanRequest.policyVersion !== request.plan.policyVersion ||
      expectedIsolationClass !== request.plan.isolationClass ||
      scanRequest.status !== 'RUNNING'
    ) {
      throw securityViolation(
        'CONTROL_PLANE_SCAN_SCOPE_MISMATCH',
        'Runtime request does not match the running control-plane scan.'
      );
    }
  }

  private async emitAudit(
    request: SastScannerWrapperExecutionRequest,
    auditSignals: SastScannerRuntimeAuditSignal[],
    eventType: SastScannerRuntimeAuditSignal['eventType'],
    metadata: Readonly<Record<string, unknown>>,
    optional: Pick<
      SastScannerRuntimeAuditSignal,
      | 'scanner'
      | 'scannerRunId'
      | 'executionStatus'
      | 'reasonCode'
    > = {},
    occurredAt = new Date().toISOString()
  ): Promise<SastScannerRuntimeAuditSignal> {
    const signal: SastScannerRuntimeAuditSignal = {
      eventId: `audit_${randomUUID()}`,
      eventType,
      tenantId: request.plan.tenantId,
      repositoryBindingId:
        request.plan.repositoryState.repositoryBindingId,
      scanRequestId: request.plan.scanRequestId,
      attemptId: request.attemptId,
      sandboxId: request.sandboxId,
      workloadIdentityRef: request.workloadIdentityRef,
      ...optional,
      occurredAt,
      metadataDigest: this.digest(metadata)
    };
    await this.store.recordAuditSignal(signal);
    auditSignals.push(signal);
    return signal;
  }

  private sanitizeObservation(
    observation: SastScannerProcessObservation
  ): SastScannerProcessObservation {
    return {
      scanner: observation?.scanner,
      scannerVersion: observation?.scannerVersion,
      scannerImageDigest: observation?.scannerImageDigest,
      wrapperDigest: observation?.wrapperDigest,
      ruleBundleDigest: observation?.ruleBundleDigest,
      vulnerabilityDatabaseDigest:
        observation?.vulnerabilityDatabaseDigest,
      scannerWorkspaceInventoryDigest:
        observation?.scannerWorkspaceInventoryDigest,
      exitCode: observation?.exitCode,
      terminationSignal: observation?.terminationSignal,
      timedOut: observation?.timedOut,
      outputLimitExceeded: observation?.outputLimitExceeded,
      startedAt: observation?.startedAt,
      completedAt: observation?.completedAt,
      stdout: observation?.stdout
        ? {
            byteSize: observation.stdout.byteSize,
            contentDigest: observation.stdout.contentDigest,
            truncated: observation.stdout.truncated,
            secretRedactionApplied:
              observation.stdout.secretRedactionApplied
          }
        : observation?.stdout,
      stderr: observation?.stderr
        ? {
            byteSize: observation.stderr.byteSize,
            contentDigest: observation.stderr.contentDigest,
            truncated: observation.stderr.truncated,
            secretRedactionApplied:
              observation.stderr.secretRedactionApplied
          }
        : observation?.stderr,
      resources: observation?.resources
        ? {
            cpuTimeMilliseconds:
              observation.resources.cpuTimeMilliseconds,
            peakMemoryBytes: observation.resources.peakMemoryBytes,
            bytesRead: observation.resources.bytesRead,
            bytesWritten: observation.resources.bytesWritten,
            peakProcessCount:
              observation.resources.peakProcessCount,
            peakFileDescriptorCount:
              observation.resources.peakFileDescriptorCount
          }
        : observation?.resources,
      artifact: observation?.artifact
        ? {
            artifactRef: observation.artifact.artifactRef,
            contentDigest: observation.artifact.contentDigest,
            byteSize: observation.artifact.byteSize,
            recordCount: observation.artifact.recordCount,
            truncated: observation.artifact.truncated
          }
        : undefined
    };
  }

  private sanitizeCleanup(
    signed: SastSignedSandboxCleanupObservation
  ): SastSignedSandboxCleanupObservation {
    const observation = signed?.observation;
    return {
      observation: {
        tenantId: observation?.tenantId,
        repositoryBindingId: observation?.repositoryBindingId,
        scanRequestId: observation?.scanRequestId,
        attemptId: observation?.attemptId,
        sandboxId: observation?.sandboxId,
        workloadIdentityRef: observation?.workloadIdentityRef,
        credentialRevokedAndWiped:
          observation?.credentialRevokedAndWiped,
        scannerProcessesTerminated:
          observation?.scannerProcessesTerminated,
        writableVolumesDestroyed:
          observation?.writableVolumesDestroyed,
        microVmTerminated: observation?.microVmTerminated,
        resultIngressClosed: observation?.resultIngressClosed,
        completedAt: observation?.completedAt,
        nonce: observation?.nonce
      },
      signature: signed?.signature
    };
  }

  private hasExactObservationShape(
    observation: SastScannerProcessObservation
  ): boolean {
    const topLevel = [
      'artifact',
      'completedAt',
      'exitCode',
      'outputLimitExceeded',
      'resources',
      'ruleBundleDigest',
      'scanner',
      'scannerImageDigest',
      'scannerVersion',
      'scannerWorkspaceInventoryDigest',
      'startedAt',
      'stderr',
      'stdout',
      'terminationSignal',
      'timedOut',
      'vulnerabilityDatabaseDigest',
      'wrapperDigest'
    ];
    return (
      this.hasOnlyKeys(observation, topLevel) &&
      this.hasOnlyKeys(observation?.stdout, [
        'byteSize',
        'contentDigest',
        'secretRedactionApplied',
        'truncated'
      ]) &&
      this.hasOnlyKeys(observation?.stderr, [
        'byteSize',
        'contentDigest',
        'secretRedactionApplied',
        'truncated'
      ]) &&
      this.hasOnlyKeys(observation?.resources, [
        'bytesRead',
        'bytesWritten',
        'cpuTimeMilliseconds',
        'peakFileDescriptorCount',
        'peakMemoryBytes',
        'peakProcessCount'
      ]) &&
      (observation?.artifact === undefined ||
        this.hasOnlyKeys(observation.artifact, [
          'artifactRef',
          'byteSize',
          'contentDigest',
          'recordCount',
          'truncated'
        ]))
    );
  }

  private hasExactCleanupShape(
    signed: SastSignedSandboxCleanupObservation
  ): boolean {
    return (
      this.hasOnlyKeys(signed, ['observation', 'signature']) &&
      this.hasOnlyKeys(signed?.observation, [
        'completedAt',
        'credentialRevokedAndWiped',
        'microVmTerminated',
        'nonce',
        'repositoryBindingId',
        'resultIngressClosed',
        'sandboxId',
        'scanRequestId',
        'scannerProcessesTerminated',
        'tenantId',
        'attemptId',
        'workloadIdentityRef',
        'writableVolumesDestroyed'
      ])
    );
  }

  private hasOnlyKeys(
    value: unknown,
    allowedKeys: readonly string[]
  ): boolean {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }
    const allowed = new Set(allowedKeys);
    return Object.keys(value).every((key) => allowed.has(key));
  }

  private observationFailure(
    scanner: string,
    observation: SastScannerProcessObservation,
    invocation: SastScannerExecutionRecord['invocation']
  ): SastScannerRuntimeError {
    if (
      observation?.scanner !== invocation.scanner ||
      observation?.scannerImageDigest !==
        invocation.scannerImageDigest ||
      observation?.wrapperDigest !== invocation.wrapperDigest ||
      observation?.ruleBundleDigest !==
        invocation.ruleBundleDigest ||
      observation?.vulnerabilityDatabaseDigest !==
        invocation.vulnerabilityDatabaseDigest ||
      observation?.scannerWorkspaceInventoryDigest !==
        invocation.preflightInventoryDigest
    ) {
      return securityViolation(
        'SCANNER_RUNTIME_DIGEST_MISMATCH',
        `${scanner} returned runtime identity or workspace digest metadata that does not match the plan.`
      );
    }
    return scannerDefect(
      'SCANNER_RUNTIME_OBSERVATION_INVALID',
      `${scanner} returned malformed or unbounded execution metadata.`
    );
  }

  private scannerExecutionFailure(
    status: SastScannerExecutionRecord['status'],
    scanner: string
  ): SastScannerRuntimeError {
    if (status === 'QUARANTINED') {
      return securityViolation(
        'SCANNER_OUTPUT_LIMIT_EXCEEDED',
        `${scanner} exceeded the approved bounded output policy.`
      );
    }
    return scannerDefect(
      this.scannerFailureReason(status),
      `${scanner} did not produce a successful approved artifact.`
    );
  }

  private scannerFailureReason(
    status: SastScannerExecutionRecord['status']
  ): string {
    if (status === 'TIMED_OUT') {
      return 'SCANNER_TIMEOUT';
    }
    if (status === 'QUARANTINED') {
      return 'SCANNER_OUTPUT_LIMIT_EXCEEDED';
    }
    return 'SCANNER_NONZERO_EXIT';
  }

  private normalizeFailure(error: unknown): SastScannerRuntimeError {
    if (error instanceof SastScannerRuntimeError) {
      return error;
    }
    return retryableInfrastructureFailure(
      'SCANNER_RUNTIME_PROVIDER_FAILURE',
      'Scanner runtime provider failed before returning bounded metadata.'
    );
  }

  private async runBeforeDeadline<T>(
    deadlineAt: string,
    controller: AbortController,
    operation: () => Promise<T>,
    scanner: string
  ): Promise<T> {
    return this.runWithDeadline(
      deadlineAt,
      controller,
      operation,
      () =>
        scannerDefect(
          'SCANNER_TIMEOUT',
          `${scanner} exceeded the signed attempt wall-clock deadline.`
        )
    );
  }

  private async runCleanupBeforeDeadline<T>(
    deadlineAt: string,
    controller: AbortController,
    operation: () => Promise<T>
  ): Promise<T> {
    return this.runWithDeadline(
      deadlineAt,
      controller,
      operation,
      () =>
        securityViolation(
          'SANDBOX_CLEANUP_TIMEOUT',
          'Sandbox cleanup exceeded the bounded destruction deadline.'
        )
    );
  }

  private async runWithDeadline<T>(
    deadlineAt: string,
    controller: AbortController,
    operation: () => Promise<T>,
    timeoutFailure: () => SastScannerRuntimeError
  ): Promise<T> {
    const deadline = Date.parse(deadlineAt);
    const remainingMilliseconds = deadline - Date.now();
    if (!Number.isFinite(deadline) || remainingMilliseconds <= 0) {
      controller.abort();
      throw timeoutFailure();
    }

    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(timeoutFailure());
      }, remainingMilliseconds);
    });

    try {
      const result = await Promise.race([
        Promise.resolve().then(operation),
        timeout
      ]);
      if (Date.now() > deadline) {
        controller.abort();
        throw timeoutFailure();
      }
      return result;
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }

  private digest(
    value: Readonly<Record<string, unknown>>
  ): `sha256:${string}` {
    return `sha256:${createHash('sha256')
      .update(this.canonical(value), 'utf8')
      .digest('hex')}`;
  }

  private canonical(value: unknown): string {
    if (value === null || typeof value !== 'object') {
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      return `[${value.map((item) => this.canonical(item)).join(',')}]`;
    }
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .filter((key) => record[key] !== undefined)
      .map(
        (key) =>
          `${JSON.stringify(key)}:${this.canonical(record[key])}`
      )
      .join(',')}}`;
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
