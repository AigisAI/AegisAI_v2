import { Module } from "@nestjs/common";

import { isMockAnalysisFixtureEnabled } from '../client/analysis/analysis-fixture.policy';
import { EvidenceController } from "./evidence.controller";
import { EvidenceExpiryTask } from "./evidence-expiry.task";
import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { FindingsController } from "./findings.controller";
import { ScanPlaneController } from "./scan-plane.controller";
import { ScanPlaneMockController } from './scan-plane-mock.controller';
import { ScanPlaneService } from "./scan-plane.service";
import { ScannerSandboxAdapterService } from "./scanner-sandbox-adapter.service";
import {
  ScannerSandboxRuntimeProvider,
  UnavailableScannerSandboxRuntimeProvider
} from './scanner-sandbox-runtime.provider';
import { ScannerWorkspaceManifestService } from './scanner-workspace-manifest.service';
import { SandboxRuntimeAttestationService } from './sandbox-runtime-attestation.service';
import { SastScannerRuntimeService } from './sast-scanner-runtime.service';
import {
  PrismaSastScannerRuntimeStore
} from './prisma-sast-scanner-runtime.store';
import { SastScannerRuntimeStore } from './sast-scanner-runtime.store';
import { SastAttemptReconciliationTask } from './sast-attempt-reconciliation.task';
import { ConfigModule } from "../config/config.module";
import { ControlPlaneModule } from '../control-plane/control-plane.module';
import { TokenBrokerModule } from '../token-broker/token-broker.module';
import {
  NodeRepositoryGitExecutor,
  RepositoryGitExecutor
} from './repository-git-executor';
import { RepositoryFetchService } from './repository-fetch.service';
import { RepositoryPreflightAttestationService } from './repository-preflight-attestation.service';
import { RepositoryPreflightService } from './repository-preflight.service';
import {
  CredentialTmpfsVerifier,
  NodeCredentialTmpfsVerifier
} from './credential-tmpfs-verifier.service';

@Module({
  imports: [ConfigModule, ControlPlaneModule, TokenBrokerModule],
  controllers: [
    ScanPlaneController,
    FindingsController,
    EvidenceController,
    ...(isMockAnalysisFixtureEnabled() ? [ScanPlaneMockController] : [])
  ],
  providers: [
    ScanPlaneService,
    ScannerSandboxAdapterService,
    SandboxRuntimeAttestationService,
    ScannerWorkspaceManifestService,
    SastScannerRuntimeService,
    UnavailableScannerSandboxRuntimeProvider,
    {
      provide: ScannerSandboxRuntimeProvider,
      useExisting: UnavailableScannerSandboxRuntimeProvider
    },
    PrismaSastScannerRuntimeStore,
    {
      provide: SastScannerRuntimeStore,
      useExisting: PrismaSastScannerRuntimeStore
    },
    SastAttemptReconciliationTask,
    RepositoryFetchService,
    RepositoryPreflightService,
    RepositoryPreflightAttestationService,
    NodeCredentialTmpfsVerifier,
    {
      provide: CredentialTmpfsVerifier,
      useExisting: NodeCredentialTmpfsVerifier
    },
    NodeRepositoryGitExecutor,
    {
      provide: RepositoryGitExecutor,
      useExisting: NodeRepositoryGitExecutor
    },
    EvidenceObjectStorageService,
    EvidenceExpiryTask
  ],
  exports: [
    RepositoryFetchService,
    RepositoryPreflightService,
    SandboxRuntimeAttestationService,
    SastScannerRuntimeService
  ]
})
export class ScanPlaneModule {}
