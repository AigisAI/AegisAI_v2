import { Module } from "@nestjs/common";

import { isMockAnalysisFixtureEnabled } from '../client/analysis/analysis-fixture.policy';
import { EvidenceController } from "./evidence.controller";
import { EvidenceExpiryTask } from "./evidence-expiry.task";
import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { FindingsController } from "./findings.controller";
import { ScanPlaneController } from "./scan-plane.controller";
import { SastArtifactIngressController } from './sast-artifact-ingress.controller';
import { SastArtifactIngressService } from './sast-artifact-ingress.service';
import {
  PrismaSastArtifactIngressStore
} from './prisma-sast-artifact-ingress.store';
import { SastArtifactIngressStore } from './sast-artifact-ingress.store';
import {
  SastArtifactObjectStore,
  UnavailableSastArtifactObjectStore
} from './sast-artifact-object-store';
import { SastArtifactValidationService } from './sast-artifact-validation.service';
import {
  SastArtifactAcceptanceGate,
  UnavailableSastArtifactAcceptanceGate
} from './sast-artifact-acceptance-gate';
import {
  SastArtifactDispositionStorage,
  UnavailableSastArtifactDispositionStorage
} from './sast-artifact-disposition-storage';
import { SastArtifactDispositionService } from './sast-artifact-disposition.service';
import { SastArtifactDispositionTask } from './sast-artifact-disposition.task';
import {
  PrismaSastArtifactDispositionStore
} from './prisma-sast-artifact-disposition.store';
import { SastArtifactDispositionStore } from './sast-artifact-disposition.store';
import {
  SastFileCoordinateAttestationProvider,
  UnavailableSastFileCoordinateAttestationProvider
} from './sast-file-coordinate-attestation.provider';
import {
  DirectMtlsSastWorkloadIdentityAuthenticator,
  SastWorkloadIdentityAuthenticator
} from './sast-workload-identity.authenticator';
import { SastWorkloadIdentityGuard } from './sast-workload-identity.guard';
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
import { OpenGrepSarifNormalizer } from './opengrep-sarif-normalizer';
import { TrivyJsonNormalizer } from './trivy-json-normalizer';
import { SyftCycloneDxInventoryIngestor } from './syft-cyclonedx-inventory-ingestor';
import { SastSecretRedactionService } from './sast-secret-redaction.service';

@Module({
  imports: [ConfigModule, ControlPlaneModule, TokenBrokerModule],
  controllers: [
    ScanPlaneController,
    SastArtifactIngressController,
    FindingsController,
    EvidenceController,
    ...(isMockAnalysisFixtureEnabled() ? [ScanPlaneMockController] : [])
  ],
  providers: [
    ScanPlaneService,
    SastArtifactIngressService,
    SastArtifactValidationService,
    OpenGrepSarifNormalizer,
    TrivyJsonNormalizer,
    SyftCycloneDxInventoryIngestor,
    SastSecretRedactionService,
    SastArtifactDispositionService,
    SastArtifactDispositionTask,
    PrismaSastArtifactDispositionStore,
    {
      provide: SastArtifactDispositionStore,
      useExisting: PrismaSastArtifactDispositionStore
    },
    UnavailableSastArtifactDispositionStorage,
    {
      provide: SastArtifactDispositionStorage,
      useExisting: UnavailableSastArtifactDispositionStorage
    },
    UnavailableSastArtifactAcceptanceGate,
    {
      provide: SastArtifactAcceptanceGate,
      useExisting: UnavailableSastArtifactAcceptanceGate
    },
    UnavailableSastFileCoordinateAttestationProvider,
    {
      provide: SastFileCoordinateAttestationProvider,
      useExisting: UnavailableSastFileCoordinateAttestationProvider
    },
    SastWorkloadIdentityGuard,
    DirectMtlsSastWorkloadIdentityAuthenticator,
    {
      provide: SastWorkloadIdentityAuthenticator,
      useExisting: DirectMtlsSastWorkloadIdentityAuthenticator
    },
    PrismaSastArtifactIngressStore,
    {
      provide: SastArtifactIngressStore,
      useExisting: PrismaSastArtifactIngressStore
    },
    UnavailableSastArtifactObjectStore,
    {
      provide: SastArtifactObjectStore,
      useExisting: UnavailableSastArtifactObjectStore
    },
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
    SastScannerRuntimeService,
    SyftCycloneDxInventoryIngestor,
    SastSecretRedactionService
  ]
})
export class ScanPlaneModule {}
