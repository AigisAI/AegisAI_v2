import { Module } from "@nestjs/common";

import { EvidenceController } from "./evidence.controller";
import { EvidenceExpiryTask } from "./evidence-expiry.task";
import { EvidenceObjectStorageService } from "./evidence-object-storage.service";
import { FindingsController } from "./findings.controller";
import { ScanPlaneController } from "./scan-plane.controller";
import { ScanPlaneService } from "./scan-plane.service";
import { ScannerSandboxAdapterService } from "./scanner-sandbox-adapter.service";
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
  controllers: [ScanPlaneController, FindingsController, EvidenceController],
  providers: [
    ScanPlaneService,
    ScannerSandboxAdapterService,
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
  exports: [RepositoryFetchService, RepositoryPreflightService]
})
export class ScanPlaneModule {}
