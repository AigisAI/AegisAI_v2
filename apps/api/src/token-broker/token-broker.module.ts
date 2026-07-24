import { Module } from "@nestjs/common";

import { ControlPlaneModule } from '../control-plane/control-plane.module';
import { AuditEventsController } from "./audit-events.controller";
import { PrismaRepositoryCredentialLeaseStore } from './prisma-repository-credential-lease.store';
import { RepositoryCredentialLeaseStore } from './repository-credential-lease.store';
import { TokenCredentialIssuerService } from "./token-credential-issuer.service";
import { TokenBrokerController } from "./token-broker.controller";
import { TokenBrokerService } from "./token-broker.service";
import { WorkloadIdentityAttestationService } from './workload-identity-attestation.service';

@Module({
  imports: [ControlPlaneModule],
  controllers: [TokenBrokerController, AuditEventsController],
  providers: [
    TokenBrokerService,
    TokenCredentialIssuerService,
    WorkloadIdentityAttestationService,
    PrismaRepositoryCredentialLeaseStore,
    {
      provide: RepositoryCredentialLeaseStore,
      useExisting: PrismaRepositoryCredentialLeaseStore
    }
  ],
  exports: [TokenBrokerService, WorkloadIdentityAttestationService]
})
export class TokenBrokerModule {}
