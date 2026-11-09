// Read existing acceptance data after reboot. Never create another scan/session.
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {loadRuntimeSecrets} from '/app/apps/api/dist/data-security/runtime-secrets.js';
import {PrismaService} from '/app/apps/api/dist/prisma/prisma.service.js';
import {EvidenceAccessService} from '/app/apps/api/dist/data-security/evidence-access.service.js';

await loadRuntimeSecrets('api');
const prisma=new PrismaService();
try {
  const accepted=JSON.parse(await readFile('/run/acceptance/live-scan-result.json','utf8'));
  assert.equal(accepted.operatorLiveScanAcceptance,'passed');
  const scan=await prisma.scanRequest.findFirst({where:{id:accepted.scanRequestId,tenantId:accepted.tenantId}});
  assert.equal(scan?.status,'COMPLETED');
  assert.equal(scan.commitSha,accepted.commitSha);
  const runs=await prisma.scannerRun.count({where:{scanRequestId:scan.id,tenantId:scan.tenantId,status:'COMPLETED'}});
  assert.equal(runs,3);
  assert.equal((await prisma.scanDispatchJob.findUnique({where:{scanRequestId:scan.id}})).status,'SUCCEEDED');
  const evidence=JSON.parse((await new EvidenceAccessService(prisma).read(scan.tenantId,scan.id,'deployment-restart-verifier')).toString());
  assert.equal(evidence.ai,'DISABLED');assert.equal(evidence.fragmentCount,0);
  const counts={identities:await prisma.userOAuthIdentity.count(),integrations:await prisma.scmIntegration.count(),
    repositories:await prisma.repositoryBinding.count(),scans:await prisma.scanRequest.count(),
    scannerRuns:await prisma.scannerRun.count(),evidencePacks:await prisma.evidencePack.count()};
  assert.deepEqual(counts,{identities:1,integrations:1,repositories:5,scans:1,scannerRuns:3,evidencePacks:1});
  const report={managedBootRecovery:'passed',existingScanReadable:true,existingEncryptedEvidenceReadable:true,
    completedJobNotReplayed:true,noSyntheticSessionCreated:true,counts,verifiedAt:new Date().toISOString()};
  await writeFile('/run/acceptance/restart-result.json',JSON.stringify(report,null,2),{mode:0o600});
  console.log(JSON.stringify(report));
} finally {await prisma.$disconnect();}
