// Operator acceptance only, on behalf of the existing verified owner. No test
// identity, session, tenant, repository or finding is inserted into production.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {loadRuntimeSecrets} from '/app/apps/api/dist/data-security/runtime-secrets.js';
import {PrismaService} from '/app/apps/api/dist/prisma/prisma.service.js';
import {ControlPlaneService} from '/app/apps/api/dist/control-plane/control-plane.service.js';
import {GithubAppClient} from '/app/apps/api/dist/control-plane/github-app.client.js';
import {RuntimeApiService} from '/app/apps/api/dist/runtime/runtime-api.service.js';
import {RuntimeCatalogService} from '/app/apps/api/dist/runtime/runtime-catalog.service.js';
import {EvidenceAccessService} from '/app/apps/api/dist/data-security/evidence-access.service.js';
import {S3EvidenceStore} from '/app/apps/api/dist/data-security/evidence-store.js';

await loadRuntimeSecrets('api');
const prisma=new PrismaService();
try {
  const providerUserId='161540124';
  assert.equal(process.env.ALLOWED_GITHUB_USER_IDS,providerUserId);
  const identity=await prisma.userOAuthIdentity.findUnique({where:{provider_providerUserId:{provider:'GITHUB',providerUserId}},include:{user:true}});
  assert.ok(identity?.user);
  const tenantId='tenant_'+createHash('sha256').update('github:'+providerUserId).digest('hex').slice(0,32);
  assert.ok(await prisma.tenant.findFirst({where:{id:tenantId,status:'ACTIVE'}}));
  const binding=await prisma.repositoryBinding.findFirst({where:{tenantId,providerRepoId:'1087577243',integration:{status:'ACTIVE',provider:'GITHUB'}}});
  assert.ok(binding,'The selected Java repository must already be bound by real organization discovery');
  const identitiesBefore=await prisma.userOAuthIdentity.count();
  const api=new RuntimeApiService(prisma,new ControlPlaneService(prisma),new GithubAppClient({get:key=>process.env[key],getOptional:key=>process.env[key]}),new RuntimeCatalogService());
  const principal={userId:identity.userId,tenantId,provider:'GITHUB',providerUserId,email:identity.user.email??'',name:identity.user.name};
  const created=await api.create(principal,binding.id);
  await prisma.auditEvent.create({data:{tenantId,scanRequestId:created.id,eventType:'scan.acceptance.started',actor:'deployment-operator',targetType:'scan_request',targetId:created.id,metadata:{actualPersistedIdentity:true}}});
  console.log(JSON.stringify({operatorAcceptance:'started',scanRequestId:created.id,ai:'DISABLED'}));
  let state,previous;
  const deadline=Date.now()+10*60_000;
  while(Date.now()<deadline) {
    state=await prisma.scanRequest.findUnique({where:{id:created.id}});
    if(state.status!==previous) {console.log(JSON.stringify({scanState:state.status}));previous=state.status;}
    if(['COMPLETED','FAILED','CANCELED'].includes(state.status))break;
    await new Promise(resolve=>setTimeout(resolve,3000));
  }
  assert.equal(state.status,'COMPLETED','Actual private scan did not complete successfully');
  const detail=await api.detail(tenantId,created.id);
  assert.equal(detail.runs.length,3);assert.ok(detail.runs.every(run=>run.status==='COMPLETED'));
  assert.equal(detail.ai,'DISABLED');assert.equal(detail.coverage,'LIMITED');assert.equal(detail.policy.mergeEnforced,false);
  const job=await prisma.scanDispatchJob.findUnique({where:{scanRequestId:created.id}});
  assert.equal(job.status,'SUCCEEDED');
  const pack=await prisma.evidencePack.findFirst({where:{tenantId,scanRequestId:created.id}});
  assert.ok(pack?.redacted&&pack.byteSize>0&&pack.byteSize<=1024*1024);
  const data=JSON.parse((await new EvidenceAccessService(prisma).read(tenantId,created.id,'deployment-operator')).toString());
  assert.equal(data.fragmentCount,0);assert.equal(data.ai,'DISABLED');assert.equal(data.redacted,true);
  const encrypted=await S3EvidenceStore.fromEnvironment().describe(pack.objectKey);
  assert.equal(encrypted.ServerSideEncryption,'aws:kms');assert.equal(encrypted.SSEKMSKeyId,process.env.EVIDENCE_KMS_KEY_ARN);
  assert.equal(await prisma.userOAuthIdentity.count(),identitiesBefore);
  const report={operatorLiveScanAcceptance:'passed',scanRequestId:created.id,tenantId,repositoryId:binding.providerRepoId,
    commitSha:state.commitSha,scannerCount:detail.runs.length,normalizedFindingCount:detail.findings.length,
    ai:'DISABLED',coverage:'LIMITED',dispatch:'SUCCEEDED',encryptedEvidence:true,evidenceReadAudited:true,
    noSyntheticIdentityCreated:true,customerCodeExecuted:false,browserInitiatedScanVerified:false};
  await writeFile('/run/acceptance/live-scan-result.json',JSON.stringify(report,null,2),{mode:0o600});
  console.log(JSON.stringify(report));
} finally {await prisma.$disconnect();}
