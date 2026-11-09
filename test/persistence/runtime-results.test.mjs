import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import test from 'node:test';

const url=process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(url);
assert.match(new URL(url).pathname,/^\/aegisai_(verify|ci|test)$/);
process.env.DATABASE_URL=url;
const require=createRequire(new URL('../../apps/api/package.json',import.meta.url));
const {PrismaClient}=require('@prisma/client');
const {ControlPlaneService}=await import('../../apps/api/dist/control-plane/control-plane.service.js');
const {ScanDispatchService}=await import('../../apps/api/dist/dispatch/scan-dispatch.service.js');
const {FetchCapabilityService}=await import('../../apps/api/dist/token-broker/fetch-capability.service.js');
const {RuntimeResultsService,validateRuntimeResult}=await import('../../apps/api/dist/worker/runtime-results.service.js');
const {MemoryEvidenceStore}=await import('../../apps/api/test/support/memory-evidence.mjs');
const {EvidenceAccessService}=await import('../../apps/api/dist/data-security/evidence-access.service.js');
const {enforceEvidenceExpiry}=await import('../../apps/api/dist/data-security/evidence-maintenance.js');
const result=()=>({scannerSetVersion:'fixture-v1',vulnerabilityDatabaseDigest:'sha256:'+'d'.repeat(64),
  runs:['OPENGREP','TRIVY','SYFT'].map(scanner=>({scanner,status:'COMPLETED',durationMs:10})),
  findings:[{scanner:'OPENGREP',ruleId:'aegisai.java.weak-des-cipher',severity:'MEDIUM',filePath:'src/Fixture.java',lineStart:5,lineEnd:5},
    {scanner:'TRIVY',ruleId:'CVE-2021-44228',severity:'CRITICAL',filePath:'pom.xml',lineStart:null,lineEnd:null}]});

test('Fenced deterministic result delivery without an AI provider',async t=>{
  const prisma=new PrismaClient();
  async function fixture(run) {
    assert.equal(await prisma.scanDispatchJob.count({where:{status:{in:['PENDING','LEASED']}}}),0,'Serialize verification DB suites');
    const id=String(Number.parseInt(randomBytes(6).toString('hex'),16)+1);
    const tenantId='tenant_'+createHash('sha256').update('github:'+id).digest('hex').slice(0,32);
    const control=new ControlPlaneService(prisma),queue=new ScanDispatchService(prisma);
    const caps=new FetchCapabilityService(prisma,{getOptional:()=>id});
    const evidence=new MemoryEvidenceStore();
    const service=new RuntimeResultsService(prisma,caps,evidence);
    try {
      await prisma.tenant.create({data:{id:tenantId,slug:tenantId,name:'Synthetic result verification'}});
      const integration=await control.installIntegration({tenantId,externalInstallationId:'99',repoReadPrincipalId:'verified-test-read',
        repositories:[{providerRepoId:'100',fullName:'AigisAI/fixture',defaultBranch:'main',isPrivate:true}]},
      {provider:'GITHUB',integrationType:'GITHUB_APP'});
      const [binding]=await control.listRepositoryBindings(tenantId);
      const scan=await control.createScanRequest({tenantId,repositoryBindingId:binding.id,lane:'FAST',targetRef:'main',
        commitSha:'a'.repeat(40),policyVersion:'fixture-v1',scannerSetVersion:'fixture-v1'});
      await caps.startEpoch();
      const lease=await queue.claim('result_fixture',[tenantId]);
      const issued=await caps.issue(lease);
      await assert.rejects(service.start(lease,issued.credentialId),{status:409});
      const claim=await caps.consume(lease,issued.capability);
      assert.equal((await caps.complete(tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true})).handoffAllowed,true);
      await service.start(lease,issued.credentialId);
      await run({tenantId,control,queue,caps,service,lease,issued,scan,integration,evidence});
    } finally {
      await prisma.tenant.deleteMany({where:{id:tenantId}});
      await prisma.scanBrokerRuntime.deleteMany({where:{id:'private-single-host'}});
    }
  }
  try {
    await t.test('publishes once atomically, preserves null locations and requires no AI configuration',()=>fixture(async({tenantId,queue,service,lease,issued,scan,evidence})=>{
      assert.equal((await prisma.scanRequest.findUnique({where:{id:scan.id}})).status,'RUNNING');
      await queue.heartbeat(tenantId,lease.jobId,lease.leaseToken);
      assert.deepEqual(await service.publish(lease,issued.credentialId,result()),{status:'COMPLETED',findingCount:2,ai:'DISABLED'});
      assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:lease.jobId}})).status,'SUCCEEDED');
      assert.equal((await prisma.scanRequest.findUnique({where:{id:scan.id}})).status,'COMPLETED');
      const findings=await prisma.normalizedFinding.findMany({where:{tenantId}});
      assert.equal(findings.length,2);
      assert.equal(findings.find(item=>item.scannerProvenance==='TRIVY').lineStart,null);
      const policy=await prisma.policyDecision.findFirst({where:{tenantId}});
      assert.equal(policy.aiAdvisoryVisible,false);assert.equal(policy.blockRequested,false);
      assert.equal(policy.requiredCoverage.state,'LIMITED');assert.equal(policy.requiredCoverage.mergeEnforced,false);
      const pack=await prisma.evidencePack.findFirst({where:{tenantId}});
      assert.ok(pack&&pack.redacted&&pack.byteSize>0);
      class FixtureEvidenceAccess extends EvidenceAccessService {store(){return evidence;}}
      const access=new FixtureEvidenceAccess(prisma);
      assert.equal(JSON.parse((await access.read(tenantId,scan.id,'synthetic-reader')).toString()).fragmentCount,0);
      assert.equal(await prisma.auditEvent.count({where:{tenantId,eventType:'evidence.read'}}),1);
      await assert.rejects(access.read('foreign-tenant',scan.id,'stranger'),{status:404});
      await prisma.evidencePack.update({where:{id:pack.id},data:{createdAt:new Date(Date.now()-10000),expiresAt:new Date(Date.now()-5000)}});
      await assert.rejects(access.read(tenantId,scan.id,'synthetic-reader'),{status:410});
      assert.equal((await enforceEvidenceExpiry(prisma,evidence)).deleted,1);
      assert.equal(evidence.objects.size,0);
      assert.ok((await prisma.evidencePack.findUnique({where:{id:pack.id}})).deletedAt);
      await assert.rejects(service.publish(lease,issued.credentialId,result()),{status:409});
      assert.equal(await prisma.normalizedFinding.count({where:{tenantId}}),2);
    }));
    await t.test('rejects stale fences and cancels a running scan on integration revocation',()=>fixture(async({tenantId,control,service,lease,issued,scan,integration})=>{
      await assert.rejects(service.publish({...lease,leaseToken:'wrong-fence'},issued.credentialId,result()),{status:409});
      await control.removeIntegration(tenantId,integration.id);
      await assert.rejects(service.publish(lease,issued.credentialId,result()),{status:409});
      assert.equal((await prisma.scanRequest.findUnique({where:{id:scan.id}})).status,'CANCELED');
      assert.equal(await prisma.scannerRun.count({where:{tenantId}}),0);
    }));
    await t.test('rolls back the entire publication on audit failure and rejects raw/invalid output',()=>fixture(async({tenantId,service,caps,lease,issued,scan,evidence})=>{
      const bad=result();bad.findings[0].codeSnippet='must-never-be-accepted';
      assert.throws(()=>validateRuntimeResult(bad),{status:400});
      const badLocation=result();badLocation.findings[1].lineStart=1;
      assert.throws(()=>validateRuntimeResult(badLocation),{status:400});
      const failing=new Proxy(prisma,{get(target,key){
        if(key!=='$transaction') return Reflect.get(target,key);
        return (operation,options)=>prisma.$transaction(tx=>operation(new Proxy(tx,{get(transaction,field){
          if(field==='auditEvent')return {create:async()=>{throw new Error('synthetic publication audit failure');}};
          return Reflect.get(transaction,field);
        }})),options);
      }});
      await assert.rejects(new RuntimeResultsService(failing,caps,evidence).publish(lease,issued.credentialId,result()),/synthetic publication audit failure/);
      assert.equal(evidence.objects.size,0);
      assert.equal(await prisma.scannerRun.count({where:{tenantId}}),0);
      assert.equal(await prisma.normalizedFinding.count({where:{tenantId}}),0);
      assert.equal(await prisma.policyDecision.count({where:{tenantId}}),0);
      assert.equal(await prisma.evidencePack.count({where:{tenantId}}),0);
      assert.equal((await prisma.scanRequest.findUnique({where:{id:scan.id}})).status,'RUNNING');
      assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:lease.jobId}})).status,'LEASED');
      const failed=result();failed.runs[2].status='FAILED';
      assert.equal((await service.publish(lease,issued.credentialId,failed)).status,'FAILED');
    }));
  } finally {await prisma.$disconnect();}
});
