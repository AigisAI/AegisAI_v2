import assert from 'node:assert/strict';
import { createHash,randomBytes } from 'node:crypto';
import { mkdtemp,chown,chmod,lstat,rm } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRequire } from 'node:module';
import test from 'node:test';

assert.equal(process.platform,'linux','Run this acceptance suite in the target Linux API image');
assert.equal(process.getuid(),0,'Target fixture needs isolated container UID 0, never a production database');
const url=process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(url);
assert.match(new URL(url).pathname,/^\/aegisai_(verify|ci|test)$/);
process.env.DATABASE_URL=url;
const require=createRequire(new URL('../../apps/private-api/package.json',import.meta.url));
const {PrismaClient}=require('@aegisai/private-runtime-db');
const {ControlPlaneService}=await import('../../apps/private-api/dist/control-plane/control-plane.service.js');
const {PrivateWorkerBroker}=await import('../../apps/private-api/dist/worker/private-worker-broker.js');
const {GithubReadSession}=await import('../../apps/private-api/dist/control-plane/github-read-session.js');
const {MemoryEvidenceStore}=await import('../../apps/private-api/test/support/memory-evidence.mjs');
const execute=promisify(execFile);

function request(socketPath,path,value) {
  const encoded=Buffer.from(JSON.stringify(value));
  return new Promise((resolve,reject)=>{
    const req=http.request({socketPath,path,method:'POST',headers:{'Content-Type':'application/json','Content-Length':encoded.length}},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));
      res.once('end',()=>{try {resolve({status:res.statusCode,body:JSON.parse(Buffer.concat(chunks).toString())});}catch{reject(new Error('Invalid private fixture reply'));}});
    });
    req.setTimeout(10000,()=>req.destroy(new Error('Private fixture timeout')));
    req.once('error',reject);req.end(encoded);
  });
}
function health(socketPath) {
  return new Promise((resolve,reject)=>{
    const req=http.get({socketPath,path:'/health'},res=>{res.resume();res.once('end',()=>resolve(res.statusCode));});
    req.once('error',reject);
  });
}
function open(socketPath,lease,capability) {
  const encoded=Buffer.from(JSON.stringify({lease,capability}));
  return new Promise((resolve,reject)=>{
    const req=http.request({socketPath,path:'/gateway/open',method:'POST',headers:{'Content-Type':'application/json','Content-Length':encoded.length}},res=>{
      if(res.statusCode!==200) {res.resume();reject(new Error('Private fixture open failed'));return;}
      let text='';const frames=[];
      res.on('data',chunk=>{
        text+=chunk.toString();
        if(text.length>16384) {req.destroy();reject(new Error('Private frame bound exceeded'));return;}
        let next;
        while((next=text.indexOf('\n'))>=0) {
          frames.push(JSON.parse(text.slice(0,next)));text=text.slice(next+1);
          if(frames.length===2) resolve({frames,close:()=>req.destroy()});
        }
      });
      res.once('error',()=>{if(frames.length<2)reject(new Error('Private stream ended early'));});
      res.once('end',()=>{if(frames.length<2)reject(new Error('Private stream ended early'));});
    });
    req.setTimeout(10000,()=>req.destroy(new Error('Private fixture timeout')));
    req.once('error',reject);req.end(encoded);
  });
}

test('Private Unix worker/gateway broker in target Node image',async t=>{
  const prisma=new PrismaClient();
  const control=new ControlPlaneService(prisma);
  async function fixture(run) {
    assert.equal(await prisma.scanDispatchJob.count({where:{status:{in:['PENDING','LEASED']}}}),0,'Run verification DB suites serially');
    const id=String(Number.parseInt(randomBytes(6).toString('hex'),16)+1);
    const tenantId='tenant_'+createHash('sha256').update('github:'+id).digest('hex').slice(0,32);
    const unadmittedId='unadmitted_native_'+randomBytes(8).toString('hex');
    const directory=await mkdtemp(join(tmpdir(),'aegisai-private-broker-'));
    await chown(directory,0,50001);await chmod(directory,0o2750);
    const config={getOptional:key=>key==='ALLOWED_GITHUB_USER_IDS'?id:undefined};
    const sourceToken='synthetic-upstream-only-not-public';
    let revocations=0,opened=0,revokeFails=false;
    let databaseFails=false,allowUnconfirmedCleanup=false;
    const brokerDatabase=new Proxy(prisma,{get(target,key){
      if(key==='$transaction') return (...args)=>{
        if(databaseFails) return Promise.reject(new Error('synthetic database unavailable'));
        return target.$transaction(...args);
      };
      if(key==='scanBrokerRuntime') return {findUnique:args=>{
        if(databaseFails) return Promise.reject(new Error('synthetic database unavailable'));
        return target.scanBrokerRuntime.findUnique(args);
      }};
      return Reflect.get(target,key);
    }});
    const provider={openReadSession:async(installation,repository,user,deadline,unconfirmed)=>{
      assert.equal(installation,99);assert.equal(repository,100);assert.equal(user,id);
      opened++;
      return new GithubReadSession(sourceToken,deadline,async()=>{revocations++;if(revokeFails)throw new Error(sourceToken);},unconfirmed);
    }};
    const evidence=new MemoryEvidenceStore();
    const broker=new PrivateWorkerBroker(brokerDatabase,config,provider,directory,50001,undefined,evidence);
    const controlSocket=join(directory,'control.sock'),gatewaySocket=join(directory,'gateway.sock');
    try {
      await prisma.tenant.create({data:{id:unadmittedId,slug:unadmittedId,name:'Unadmitted synthetic verification'}});
      await control.installIntegration({tenantId:unadmittedId,externalInstallationId:'99',repoReadPrincipalId:'verified-test-read',
        repositories:[{providerRepoId:'100',fullName:'AigisAI/fixture',defaultBranch:'main',isPrivate:true}]},
      {provider:'GITHUB',integrationType:'GITHUB_APP'});
      const [unadmittedBinding]=await control.listRepositoryBindings(unadmittedId);
      await control.createScanRequest({tenantId:unadmittedId,repositoryBindingId:unadmittedBinding.id,lane:'FAST',targetRef:'main',commitSha:'a'.repeat(40),policyVersion:'v1',scannerSetVersion:'v1'});
      await prisma.tenant.create({data:{id:tenantId,slug:tenantId,name:'Synthetic Unix verification'}});
      const integration=await control.installIntegration({tenantId,externalInstallationId:'99',repoReadPrincipalId:'verified-test-read',
        repositories:[{providerRepoId:'100',fullName:'AigisAI/fixture',defaultBranch:'main',isPrivate:true}]},
      {provider:'GITHUB',integrationType:'GITHUB_APP'});
      const [binding]=await control.listRepositoryBindings(tenantId);
      await control.createScanRequest({tenantId,repositoryBindingId:binding.id,lane:'FAST',targetRef:'main',commitSha:'a'.repeat(40),policyVersion:'v1',scannerSetVersion:'v1'});
      await broker.start();
      const claimed=await request(controlSocket,'/worker/claim',{workerId:'native_fixture'});
      assert.equal(claimed.status,200);assert.ok(claimed.body.data);
      const lease=claimed.body.data.lease;
      assert.equal(lease.tenantId,tenantId);
      assert.equal(await prisma.scanDispatchJob.count({where:{tenantId:unadmittedId,status:'PENDING'}}),1);
      const issued=await request(controlSocket,'/worker/capability',{lease});
      assert.equal(issued.status,200);
      assert.equal(JSON.stringify(issued.body).includes(sourceToken),false);
      await run({broker,config,provider,directory,evidence,controlSocket,gatewaySocket,lease,cap:issued.body.data,tenantId,integration,
        sourceToken,counts:()=>({revocations,opened}),failRevocation:()=>{revokeFails=true;},
        databaseFailure:value=>{databaseFails=value;},allowUnconfirmedCleanup:()=>{allowUnconfirmedCleanup=true;}});
    } finally {
      let closeError;
      try {await broker.close();} catch(error){closeError=error;}
      finally {
        await prisma.tenant.deleteMany({where:{id:{in:[tenantId,unadmittedId]}}});
        await prisma.scanBrokerRuntime.deleteMany({where:{id:'private-single-host'}});
        assert.ok(directory.startsWith(join(tmpdir(),'aegisai-private-broker-')));
        await rm(directory,{recursive:true,force:true});
      }
      if(closeError && !(allowUnconfirmedCleanup && closeError.message==='BROKER_FINALIZATION_UNCONFIRMED')) throw closeError;
    }
  }
  try {
    await t.test('separates filesystem roles and sends upstream secrets only on the gateway stream',()=>fixture(async f=>{
      assert.equal((await lstat(f.controlSocket)).mode&0o777,0o600);
      assert.equal((await lstat(f.gatewaySocket)).mode&0o777,0o660);
      const probe='const n=require("node:net");const s=n.createConnection(process.argv[1]);s.once("connect",()=>{process.stdout.write("CONNECTED");s.destroy();});s.once("error",e=>process.stdout.write(e.code));';
      assert.equal((await execute(process.execPath,['-e',probe,f.controlSocket],{uid:50001,gid:50001})).stdout,'EACCES');
      assert.equal((await execute(process.execPath,['-e',probe,f.gatewaySocket],{uid:50001,gid:50001})).stdout,'CONNECTED');
      assert.equal((await request(f.gatewaySocket,'/worker/claim',{workerId:'forbidden'})).status,403);
      assert.equal((await request(f.controlSocket,'/gateway/open',{lease:f.lease,capability:f.cap.capability})).status,403);
      assert.equal(f.counts().opened,0);
      const start={lease:f.lease,credentialId:f.cap.credentialId};
      assert.equal((await request(f.gatewaySocket,'/worker/start',start)).status,403);
      assert.equal((await request(f.controlSocket,'/worker/start',start)).status,409);
      const stream=await open(f.gatewaySocket,f.lease,f.cap.capability);
      const claim=stream.frames[0].claim;
      assert.equal(stream.frames[0].kind,'fetch-scope');
      assert.equal(stream.frames[1].upstreamToken,f.sourceToken);
      const auth={tenantId:f.tenantId,credentialId:claim.credentialId,claimToken:claim.claimToken};
      assert.equal((await request(f.gatewaySocket,'/gateway/check',auth)).body.data.authorized,true);
      const result=await request(f.gatewaySocket,'/gateway/finish',{...auth,success:true});
      assert.deepEqual(result.body.data,{handoffAllowed:true,integrationSuspended:false});
      assert.equal(f.counts().revocations,1);stream.close();
      assert.equal((await prisma.scanFetchCapability.findUnique({where:{id:claim.credentialId}})).status,'CONSUMED');
      assert.equal((await request(f.controlSocket,'/worker/start',start)).status,200);
      assert.equal((await request(f.controlSocket,'/worker/heartbeat',{lease:f.lease})).status,200);
      const publication=await request(f.controlSocket,'/worker/publish',{...start,result:{
        scannerSetVersion:'v1',vulnerabilityDatabaseDigest:'sha256:'+'d'.repeat(64),
        runs:['OPENGREP','TRIVY','SYFT'].map(scanner=>({scanner,status:'COMPLETED',durationMs:10})),findings:[]}});
      assert.equal(publication.status,200);
      assert.deepEqual(publication.body.data,{status:'COMPLETED',findingCount:0,ai:'DISABLED'});
      assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:f.lease.jobId}})).status,'SUCCEEDED');
    }));
    await t.test('records unsupported input as a terminal rejection without retrying or issuing an upstream token',()=>fixture(async f=>{
      const response=await request(f.controlSocket,'/worker/reject',{lease:f.lease,reason:'UNSUPPORTED_SCAN_PROFILE'});
      assert.equal(response.status,200);assert.equal(f.counts().opened,0);
      assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:f.lease.jobId}})).status,'DEAD');
      assert.equal((await prisma.scanRequest.findUnique({where:{id:f.lease.scanRequestId}})).status,'FAILED');
      assert.equal((await prisma.scanFetchCapability.findUnique({where:{id:f.cap.credentialId}})).status,'REVOKED');
    }));
    await t.test('revokes and denies handoff after the gateway channel disconnects',()=>fixture(async f=>{
      const stream=await open(f.gatewaySocket,f.lease,f.cap.capability);
      const id=stream.frames[0].claim.credentialId;
      stream.close();
      for(let attempt=0;attempt<50;attempt++) {
        if((await prisma.scanFetchCapability.findUnique({where:{id}})).status==='REVOKED')break;
        await new Promise(resolve=>setTimeout(resolve,50));
      }
      assert.equal((await prisma.scanFetchCapability.findUnique({where:{id}})).status,'REVOKED');
      assert.equal(f.counts().revocations,1);
      assert.equal((await prisma.scmIntegration.findUnique({where:{id:f.integration.id}})).status,'ACTIVE');
    }));
    await t.test('suspends on unconfirmed revocation without returning provider errors',()=>fixture(async f=>{
      const stream=await open(f.gatewaySocket,f.lease,f.cap.capability);
      const claim=stream.frames[0].claim;f.failRevocation();
      const result=await request(f.gatewaySocket,'/gateway/finish',{tenantId:f.tenantId,credentialId:claim.credentialId,claimToken:claim.claimToken,success:true});
      assert.equal(result.status,200);
      assert.deepEqual(result.body.data,{handoffAllowed:false,integrationSuspended:true});
      assert.equal(JSON.stringify(result.body).includes(f.sourceToken),false);
      assert.equal((await prisma.scmIntegration.findUnique({where:{id:f.integration.id}})).status,'SUSPENDED');
      stream.close();
    }));
    await t.test('rejects malformed scope and duplicate startup before rotating a live epoch',()=>fixture(async f=>{
      assert.equal((await request(f.controlSocket,'/worker/capability',{lease:f.lease,tenantId:f.tenantId})).status,400);
      const before=await prisma.scanBrokerRuntime.findUnique({where:{id:'private-single-host'}});
      const duplicate=new PrivateWorkerBroker(prisma,f.config,f.provider,f.directory,50001,undefined,f.evidence);
      await assert.rejects(duplicate.start(),/BROKER_ALREADY_RUNNING/);
      assert.equal((await prisma.scanBrokerRuntime.findUnique({where:{id:'private-single-host'}})).epoch,before.epoch);
      const stream=await open(f.gatewaySocket,f.lease,f.cap.capability);
      const claim=stream.frames[0].claim;
      assert.equal((await request(f.gatewaySocket,'/gateway/finish',{tenantId:f.tenantId,credentialId:claim.credentialId,claimToken:claim.claimToken,success:true})).body.data.handoffAllowed,true);
      stream.close();
    }));
    await t.test('revokes independently of DB failure, closes readiness and reconciles interrupted authority on restart',()=>fixture(async f=>{
      const stream=await open(f.gatewaySocket,f.lease,f.cap.capability);
      const claim=stream.frames[0].claim;
      f.databaseFailure(true);
      assert.equal(await health(f.controlSocket),503);
      const result=await request(f.gatewaySocket,'/gateway/finish',{tenantId:f.tenantId,credentialId:claim.credentialId,claimToken:claim.claimToken,success:true});
      assert.equal(result.status,503);
      assert.equal(f.counts().revocations,1);
      f.databaseFailure(false);
      assert.equal(await health(f.controlSocket),503);
      f.allowUnconfirmedCleanup();
      await assert.rejects(f.broker.close(),/BROKER_FINALIZATION_UNCONFIRMED/);
      const restarted=new PrivateWorkerBroker(prisma,f.config,f.provider,f.directory,50001,undefined,f.evidence);
      try {
        await restarted.start();
        assert.equal((await prisma.scmIntegration.findUnique({where:{id:f.integration.id}})).status,'SUSPENDED');
        assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:f.lease.jobId}})).status,'CANCELED');
        assert.equal((await prisma.scanFetchCapability.findUnique({where:{id:claim.credentialId}})).status,'REVOKED');
      } finally {await restarted.close();stream.close();}
    }));
  } finally {await prisma.$disconnect();}
});
