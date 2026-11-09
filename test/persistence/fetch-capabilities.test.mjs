import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import test from 'node:test';

const url = process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(url, 'Dedicated verification database required');
assert.match(new URL(url).pathname, /^\/aegisai_(verify|ci|test)$/);
process.env.DATABASE_URL = url;
const require = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { PrismaClient } = require('@prisma/client');
const { ControlPlaneService } = await import('../../apps/api/dist/control-plane/control-plane.service.js');
const { ScanDispatchService } = await import('../../apps/api/dist/dispatch/scan-dispatch.service.js');
const { FetchCapabilityService } = await import('../../apps/api/dist/token-broker/fetch-capability.service.js');

test('Durable one-use private fetch capabilities against PostgreSQL', async (t) => {
  const prisma = new PrismaClient();
  const control = new ControlPlaneService(prisma);
  const queue = new ScanDispatchService(prisma);
  async function fixture(count, run) {
    const ids = Array.from({length:count},()=>String(Number.parseInt(randomBytes(6).toString('hex'),16)+1));
    const tenants = ids.map(id=>'tenant_'+createHash('sha256').update('github:'+id).digest('hex').slice(0,32));
    const config = {getOptional: key=>key==='ALLOWED_GITHUB_USER_IDS'?ids.join(','):undefined};
    const broker = new FetchCapabilityService(prisma,config);
    const inputs = [];
    const integrations = [];
    try {
      assert.equal(await prisma.scanDispatchJob.count({where:{status:{in:['PENDING','LEASED']}}}),0,'Run isolated DB suites serially');
      for (const tenantId of tenants) {
        await prisma.tenant.create({data:{id:tenantId,slug:tenantId,name:'Synthetic capability verification'}});
        integrations.push(await control.installIntegration({tenantId,externalInstallationId:'99',repoReadPrincipalId:'verified-test-read',
          repositories:[{providerRepoId:'100',fullName:'AigisAI/fixture',defaultBranch:'main',isPrivate:true}]},
        {provider:'GITHUB',integrationType:'GITHUB_APP'}));
        const [binding] = await control.listRepositoryBindings(tenantId);
        inputs.push({tenantId,repositoryBindingId:binding.id,lane:'FAST',targetRef:'main',commitSha:'a'.repeat(40),
          policyVersion:'v1',scannerSetVersion:'v1'});
        await control.createScanRequest(inputs.at(-1));
      }
      await broker.startEpoch();
      const leases=[];
      for(let i=0;i<count;i++) leases.push(await queue.claim('capability_fixture_'+i));
      assert.ok(leases.every(Boolean));
      await run({broker,config,tenants,inputs,integrations,leases});
    } finally {
      await prisma.tenant.deleteMany({where:{id:{in:tenants}}});
      await prisma.scanBrokerRuntime.deleteMany({where:{id:'private-single-host'}});
    }
  }
  try {
    await t.test('issues ten-minute hash-only authority, derives immutable scope and consumes exactly once',()=>fixture(1,async({broker,leases})=>{
      const lease=leases[0];
      const issued=await broker.issue(lease);
      const row=await prisma.scanFetchCapability.findUnique({where:{id:issued.credentialId}});
      assert.equal(row.expiresAt-row.issuedAt,600000);
      assert.equal(issued.expiresInSeconds,600);
      const attempts=await Promise.allSettled(Array.from({length:6},()=>broker.consume(lease,issued.capability)));
      const claimed=attempts.filter(item=>item.status==='fulfilled');
      assert.equal(claimed.length,1);
      assert.ok(attempts.filter(item=>item.status==='rejected').every(item=>item.reason.status===409));
      const claim=claimed[0].value;
      assert.equal(await broker.validateClaim(lease.tenantId,claim.credentialId,claim.claimToken),true);
      assert.equal(claim.commitSha,'a'.repeat(40));
      assert.equal(claim.providerRepoId,'100');
      assert.match(claim.providerUserId,/^[1-9][0-9]*$/);
      assert.equal('tenant_'+createHash('sha256').update('github:'+claim.providerUserId).digest('hex').slice(0,32),lease.tenantId);
      assert.equal(claim.installationId,'99');
      assert.equal(claim.repositoryBindingId,(await prisma.scanRequest.findUnique({where:{id:lease.scanRequestId}})).repositoryBindingId);
      const stored=JSON.stringify(await prisma.scanFetchCapability.findMany({where:{tenantId:lease.tenantId}}))+
        JSON.stringify(await prisma.auditEvent.findMany({where:{tenantId:lease.tenantId}}));
      for(const value of [issued.capability,claim.claimToken,lease.leaseToken]) assert.equal(stored.includes(value),false);
      assert.deepEqual(await broker.complete(lease.tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true}),
        {handoffAllowed:true,integrationSuspended:false});
      assert.equal((await prisma.scanFetchCapability.findUnique({where:{id:claim.credentialId}})).status,'CONSUMED');
      await assert.rejects(broker.complete(lease.tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true}),{status:409});
      assert.equal((await prisma.scanRequest.findUnique({where:{id:lease.scanRequestId}})).status,'PLANNING');
    }));
    await t.test('denies cross-tenant, forged capability and stale dispatch fences',()=>fixture(2,async({broker,leases})=>{
      const [one,two]=leases;
      const issued=await broker.issue(one);
      await assert.rejects(broker.consume(two,issued.capability),{status:409});
      await assert.rejects(broker.consume(one,randomBytes(32).toString('base64url')),{status:409});
      await assert.rejects(broker.issue({...one,leaseToken:randomUUID()}),{status:409});
      const claim=await broker.consume(one,issued.capability);
      await assert.rejects(broker.complete(two.tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true}),{status:409});
      await assert.rejects(broker.validateClaim(two.tenantId,claim.credentialId,claim.claimToken),{status:409});
      await assert.rejects(broker.complete(one.tenantId,claim.credentialId,randomBytes(32).toString('base64url'),{success:true,upstreamRevoked:true}),{status:409});
      await prisma.scanDispatchJob.update({where:{id:one.jobId},data:{leaseExpiresAt:new Date(0)}});
      await assert.rejects(broker.validateClaim(one.tenantId,claim.credentialId,claim.claimToken),{status:409});
      assert.equal((await broker.complete(one.tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true})).handoffAllowed,false);
    }));
    await t.test('enforces TTL in service and SQL and rejects expired unconsumed authority',()=>fixture(1,async({broker,leases})=>{
      const lease=leases[0];
      for(const ttl of [0,601,1.5]) await assert.rejects(broker.issue(lease,ttl),{status:400});
      const issued=await broker.issue(lease);
      const row=await prisma.scanFetchCapability.findUnique({where:{id:issued.credentialId}});
      await assert.rejects(prisma.scanFetchCapability.update({where:{id:row.id},data:{expiresAt:new Date(row.issuedAt.getTime()+601000)}}));
      const expired=Date.now();
      await prisma.scanFetchCapability.update({where:{id:row.id},data:{issuedAt:new Date(expired-700000),expiresAt:new Date(expired-100000)}});
      await assert.rejects(broker.consume(lease,issued.capability),{status:409});
    }));
    await t.test('rotates undelivered capabilities but refuses to rotate an active gateway claim',()=>fixture(1,async({broker,leases})=>{
      const lease=leases[0];
      const old=await broker.issue(lease);
      const current=await broker.issue(lease);
      await assert.rejects(broker.consume(lease,old.capability),{status:409});
      await broker.consume(lease,current.capability);
      await assert.rejects(broker.issue(lease),{status:409});
      assert.equal(await prisma.scanFetchCapability.count({where:{dispatchJobId:lease.jobId,status:{in:['ISSUED','CONSUMING']}}}),1);
    }));
    await t.test('denies unsupported hardened/restricted profiles before source issuance or handoff',()=>fixture(1,async({broker,leases})=>{
      const lease=leases[0];
      await prisma.scanRequest.update({where:{id:lease.scanRequestId},data:{isolationClass:'HARDENED'}});
      await assert.rejects(broker.issue(lease),{status:409});
      await prisma.scanRequest.update({where:{id:lease.scanRequestId},data:{isolationClass:'STANDARD'}});
      const issued=await broker.issue(lease);
      const claim=await broker.consume(lease,issued.capability);
      await prisma.scanRequest.update({where:{id:lease.scanRequestId},data:{isolationClass:'RESTRICTED'}});
      await assert.rejects(broker.validateClaim(lease.tenantId,claim.credentialId,claim.claimToken),{status:409});
      assert.equal((await broker.complete(lease.tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true})).handoffAllowed,false);
    }));
    await t.test('denies source checks and parser handoff when a consumed gateway lease expires',()=>fixture(1,async({broker,leases})=>{
      const lease=leases[0];
      const issued=await broker.issue(lease);
      const claim=await broker.consume(lease,issued.capability);
      const expired=Date.now();
      await prisma.scanFetchCapability.update({where:{id:issued.credentialId},data:{issuedAt:new Date(expired-700000),expiresAt:new Date(expired-100000)}});
      await assert.rejects(broker.validateClaim(lease.tenantId,claim.credentialId,claim.claimToken),{status:409});
      assert.equal((await broker.complete(lease.tenantId,claim.credentialId,claim.claimToken,{success:true,upstreamRevoked:true})).handoffAllowed,false);
    }));
    await t.test('invalidates old broker epochs and old values without persisting their secrets',()=>fixture(1,async({broker,config,leases})=>{
      const lease=leases[0];
      const issued=await broker.issue(lease);
      const restarted=new FetchCapabilityService(prisma,config);
      await restarted.startEpoch();
      await assert.rejects(broker.issue(lease),{status:409});
      await assert.rejects(restarted.consume(lease,issued.capability),{status:409});
      assert.equal((await prisma.scanFetchCapability.findUnique({where:{id:issued.credentialId}})).status,'REVOKED');
      const next=await restarted.issue(lease);
      assert.ok(await restarted.consume(lease,next.capability));
    }));
    await t.test('suspends integration and fails/cancels the job when upstream revocation is unconfirmed',()=>fixture(1,async({broker,leases,integrations})=>{
      const lease=leases[0];
      const cap=await broker.issue(lease);
      const claim=await broker.consume(lease,cap.capability);
      assert.deepEqual(await broker.complete(lease.tenantId,cap.credentialId,claim.claimToken,{success:true,upstreamRevoked:false}),
        {handoffAllowed:false,integrationSuspended:true});
      assert.equal((await prisma.scmIntegration.findUnique({where:{id:integrations[0].id}})).status,'SUSPENDED');
      assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:lease.jobId}})).status,'CANCELED');
      assert.equal((await prisma.scanRequest.findUnique({where:{id:lease.scanRequestId}})).status,'FAILED');
      assert.equal(await prisma.auditEvent.count({where:{tenantId:lease.tenantId,eventType:'token.revocation_unconfirmed'}}),1);
    }));
    await t.test('fails closed after restart with an interrupted gateway claim',()=>fixture(1,async({broker,config,leases,integrations})=>{
      const lease=leases[0];
      const cap=await broker.issue(lease);
      await broker.consume(lease,cap.capability);
      await new FetchCapabilityService(prisma,config).startEpoch();
      assert.equal((await prisma.scmIntegration.findUnique({where:{id:integrations[0].id}})).status,'SUSPENDED');
      assert.equal((await prisma.scanDispatchJob.findUnique({where:{id:lease.jobId}})).status,'CANCELED');
      assert.equal((await prisma.scanFetchCapability.findUnique({where:{id:cap.credentialId}})).status,'REVOKED');
    }));
    await t.test('rejects tenant suspension, integration revocation and accounts outside private admission',()=>fixture(1,async({broker,leases,integrations})=>{
      const lease=leases[0];
      const unadmitted=new FetchCapabilityService(prisma,{getOptional:()=> '1'});
      await assert.rejects(unadmitted.issue(lease),{status:403});
      await prisma.tenant.update({where:{id:lease.tenantId},data:{status:'SUSPENDED'}});
      await assert.rejects(broker.issue(lease),{status:409});
      await prisma.tenant.update({where:{id:lease.tenantId},data:{status:'ACTIVE'}});
      const cap=await broker.issue(lease);
      const claim=await broker.consume(lease,cap.capability);
      await control.removeIntegration(lease.tenantId,integrations[0].id);
      await assert.rejects(broker.validateClaim(lease.tenantId,claim.credentialId,claim.claimToken),{status:409});
      assert.equal((await broker.complete(lease.tenantId,cap.credentialId,claim.claimToken,{success:true,upstreamRevoked:true})).handoffAllowed,false);
      await assert.rejects(broker.issue(lease),{status:409});
    }));
    await t.test('enforces tenant/job/scan composite FK and state invariants in PostgreSQL',()=>fixture(1,async({broker,leases,inputs})=>{
      const lease=leases[0];
      const issued=await broker.issue(lease);
      const row=await prisma.scanFetchCapability.findUnique({where:{id:issued.credentialId}});
      await assert.rejects(prisma.scanFetchCapability.update({where:{id:row.id},data:{status:'CONSUMING'}}));
      await assert.rejects(prisma.scanFetchCapability.create({data:{
        tenantId:row.tenantId,scanRequestId:row.scanRequestId,dispatchJobId:row.dispatchJobId,issuerEpoch:row.issuerEpoch,
        fingerprint:'e'.repeat(64),leaseFingerprint:'f'.repeat(64),issuedAt:row.issuedAt,expiresAt:row.expiresAt
      }}),error=>error.code==='P2002');
      const claim=await broker.consume(lease,issued.capability);
      await broker.complete(lease.tenantId,row.id,claim.claimToken,{success:false,upstreamRevoked:true});
      const other=await control.createScanRequest({...inputs[0],commitSha:'b'.repeat(40)});
      const data={tenantId:lease.tenantId,scanRequestId:other.id,dispatchJobId:lease.jobId,issuerEpoch:row.issuerEpoch,
        fingerprint:'c'.repeat(64),leaseFingerprint:'d'.repeat(64),issuedAt:row.issuedAt,expiresAt:row.expiresAt};
      await assert.rejects(prisma.scanFetchCapability.create({data}),error=>error.code==='P2003');
      await assert.rejects(prisma.scanBrokerRuntime.create({data:{id:'unexpected-broker',epoch:randomUUID()}}));
    }));
    await t.test('rolls back authority issuance when its required audit cannot be written',()=>fixture(1,async({config,leases})=>{
      const failing=new Proxy(prisma,{get(target,key){
        if(key!=='$transaction') return Reflect.get(target,key);
        return (operation,options)=>prisma.$transaction(tx=>operation(new Proxy(tx,{get(transaction,field){
          if(field==='auditEvent') return {create:async()=>{throw new Error('synthetic audit failure');}};
          return Reflect.get(transaction,field);
        }})),options);
      }});
      const broker=new FetchCapabilityService(failing,config);
      await broker.startEpoch();
      await assert.rejects(broker.issue(leases[0]),/synthetic audit failure/);
      assert.equal(await prisma.scanFetchCapability.count({where:{tenantId:leases[0].tenantId}}),0);
    }));
  } finally { await prisma.$disconnect(); }
});
