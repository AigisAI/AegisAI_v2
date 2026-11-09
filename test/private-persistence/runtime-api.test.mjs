import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
import test from 'node:test';

const url=process.env.PERSISTENCE_TEST_DATABASE_URL;
assert.ok(url);assert.match(new URL(url).pathname,/^\/aegisai_(verify|ci|test)$/);process.env.DATABASE_URL=url;
const require=createRequire(new URL('../../apps/private-api/package.json',import.meta.url));
const {PrismaClient}=require('@aegisai/private-runtime-db');
const {ControlPlaneService}=await import('../../apps/private-api/dist/control-plane/control-plane.service.js');
const {RuntimeApiService}=await import('../../apps/private-api/dist/runtime/runtime-api.service.js');

test('Production request scope, immutable resolution and concurrent private queue capacity',async()=>{
  const prisma=new PrismaClient(),control=new ControlPlaneService(prisma);
  const tenantId='tenant_api_'+randomUUID().replaceAll('-','');
  let calls=0;
  try {
    await prisma.tenant.create({data:{id:tenantId,slug:tenantId,name:'Synthetic API verification'}});
    await control.installIntegration({tenantId,externalInstallationId:'99',repoReadPrincipalId:'verified-test-read',
      repositories:[{providerRepoId:'100',fullName:'AigisAI/fixture',defaultBranch:'main',isPrivate:true}]},
    {provider:'GITHUB',integrationType:'GITHUB_APP'});
    const [binding]=await control.listRepositoryBindings(tenantId);
    const provider={resolveBranchCommit:async(installation,repository,user,branch)=>{
      assert.equal(installation,99);assert.equal(repository,100);assert.equal(user,'42');calls++;
      return {commitSha:(Number(branch.slice(-1))+1).toString(16).repeat(40),targetRef:branch,providerRepoId:'100'};
    }};
    const catalog={read:async()=>({ready:true,busy:false,ai:'DISABLED',scannerSetVersion:'java-v1:'+'a'.repeat(16)+':'+'b'.repeat(64),policyVersion:'private-java-v1'})};
    const api=new RuntimeApiService(prisma,control,provider,catalog);
    const principal={userId:'synthetic-user',tenantId,provider:'GITHUB',providerUserId:'42',email:'fixture@example.test',name:'Fixture'};
    await assert.rejects(api.create({...principal,tenantId:'foreign'},binding.id,'branch0'),{status:404});assert.equal(calls,0);
    const submitted=await Promise.allSettled(Array.from({length:5},(_,index)=>api.create(principal,binding.id,'branch'+index)));
    assert.equal(submitted.filter(item=>item.status==='fulfilled').length,3);
    assert.equal(submitted.filter(item=>item.status==='rejected'&&item.reason.status===503).length,2);
    assert.equal(await prisma.scanRequest.count({where:{tenantId}}),3);
    assert.equal(await prisma.scanDispatchJob.count({where:{tenantId}}),3);
    const canonical=submitted.find(item=>item.status==='fulfilled').value;
    const repeated=await api.create(principal,binding.id,canonical.targetRef);
    assert.equal(repeated.id,canonical.id);
    assert.equal((await api.list(tenantId)).length,3);
    assert.equal((await api.list('foreign')).length,0);
    await assert.rejects(api.detail('foreign',canonical.id),{status:404});
  } finally {await prisma.tenant.deleteMany({where:{id:tenantId}});await prisma.$disconnect();}
});
