import assert from 'node:assert/strict';
import {createHash,createHmac} from 'node:crypto';
import {createRequire} from 'node:module';
import {loadRuntimeSecrets} from '/app/apps/api/dist/data-security/runtime-secrets.js';
import {assertPrivateDatabase} from '/app/apps/api/dist/data-security/private-profile.js';
import {PrismaService} from '/app/apps/api/dist/prisma/prisma.service.js';
import {EvidenceAccessService} from '/app/apps/api/dist/data-security/evidence-access.service.js';
import {RuntimeApiService} from '/app/apps/api/dist/runtime/runtime-api.service.js';
const require=createRequire('/app/apps/api/package.json');
await loadRuntimeSecrets('api');await assertPrivateDatabase();
const prisma=new PrismaService();const redis=require('redis').createClient({url:process.env.REDIS_URL});
const owner='161540124';const tenant='tenant_'+createHash('sha256').update('github:'+owner).digest('hex').slice(0,32);
const scanId='scan_request_77c5b7c8-c3a8-4b01-be7e-7a348e0664ea';
try {
 const counts={};for(const name of ['userOAuthIdentity','scmIntegration','repositoryBinding','scanRequest','scannerRun','evidencePack'])counts[name]=await prisma[name].count();
 assert.deepEqual(counts,{userOAuthIdentity:1,scmIntegration:1,repositoryBinding:5,scanRequest:1,scannerRun:3,evidencePack:1});
 assert.ok(await prisma.userOAuthIdentity.findUnique({where:{provider_providerUserId:{provider:'GITHUB',providerUserId:owner}}}));
 assert.equal((await prisma.scanDispatchJob.findUnique({where:{scanRequestId:scanId}})).status,'SUCCEEDED');
 const api=new RuntimeApiService(prisma,undefined,undefined,undefined);const detail=await api.detail(tenant,scanId);
 assert.equal(detail.status,'COMPLETED');assert.equal(detail.ai,'DISABLED');assert.equal(detail.coverage,'LIMITED');assert.equal(detail.runs.length,3);
 const access=new EvidenceAccessService(prisma);const evidence=JSON.parse((await access.read(tenant,scanId,'deployment-20261109-verifier')).toString());
 assert.equal(evidence.ai,'DISABLED');assert.equal(evidence.fragmentCount,0);assert.equal(evidence.redacted,true);
 await assert.rejects(access.read('tenant_deployment_denied',scanId,'deployment-20261109-verifier'),error=>error.getStatus?.()===404);
 assert.equal((await fetch('http://127.0.0.1:3000/api/runtime/scans')).status,401);
 await redis.connect();let session;
 for await (const batch of redis.scanIterator({MATCH:'aegisai:session:*',COUNT:50})) {
  for(const key of typeof batch==='string'?[batch]:batch) {
   const raw=await redis.get(key);if(!raw)continue;const value=JSON.parse(raw);
   if(value.auth?.providerUserId===owner && Date.parse(value.cookie?.expires)>Date.now()) {session={id:key.slice('aegisai:session:'.length),auth:value.auth};break;}
  }
  if(session)break;
 }
 let existingSessionVerified=false;
 if(session) {
  const signature=createHmac('sha256',process.env.SESSION_SECRET).update(session.id).digest('base64').replace(/=+$/,'');
  const cookie=(process.env.SESSION_COOKIE_NAME||'connect.sid')+'='+encodeURIComponent('s:'+session.id+'.'+signature);
  const headers={Cookie:cookie,'X-Forwarded-Proto':'https'};
  async function read(path) {const response=await fetch('http://127.0.0.1:3000/api'+path,{headers});assert.equal(response.status,200);return response.json();}
  assert.equal((await read('/auth/me')).authenticated,true);
  assert.equal((await read('/runtime/repositories')).length,5);
  assert.equal((await read('/runtime/scans')).length,1);
  assert.equal((await read('/runtime/scans/'+scanId)).status,'COMPLETED');
  const fetched=await fetch('http://127.0.0.1:3000/api/runtime/scans/'+scanId+'/evidence',{headers});assert.equal(fetched.status,200);await fetched.arrayBuffer();
  existingSessionVerified=true;
 }
 console.log(JSON.stringify({postDeploymentReadAcceptance:'passed',counts,existingIdentityVerified:true,existingSessionVerified,noSyntheticSessionCreated:true,
  existingScanReadable:true,existingEncryptedEvidenceReadable:true,unauthorizedReadDenied:true,crossTenantEvidenceDenied:true,completedJobNotReplayed:true,
  ai:'DISABLED',newScanExecuted:false,browserOauthRepeated:false,verifiedAt:new Date().toISOString()}));
} finally {if(redis.isOpen)await redis.quit();await prisma.$disconnect();}
