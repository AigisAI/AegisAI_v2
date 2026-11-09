import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import test from 'node:test';

const privateRequire=createRequire(new URL('../../apps/private-api/package.json',import.meta.url));
const generalRequire=createRequire(new URL('../../apps/api/package.json',import.meta.url));
const privateClient=privateRequire('@aegisai/private-runtime-db');
const generalClient=generalRequire('@prisma/client');
const {validatePrivateHistory}=await import('../../apps/private-api/dist/data-security/private-profile.js');
const profile=JSON.parse(readFileSync(new URL('../../deploy/aws-ec2/runtime-profile.json',import.meta.url),'utf8'));
const history=()=>profile.migrations.map(m=>({migration_name:m.name,checksum:m.acceptedAppliedChecksums[0],finished_at:new Date(),rolled_back_at:null}));

test('general and private generated Prisma models coexist without shared generation state',()=>{
  const privateModels=privateClient.Prisma.dmmf.datamodel.models.map(m=>m.name);
  const generalModels=generalClient.Prisma.dmmf.datamodel.models.map(m=>m.name);
  assert.ok(privateModels.includes('UserOAuthIdentity'));
  assert.ok(privateModels.includes('ScanDispatchJob'));
  assert.ok(!generalModels.includes('UserOAuthIdentity'));
  assert.ok(generalModels.includes('OAuthToken'));
  assert.ok(generalModels.length>privateModels.length);
  assert.notEqual(privateClient.PrismaClient,generalClient.PrismaClient);
});

test('private history accepts only complete approved existing migrations, never general schema history',()=>{
  assert.doesNotThrow(()=>validatePrivateHistory(profile,history()));
  for(const mutate of [
    rows=>rows.pop(),rows=>rows.push({...rows[0]}),
    rows=>{rows[1].migration_name='20260603070000_production_architecture_baseline';},
    rows=>{rows[0].checksum='0'.repeat(64);},rows=>{rows[0].finished_at=null;},
    rows=>{rows[0].rolled_back_at=new Date();},rows=>{rows[1].migration_name=rows[0].migration_name;}
  ]) {
    const rows=history();mutate(rows);
    assert.throws(()=>validatePrivateHistory(profile,rows),/PRIVATE_DATABASE_HISTORY_MISMATCH/);
  }
  assert.throws(()=>validatePrivateHistory({...profile,generalQualification:'PASSED'},history()));
});

test('production image and deployment choose only private workspace targets',()=>{
  const docker=readFileSync(new URL('../../apps/private-api/Dockerfile',import.meta.url),'utf8');
  const compose=readFileSync(new URL('../../deploy/aws-ec2/compose.yaml',import.meta.url),'utf8');
  const workspace=readFileSync(new URL('../../deploy/aws-ec2/container-workspace.yaml',import.meta.url),'utf8');
  assert.match(docker,/apps\/private-api/);assert.match(docker,/private-runtime-profile\.json/);
  assert.match(compose,/apps\/private-api\/Dockerfile/);assert.match(compose,/apps\/private-web\/Dockerfile/);
  assert.match(workspace,/"apps\/api"/);assert.doesNotMatch(workspace,/apps\/\*/);
});
