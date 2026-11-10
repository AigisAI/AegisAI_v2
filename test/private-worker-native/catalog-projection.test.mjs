import assert from 'node:assert/strict';
import {mkdir,writeFile,symlink,unlink,chmod,chown,rm,lstat} from 'node:fs/promises';
import test from 'node:test';
import {RuntimeCatalogService} from '../../apps/private-api/dist/runtime/runtime-catalog.service.js';

assert.equal(process.platform,'linux');
assert.equal(process.getuid(),0,'Isolated verification container only');
assert.match(new URL(process.env.PERSISTENCE_TEST_DATABASE_URL).pathname,/^\/aegisai_(verify|ci|test)$/);
const root='/run/aegisai-runtime';
const stamp='..2026_11_10_01_15_30.123456789';
function reader(mode){return new RuntimeCatalogService({getOptional:()=>mode});}
function status(){return {ready:true,busy:false,ai:'DISABLED',updatedAt:new Date().toISOString(),
  scannerSetVersion:'java-v1:'+'a'.repeat(16)+':'+'b'.repeat(64),policyVersion:'private-java-v1'};}

test('contained root-owned projected catalog preserves freshness and default symlink denial',async()=>{
  // Refuse an existing mount/directory before creating or cleaning anything.
  await assert.rejects(lstat(root),{code:'ENOENT'});
  let created=false;
  try {
    await mkdir(root,{mode:0o755});created=true;
    await mkdir(root+'/'+stamp,{mode:0o755});
    const leaf=root+'/'+stamp+'/current.json';
    await writeFile(leaf,JSON.stringify(status()),{mode:0o444});
    await symlink(stamp,root+'/..data');
    await symlink('..data/current.json',root+'/current.json');
    assert.equal((await reader('projected').read()).ready,true);
    assert.equal((await reader('regular').read()).ready,false);
    await unlink(root+'/..data');await symlink('/etc',root+'/..data');
    assert.equal((await reader('projected').read()).ready,false);
    await unlink(root+'/..data');await symlink(stamp,root+'/..data');
    await chmod(leaf,0o666);assert.equal((await reader('projected').read()).ready,false);
    await chmod(leaf,0o444);await chown(leaf,1000,1000);
    assert.equal((await reader('projected').read()).ready,false);
    await chown(leaf,0,0);await chmod(leaf,0o644);
    await writeFile(leaf,JSON.stringify({...status(),updatedAt:new Date(Date.now()-61000).toISOString()}));
    assert.equal((await reader('projected').read()).ready,false);
    // A new valid atomic-writer target is accepted without restarting the reader.
    const next='..2026_11_10_01_16_30.987654321';
    await mkdir(root+'/'+next,{mode:0o755});await writeFile(root+'/'+next+'/current.json',JSON.stringify(status()),{mode:0o444});
    await unlink(root+'/..data');await symlink(next,root+'/..data');
    assert.equal((await reader('projected').read()).ready,true);
  } finally {
    if(created) await rm(root,{recursive:true,force:true});
  }
});
