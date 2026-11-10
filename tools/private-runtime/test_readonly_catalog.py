"""Actual non-root read-only/RW mount cases, isolated hosted-CI image only."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile

assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
PROGRAM=r"""
const assert=require('node:assert/strict'),fs=require('node:fs');
const {RuntimeCatalogService}=require('/app/apps/private-api/dist/runtime/runtime-catalog.service.js');
(async()=>{const reader=new RuntimeCatalogService({getOptional:()=> 'projected'});assert.equal((await reader.read()).ready,process.env.EXPECT_READY==='true');assert.equal((await new RuntimeCatalogService({getOptional:()=> 'regular'}).read()).ready,false);if(process.env.EXPECT_WRITABLE==='true'){fs.writeFileSync('/run/aegisai-runtime/writable-proof','x');}else{assert.throws(()=>fs.writeFileSync('/run/aegisai-runtime/writable-proof','x'),e=>e.code==='EROFS');}})().catch(()=>{console.error('READONLY_CATALOG_BOUNDARY_FAILED');process.exit(1)});
"""


with tempfile.TemporaryDirectory(prefix='aegisai-catalog-ro-') as temporary:
    root=Path(temporary);root.chmod(0o777)
    stamp='..2026_11_10_01_15_30.123456789';(root/stamp).mkdir(mode=0o755)
    leaf=root/stamp/'current.json'
    value={'ready':True,'busy':False,'ai':'DISABLED','updatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'scannerSetVersion':'java-v1:'+'a'*16+':'+'b'*64,'policyVersion':'private-java-v1'}
    leaf.write_text(json.dumps(value));leaf.chmod(0o444)
    (root/'..data').symlink_to(stamp);(root/'current.json').symlink_to('..data/current.json')
    def check(name,expected,readonly=True):
        subprocess.run(['docker','run','--rm','--user','1000:1000','--network','none','--read-only',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','192m','--cpus','1','--pids-limit','64',
            '-e','EXPECT_READY='+str(expected).lower(),'-e','EXPECT_WRITABLE='+str(not readonly).lower(),
            '-v',str(root)+':/run/aegisai-runtime:'+('ro' if readonly else 'rw'),
            'aegisai-private-verify:ci','node','-e',PROGRAM],check=True,timeout=30)
        print(name+': passed')
    check('actual-nonroot-readonly-projection',True)
    check('actual-writable-projection-denied',False,False)
    leaf.chmod(0o666);check('writable-leaf-denied',False);leaf.chmod(0o444)
    os.chown(leaf,1000,1000);check('nonroot-authored-leaf-denied',False);os.chown(leaf,0,0)
    (root/'..data').unlink();(root/'..data').symlink_to('/etc');check('escape-pointer-denied',False)
    (root/'..data').unlink();(root/'..data').symlink_to(stamp)
    leaf.chmod(0o644);value['updatedAt']=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(seconds=61)).isoformat()
    leaf.write_text(json.dumps(value));leaf.chmod(0o444);check('stale-projection-denied',False)
