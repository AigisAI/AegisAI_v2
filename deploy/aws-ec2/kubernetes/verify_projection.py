"""Actual read-only ConfigMap propagation in a signed, restricted Node Pod."""
import json
import os
import time
from bootstrap import ROOT, now, snapshot
from foundation import kube
from verify_admission import pod

PROGRAM=r"""
const assert=require('node:assert/strict');const {RuntimeCatalogService}=require('/app/apps/api/dist/runtime/runtime-catalog.service.js');
const reader=new RuntimeCatalogService({getOptional:()=> 'projected'});
(async()=>{const first=await reader.read();assert.equal(first.ready,true);await new Promise(r=>setTimeout(r,20000));const second=await reader.read();assert.equal(second.ready,true);assert.notEqual(first.updatedAt,second.updatedAt);console.log(JSON.stringify({projectedCatalogReadable:true,actualRotationObserved:true,firstTimestamp:first.updatedAt,secondTimestamp:second.updatedAt,ai:second.ai}));})().catch(()=>{console.error('CATALOG_PROJECTION_NOT_ACCEPTED');process.exit(1)});
"""


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    image=json.loads((ROOT/'approved-app-images.json').read_text())['images']['api']['reference']
    before=snapshot();name='projection-probe-'+str(int(time.time()))
    value=pod(name,image)
    value['spec']['activeDeadlineSeconds']=70
    value['spec']['containers'][0]['command']=['node','-e',PROGRAM]
    value['spec']['volumes']=[{'name':'catalog','configMap':{'name':'runtime-catalog','defaultMode':0o444}}]
    value['spec']['containers'][0]['volumeMounts']=[{'name':'catalog','mountPath':'/run/aegisai-runtime','readOnly':True}]
    kube('create','-f','-',value=value)
    uid=json.loads(kube('get','pod',name,'-n','aegisai-private','-o','json'))['metadata']['uid']
    try:
        kube('wait','--for=jsonpath={.status.phase}=Succeeded','pod/'+name,'-n','aegisai-private','--timeout=80s')
        proof=json.loads(kube('logs',name,'-n','aegisai-private'))
        assert proof['projectedCatalogReadable'] and proof['actualRotationObserved']
    finally:
        assert json.loads(kube('get','pod',name,'-n','aegisai-private','-o','json'))['metadata']['uid']==uid
        kube('delete','pod',name,'-n','aegisai-private','--wait=true','--timeout=30s')
    assert snapshot()==before
    report={'nativeProjectedCatalog':'passed','proof':proof,'restrictedPod':True,'hostPathAdded':False,
        'applicationUnchanged':True,'newScanExecuted':False,'trafficMoved':False,'verifiedAt':now()}
    (ROOT/'catalog-projection-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
