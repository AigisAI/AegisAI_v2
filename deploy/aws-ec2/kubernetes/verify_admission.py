"""Bounded native admission/network probe; no SCM/DB access or customer scan."""
import copy
import json
import os
import subprocess
import time
from bootstrap import BINARY, ROOT, now, snapshot
from foundation import kube

PROBE = r"""
const assert=require('node:assert/strict'),net=require('node:net'),dns=require('node:dns').promises,fs=require('node:fs');
async function blocked(host,port){return await new Promise((resolve,reject)=>{const s=net.createConnection({host,port});s.setTimeout(1500);s.once('connect',()=>{s.destroy();reject(Error('FORBIDDEN_NETWORK_REACHABLE'));});s.once('timeout',()=>{s.destroy();resolve(true);});s.once('error',()=>{s.destroy();resolve(true);});});}
(async()=>{const a=await dns.lookup('kubernetes.default.svc.cluster.local');assert.equal(a.address,'10.45.0.1');await blocked('169.254.169.254',80);await blocked('172.31.55.151',6443);assert(!fs.existsSync('/var/run/secrets/kubernetes.io/serviceaccount/token'));console.log(JSON.stringify({dnsResolved:true,metadataDenied:true,controlApiDenied:true,serviceAccountTokenAbsent:true}));})().catch(()=>{console.error('BOUNDED_NETWORK_PROBE_FAILED');process.exit(1)});
"""


def pod(name,image):
    return {'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'aegisai-private',
            'labels':{'app.kubernetes.io/component':'admission-probe'}},'spec':{
        'restartPolicy':'Never','automountServiceAccountToken':False,'activeDeadlineSeconds':45,
        'securityContext':{'runAsNonRoot':True,'runAsUser':1000,'runAsGroup':1000,
                           'seccompProfile':{'type':'RuntimeDefault'}},
        'containers':[{'name':'probe','image':image,'imagePullPolicy':'Never',
            'command':['node','-e',PROBE],
            'resources':{'requests':{'cpu':'50m','memory':'64Mi'},'limits':{'cpu':'250m','memory':'192Mi'}},
            'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,
                               'capabilities':{'drop':['ALL']}}}]}}


def main():
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    ledger=json.loads((ROOT/'approved-app-images.json').read_text())
    image=ledger['images']['api']['reference']
    before=snapshot()
    stamp=str(int(time.time()))
    rejected=[]
    for name in ('unsigned-digest','mutable-tag','privileged','host-socket'):
        p=pod('admission-reject-'+stamp+'-'+name,image)
        if name=='unsigned-digest':p['spec']['containers'][0]['image']='docker.io/library/aegisai-api@sha256:'+'0'*64
        elif name=='mutable-tag':p['spec']['containers'][0]['image']='aegisai-api:ec2-runtime-20261109-135802'
        elif name=='privileged':
            # Keep the request schema-valid so real PodSecurity, rather than
            # incompatible-field validation, supplies the rejection evidence.
            p['spec']['containers'][0]['securityContext'].update(privileged=True,allowPrivilegeEscalation=True)
        else:
            p['spec']['volumes']=[{'name':'host-socket','hostPath':{'path':'/var/run/docker.sock','type':'Socket'}}]
            p['spec']['containers'][0]['volumeMounts']=[{'name':'host-socket','mountPath':'/host.sock'}]
        result=subprocess.run([str(BINARY),'kubectl','--kubeconfig',str(ROOT/'kubeconfig.yaml'),
            'create','-f','-'],input=json.dumps(p),capture_output=True,text=True,timeout=20)
        if result.returncode==0:
            kube('delete','pod',p['metadata']['name'],'-n','aegisai-private','--wait=true')
            raise AssertionError('INVALID_POD_ADMITTED: '+name)
        assert 'Forbidden' in result.stderr or 'denied request' in result.stderr, result.stderr[:300]
        rejected.append(name)
    name='admission-network-'+stamp
    p=pod(name,image)
    kube('create','-f','-',value=p)
    uid=json.loads(kube('get','pod',name,'-n','aegisai-private','-o','json'))['metadata']['uid']
    try:
        kube('wait','--for=jsonpath={.status.phase}=Succeeded','pod/'+name,'-n','aegisai-private','--timeout=60s')
        proof=json.loads(kube('logs',name,'-n','aegisai-private'))
        assert all(proof.values())
    finally:
        current=json.loads(kube('get','pod',name,'-n','aegisai-private','-o','json'))
        assert current['metadata']['uid']==uid
        kube('delete','pod',name,'-n','aegisai-private','--wait=true','--timeout=30s')
    assert snapshot()==before
    report={'nativeKubernetesAdmission':'passed','actualRejectedPodCreates':rejected,
        'approvedDigestProbeRan':True,'networkProbe':proof,'probePodRemoved':True,
        'applicationUnchanged':True,'newScanExecuted':False,'trafficMoved':False,
        'generalQualification':'NOT_QUALIFIED','verifiedAt':now()}
    (ROOT/'admission-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__ == '__main__':
    main()
