"""Root-only native reconciliation of a ready, exact private bootstrap."""
import json
import os
from pathlib import Path
import subprocess
import urllib.request

from bootstrap import BINARY, ROOT, PIN, configuration, digest, now, snapshot, wait_ready


def kube(*args, value=None):
    result = subprocess.run([str(BINARY), 'kubectl', '--kubeconfig', str(ROOT / 'kubeconfig.yaml'), *args],
        input=json.dumps(value) if value is not None else None, capture_output=True, text=True, check=True, timeout=90)
    return result.stdout


def resources():
    values = []
    for namespace in ('aegisai-private', 'aegisai-system', 'argocd'):
        values.append({'apiVersion':'v1','kind':'Namespace','metadata':{'name':namespace,'labels':{
            'aegisai.io/private-platform':'true','pod-security.kubernetes.io/enforce':'restricted',
            'pod-security.kubernetes.io/enforce-version':'v1.37',
            'pod-security.kubernetes.io/audit':'restricted','pod-security.kubernetes.io/warn':'restricted'}}})
        values.append({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
            'metadata':{'name':'default-deny','namespace':namespace},
            'spec':{'podSelector':{},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[]}})
        values.append({'apiVersion':'v1','kind':'ResourceQuota','metadata':{'name':'bounded-platform','namespace':namespace},
            'spec':{'hard':{'pods':'6','requests.cpu':'900m','requests.memory':'1536Mi',
                           'limits.memory':'1536Mi','services':'16','secrets':'8','configmaps':'24'}}})
    # Only the vendor DNS pod runs in kube-system at this phase. No metadata,
    # internet HTTP or application/scan sockets are reachable from it.
    values += [{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
        'metadata':{'name':'default-deny','namespace':'kube-system'},
        'spec':{'podSelector':{},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[]}},
        {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
        'metadata':{'name':'dns-only','namespace':'kube-system'},'spec':{
            'podSelector':{'matchLabels':{'k8s-app':'kube-dns'}},'policyTypes':['Ingress','Egress'],
            'ingress':[{'from':[{'ipBlock':{'cidr':'10.44.0.0/16'}},{'ipBlock':{'cidr':'172.31.55.151/32'}}],
                        'ports':[{'port':53,'protocol':'UDP'},{'port':53,'protocol':'TCP'}]}],
            'egress':[{'to':[{'ipBlock':{'cidr':'172.31.0.2/32'}}],
                       'ports':[{'port':53,'protocol':'UDP'},{'port':53,'protocol':'TCP'}]},
                      {'to':[{'ipBlock':{'cidr':'172.31.55.151/32'}},{'ipBlock':{'cidr':'10.45.0.1/32'}}],
                       'ports':[{'port':443,'protocol':'TCP'},{'port':6443,'protocol':'TCP'}]}]}}]
    return {'apiVersion':'v1','kind':'List','items':values}


def main():
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    assert digest(BINARY) == PIN['binary']['sha256']
    assert json.loads((ROOT/'config.yaml').read_text()) == configuration(), 'CONTROL_CONFIG_DRIFT'
    before = json.loads((ROOT/'before-bootstrap.json').read_text())['application']
    assert snapshot() == before
    node = wait_ready()
    kube('apply','-f','-',value=resources())
    for namespace in ('default','aegisai-private','aegisai-system','argocd'):
        kube('apply','-f','-',value={'apiVersion':'v1','kind':'ServiceAccount',
             'metadata':{'name':'default','namespace':namespace},'automountServiceAccountToken':False})
    kube('patch','deployment','coredns','-n','kube-system','--type=strategic','-p',json.dumps({
        'spec':{'template':{'spec':{'containers':[{'name':'coredns','resources':{
            'requests':{'cpu':'50m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'64Mi'}}}]}}}}))
    kube('rollout','status','deployment/coredns','-n','kube-system','--timeout=60s')
    assert snapshot() == before
    config = ROOT/'kubeconfig.yaml'
    assert config.stat().st_uid == 0 and config.stat().st_mode & 0o077 == 0
    assert 'aescbc' in (ROOT/'data/server/cred/encryption-config.json').read_text() or \
        'secretbox' in (ROOT/'data/server/cred/encryption-config.json').read_text()
    output = subprocess.check_output(['ss','-H','-lnt'],text=True)
    for line in output.splitlines():
        local = line.split()[3]
        if local.endswith((':6443',':10250')):
            assert local in ('172.31.55.151:6443','172.31.55.151:10250',
                             '127.0.0.1:6443','[::1]:6443'), 'NON_PRIVATE_CONTROL_LISTENER'
    with urllib.request.urlopen('http://127.0.0.1:8081/api/health',timeout=10) as response:
        assert response.status == 200
    report={'privateK3sBootstrap':'ready','version':PIN['version'],'binarySha256':digest(BINARY),
        'nodeReady':True,'nodeCount':1,'podCidr':node['spec']['podCIDR'],'privateListeners':True,
        'rootOnlyKubeconfig':True,'encryptedControlSecrets':True,'emptyAppNamespacesRestricted':True,
        'namespaceNetworkDefaultDeny':True,'dnsReady':True,'applicationUnchanged':True,
        'existingRelease':before['release'],'generalQualification':'NOT_QUALIFIED',
        'newComputeCreated':False,'appTrafficMoved':False,'rolloutOrHpaCompletion':False,'verifiedAt':now()}
    (ROOT/'bootstrap-result.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    main()
