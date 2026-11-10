"""Adopt the existing chart without rebuilding, replacing or migrating the app."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

from bootstrap import BINARY, ROOT, now
from foundation import kube
from gitops import ACCOUNT, REPO, object

REVISION='0cb7fa420e9856adb82fc8733cfa183ef70a1af1'


def pod_ids():
    return {p['metadata']['name']:p['metadata']['uid'] for p in json.loads(kube('get','pods','-n','aegisai-private','-o','json'))['items']}


def boundaries():
    binary=[str(BINARY),'kubectl','--kubeconfig',str(ROOT/'kubeconfig.yaml')]
    rows=[]
    for verb,resource,namespace,allowed in (
        ('patch','deployments.apps/api','aegisai-private',True),
        ('update','configmaps/web-nginx','aegisai-private',True),
        ('update','configmaps/api-public','aegisai-private',False),
        ('update','configmaps/runtime-catalog','aegisai-private',False),
        ('get','secrets','aegisai-private',False),
        ('update','endpointslices.discovery.k8s.io','aegisai-private',False),
        ('create','rolebindings.rbac.authorization.k8s.io','aegisai-private',False),
        ('get','nodes','argocd',False)):
        result=subprocess.run(binary+['auth','can-i',verb,resource,'-n',namespace,
            '--as=system:serviceaccount:argocd:'+ACCOUNT],capture_output=True,text=True,timeout=15)
        answer=result.stdout.strip();assert answer in ('yes','no')
        assert (answer=='yes')==allowed,(verb,resource,answer)
        rows.append({'verb':verb,'resource':resource,'namespace':namespace,'allowed':allowed})
    return rows


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    native_boundaries=boundaries();before=pod_ids();assert len(before)==2
    state=json.loads(Path('/opt/aegisai/operator/application-traffic.json').read_text())
    assert state['backend']=='kubernetes'
    values=json.loads((ROOT/'standby/values.json').read_text())
    assert state['approvedSource']==values['revision']
    app=object('Application','aegisai-private',api='argoproj.io/v1alpha1',spec={
        'project':'aegisai-private','destination':{'server':'https://kubernetes.default.svc','namespace':'aegisai-private'},
        'source':{'repoURL':REPO,'targetRevision':REVISION,'path':'deploy/aws-ec2/kubernetes/chart',
                  'helm':{'releaseName':'aegisai-private','valuesObject':values}},
        'syncPolicy':{'automated':{'enabled':True,'selfHeal':True,'prune':False,'allowEmpty':False},
                      'syncOptions':['ServerSideApply=true','RespectIgnoreDifferences=true']}})
    if not args.apply:
        print(json.dumps({'gitopsAdoptionPlan':'ready','nativeNamespaceBoundaries':'passed','chartRevision':REVISION}));return
    assert not kube('get','application','aegisai-private','-n','argocd','--ignore-not-found','-o','name').strip()
    (ROOT/'gitops/pre-adoption-pods.json').write_text(json.dumps(before))
    kube('create','-f','-',value=app)
    deadline=time.monotonic()+150
    while time.monotonic()<deadline:
        current=json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))
        status=current.get('status',{})
        if status.get('sync',{}).get('status')=='Synced' and status.get('health',{}).get('status')=='Healthy':break
        time.sleep(3)
    else:
        report={'gitopsAdoption':'pending','conditions':status.get('conditions',[]),'operation':status.get('operationState',{}).get('message'),'checkedAt':now()}
        (ROOT/'gitops/adoption-pending.json').write_text(json.dumps(report,indent=2));print(json.dumps(report));return
    assert pod_ids()==before,'ADOPTION_CHANGED_APPLICATION_PODS'
    report={'gitopsAdoption':'passed','chartRevision':REVISION,'applicationSource':values['revision'],
            'sync':'Synced','health':'Healthy','existingPodsUnchanged':True,'nativeNamespaceBoundaries':native_boundaries,
            'awsPermissionsChanged':False,'verifiedAt':now()}
    (ROOT/'gitops/adoption-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
