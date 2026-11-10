"""Root chooses immutable desired spec; controller can update operation/status."""
import json
import os
import subprocess

from bootstrap import BINARY, ROOT, now
from foundation import kube

CONTROLLER='system:serviceaccount:argocd:argocd-application-controller'


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    policy={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicy',
        'metadata':{'name':'aegisai-root-pinned-gitops'},'spec':{'failurePolicy':'Fail',
        'matchConstraints':{'resourceRules':[{'apiGroups':['argoproj.io'],'apiVersions':['v1alpha1'],
            'operations':['UPDATE'],'resources':['applications']}]},
        'matchConditions':[{'name':'private-app','expression':"object.metadata.name == 'aegisai-private' && object.metadata.namespace == 'argocd'"}],
        'validations':[{'expression':"request.userInfo.username != '"+CONTROLLER+"' || object.spec == oldObject.spec",
            'message':'Only the operator may change the pinned private Git/image desired spec'}]}}
    binding={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicyBinding',
        'metadata':{'name':'aegisai-root-pinned-gitops'},'spec':{'policyName':'aegisai-root-pinned-gitops','validationActions':['Deny','Audit']}}
    for value in (policy,binding):kube('apply','--server-side','--field-manager=aegisai-release-guard','-f','-',value=value)
    before=json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))['spec']
    command=[str(BINARY),'kubectl','--kubeconfig',str(ROOT/'kubeconfig.yaml'),'--as='+CONTROLLER,
        'patch','application','aegisai-private','-n','argocd','--type=merge','--dry-run=server','-p',
        json.dumps({'spec':{'source':{'targetRevision':'operator-guard-negative-probe'}}})]
    result=subprocess.run(command,capture_output=True,text=True,timeout=20)
    assert result.returncode!=0 and 'Only the operator may change' in result.stderr
    assert json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))['spec']==before
    report={'pinnedGitSpecGuard':'enforced','nativeUnauthorizedSpecMutationRejected':True,
            'applicationSpecUnchanged':True,'verifiedAt':now()}
    (ROOT/'gitops/release-guard-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
