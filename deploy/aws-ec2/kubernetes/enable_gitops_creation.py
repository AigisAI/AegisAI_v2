"""Permit Git recovery only for named chart objects, never operator runtime data."""
import json
import os
import subprocess
import time

from bootstrap import BINARY, ROOT, now
from foundation import kube
from release_guard import CONTROLLER

NAMES={'ConfigMap':['web-nginx','aegisai-release'],'Service':['api','web','postgres','redis','alloy'],
       'ServiceAccount':['aegisai-api','aegisai-web'],'Deployment':['api','web'],
       'NetworkPolicy':['application-static-routes','api-static-routes','web-static-routes']}


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    expression="request.userInfo.username != '"+CONTROLLER+"' || "+json.dumps(NAMES)+"[request.kind.kind].exists(n, n == object.metadata.name)"
    policy={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicy','metadata':{'name':'aegisai-named-gitops-creation'},
        'spec':{'failurePolicy':'Fail','matchConstraints':{'resourceRules':[{'apiGroups':['','apps','networking.k8s.io'],
            'apiVersions':['v1'],'operations':['CREATE'],'resources':['configmaps','services','serviceaccounts','deployments','networkpolicies']}]},
            'matchConditions':[{'name':'private-namespace','expression':"object.metadata.namespace == 'aegisai-private'"}],
            'validations':[{'expression':expression,'message':'GitOps may recreate only named chart resources, never operator data'}]}}
    binding={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicyBinding','metadata':{'name':'aegisai-named-gitops-creation'},
        'spec':{'policyName':'aegisai-named-gitops-creation','validationActions':['Deny','Audit']}}
    for value in (policy,binding):kube('apply','--server-side','--field-manager=aegisai-release-guard','-f','-',value=value)
    binary=[str(BINARY),'kubectl','--kubeconfig',str(ROOT/'kubeconfig.yaml')]
    negative={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'operator-data-create-negative','namespace':'aegisai-private'},'data':{'probe':'no-write'}}
    # Root's impersonation test exercises admission before granting CREATE. The
    # temporary request group bypasses RBAC only, not admission, and creates no token.
    for _ in range(20):
        rejected=subprocess.run(binary+['--as='+CONTROLLER,'--as-group=system:masters','create','--dry-run=server','-f','-'],
            input=json.dumps(negative),capture_output=True,text=True,timeout=15)
        if rejected.returncode!=0 and 'GitOps may recreate only named' in rejected.stderr:break
        time.sleep(0.5)
    else:raise AssertionError('NAMED_CREATE_BOUNDARY_NOT_ACTIVE')
    role=json.loads(kube('get','role','private-gitops','-n','aegisai-private','-o','json'))
    rules=role['rules']
    for rule in rules:
        if rule.get('resourceNames')==['web-nginx']:rule['resourceNames']=['web-nginx','aegisai-release']
    for group,resources in (('', ['configmaps','services','serviceaccounts']),('apps',['deployments']),('networking.k8s.io',['networkpolicies'])):
        create={'apiGroups':[group],'resources':resources,'verbs':['create']}
        if create not in rules:rules.append(create)
    kube('patch','role','private-gitops','-n','aegisai-private','--type=merge','-p',json.dumps({'rules':rules}))
    rejected=subprocess.run(binary+['--as='+CONTROLLER,'create','--dry-run=server','-f','-'],input=json.dumps(negative),capture_output=True,text=True,timeout=15)
    assert rejected.returncode!=0 and 'GitOps may recreate only named' in rejected.stderr
    positive={**negative,'metadata':{'name':'aegisai-release','namespace':'aegisai-private'}}
    # This marker is intentionally not created by the verifier; GitOps creates it.
    result=subprocess.run(binary+['--as='+CONTROLLER,'create','--dry-run=server','-f','-'],
        input=json.dumps(positive),capture_output=True,text=True,timeout=15)
    assert result.returncode==0 or 'configmaps "aegisai-release" already exists' in result.stderr
    report={'namedGitOpsRecovery':'enabled','operatorDataCreationDenied':True,'knownMarkerCreationAllowed':True,'verifiedAt':now()}
    (ROOT/'gitops/named-creation-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
