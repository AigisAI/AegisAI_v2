"""Pinned core-only Argo installation. Root keeps promotion/dynamic-field authority."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import urllib.request

from bootstrap import BINARY, ROOT, now
from foundation import kube

VENDOR_URL='https://raw.githubusercontent.com/argoproj/argo-cd/v3.6.1/manifests/core-install.yaml'
VENDOR_SHA='0b38189d6e1fd76ef5c3db10355026c48a02020d82bf21a1a1b5ab16dffe4f3c'
ARGO='quay.io/argoproj/argocd@sha256:967306562700bc6f4bab7c247caf69892d77624b019ca510e86b4b00fc9c5584'
REDIS='public.ecr.aws/docker/library/redis@sha256:de4d18872bf67ad0bd62224a712263975ca1d53b9b1d0d5d076082e7fa887890'
ACCOUNT='argocd-application-controller'
REPO='https://github.com/AigisAI/AegisAI_v2.git'


def parse_vendor_output(text):
    assert len(text)<16*1024**2
    decoder=json.JSONDecoder();values=[];text=text.lstrip()
    # kubectl create emits consecutive JSON documents for multi-document YAML.
    while text:
        value,end=decoder.raw_decode(text)
        values.extend(value['items'] if value.get('kind')=='List' else [value])
        text=text[end:].lstrip()
    assert values and all(isinstance(v,dict) and 'kind' in v for v in values)
    return values


def object(kind,name,spec=None,namespace='argocd',api='v1',**extra):
    value={'apiVersion':api,'kind':kind,'metadata':{'name':name,'namespace':namespace},**extra}
    if spec is not None:value['spec']=spec
    return value


def rule(group,resources,verbs,names=None):
    value={'apiGroups':[group],'resources':resources,'verbs':verbs}
    if names:value['resourceNames']=names
    return value


def resources(vendor):
    docs=[]
    for item in vendor:
        kind=item['kind'];name=item['metadata']['name']
        if kind=='CustomResourceDefinition' and name in ('applications.argoproj.io','appprojects.argoproj.io'):
            docs.append(copy.deepcopy(item));continue
        if kind not in ('Deployment','StatefulSet','Service','ConfigMap','ServiceAccount'):continue
        if 'applicationset' in name:continue
        if kind in ('Deployment','StatefulSet','ServiceAccount','Service') and name not in (ACCOUNT,'argocd-repo-server','argocd-redis','argocd-metrics'):continue
        value=copy.deepcopy(item);value['metadata']['namespace']='argocd'
        if kind=='ServiceAccount':value['automountServiceAccountToken']=name==ACCOUNT
        if kind in ('Deployment','StatefulSet'):
            value['spec']['replicas']=1
            pod=value['spec']['template']['spec'];pod['automountServiceAccountToken']=name==ACCOUNT
            pod['enableServiceLinks']=False;pod['terminationGracePeriodSeconds']=20
            pod['securityContext']={'runAsNonRoot':True,'runAsUser':999,'runAsGroup':999,'fsGroup':999,'seccompProfile':{'type':'RuntimeDefault'}}
            # No dynamic Redis secret creator or custom plugin executable is
            # needed. Root creates the private cache secret without API tokens.
            if name in ('argocd-redis','argocd-repo-server'):pod.pop('initContainers',None)
            for volume in pod.get('volumes',[]):
                if 'emptyDir' in volume:volume['emptyDir']={'sizeLimit':'128Mi'}
            for container in pod.get('initContainers',[])+pod['containers']:
                container['image']=REDIS if container['name']=='redis' else ARGO
                container['imagePullPolicy']='IfNotPresent'
                container['securityContext']={'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}
                maximum='64Mi' if name=='argocd-redis' else '256Mi' if name==ACCOUNT else '288Mi'
                container['resources']={'requests':{'cpu':'25m' if name=='argocd-redis' else '100m','memory':'16Mi' if name=='argocd-redis' else '128Mi'},
                                        'limits':{'cpu':'100m' if name=='argocd-redis' else '500m','memory':maximum,'ephemeral-storage':'512Mi'}}
                container.setdefault('env',[]).append({'name':'GOMEMLIMIT','value':'200MiB'})
            if name==ACCOUNT:pod['containers'][0]['args']+=['--status-processors','2','--operation-processors','1','--kubectl-parallelism-limit','1']
        if name=='argocd-cm':value['data']={'timeout.reconciliation':'60s','timeout.reconciliation.jitter':'10s',
             'resource.trackingMethod':'annotation','application.resourceTrackingMethod':'annotation',
             'resource.inclusions':'- apiGroups: ["", "apps", "networking.k8s.io"]\n  kinds: [ConfigMap, Service, ServiceAccount, Pod, Deployment, ReplicaSet, NetworkPolicy]\n  clusters: ["*"]\n'}
        if name=='argocd-cmd-params-cm':value['data']={'reposerver.parallelism.limit':'1','reposerver.log.level':'warn','controller.log.level':'warn','controller.resource.health.persist':'false'}
        docs.append(value)
    assert sum(d['kind'] in ('Deployment','StatefulSet') for d in docs)==3
    docs.append(object('Role','private-core',api='rbac.authorization.k8s.io/v1',rules=[
        rule('', ['configmaps','secrets'],['get','list','watch']),
        rule('', ['events'],['create','patch']),
        rule('argoproj.io',['applications','applications/status','applications/finalizers'],['get','list','watch','update','patch']),
        rule('argoproj.io',['appprojects'],['get','list','watch'])]))
    read=['get','list','watch'];write=['get','update','patch','delete']
    app_rules=[rule('', ['configmaps','services','serviceaccounts','pods','events'],read),
               rule('apps',['deployments','replicasets'],read),rule('networking.k8s.io',['networkpolicies'],read),
               rule('', ['configmaps'],write,['web-nginx']),rule('', ['services'],write,['api','web','postgres','redis','alloy']),
               rule('', ['serviceaccounts'],write,['aegisai-api','aegisai-web']),
               rule('apps',['deployments'],write,['api','web']),
               rule('networking.k8s.io',['networkpolicies'],write,['application-static-routes','api-static-routes','web-static-routes'])]
    # Adopt existing resources first; creation and pruning are deliberately not
    # delegated until an explicit resource-name admission boundary is installed.
    docs.append(object('Role','private-gitops',namespace='aegisai-private',api='rbac.authorization.k8s.io/v1',rules=app_rules))
    for namespace,name in (('argocd','private-core'),('aegisai-private','private-gitops')):
        docs.append(object('RoleBinding',name,namespace=namespace,api='rbac.authorization.k8s.io/v1',
            roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name},
            subjects=[{'kind':'ServiceAccount','name':ACCOUNT,'namespace':'argocd'}]))
    docs.append(object('Secret','private-in-cluster',type='Opaque',stringData={'name':'in-cluster','server':'https://kubernetes.default.svc',
        'namespaces':'aegisai-private','clusterResources':'false','config':'{}'}))
    docs[-1]['metadata']['labels']={'argocd.argoproj.io/secret-type':'cluster'}
    docs.append(object('AppProject','aegisai-private',api='argoproj.io/v1alpha1',spec={
        'sourceRepos':[REPO],'destinations':[{'server':'https://kubernetes.default.svc','namespace':'aegisai-private'}],
        'clusterResourceWhitelist':[],'namespaceResourceWhitelist':[{'group':group,'kind':kind} for group,kind in
            (('','ConfigMap'),('','Service'),('','ServiceAccount'),('apps','Deployment'),('networking.k8s.io','NetworkPolicy'))]}))
    # Core caches use only controller->repo/redis, repo->redis, and repo->publicHTTPS.
    def peer(name):return {'podSelector':{'matchLabels':{'app.kubernetes.io/name':name}}}
    for name in (ACCOUNT,'argocd-repo-server','argocd-redis'):
        ingress=[];egress=[]
        if name=='argocd-repo-server':ingress=[{'from':[peer(ACCOUNT)],'ports':[{'protocol':'TCP','port':8081}]}]
        if name=='argocd-redis':ingress=[{'from':[peer(ACCOUNT),peer('argocd-repo-server')],'ports':[{'protocol':'TCP','port':6379}]}]
        else:
            egress+=[{'to':[peer('argocd-redis')],'ports':[{'protocol':'TCP','port':6379}]},
                     {'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'kube-system'}},'podSelector':{'matchLabels':{'k8s-app':'kube-dns'}}}],
                      'ports':[{'protocol':'UDP','port':53},{'protocol':'TCP','port':53}]}]
        if name==ACCOUNT:
            egress.extend([{'to':[peer('argocd-repo-server')],'ports':[{'protocol':'TCP','port':8081}]},
                {'to':[{'ipBlock':{'cidr':'10.45.0.1/32'}},{'ipBlock':{'cidr':'172.31.55.151/32'}}],
                 'ports':[{'protocol':'TCP','port':443},{'protocol':'TCP','port':6443}]}])
        if name=='argocd-repo-server':egress.append({'to':[{'ipBlock':{'cidr':'0.0.0.0/0','except':['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4']}}],'ports':[{'protocol':'TCP','port':443}]})
        docs.append(object('NetworkPolicy','private-'+name,api='networking.k8s.io/v1',spec={'podSelector':{'matchLabels':{'app.kubernetes.io/name':name}},'policyTypes':['Ingress','Egress'],'ingress':ingress,'egress':egress}))
    return docs


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    directory=ROOT/'gitops';directory.mkdir(mode=0o700,exist_ok=True)
    with urllib.request.urlopen(VENDOR_URL,timeout=30) as response:content=response.read(8*1024**2+1)
    assert len(content)<8*1024**2 and hashlib.sha256(content).hexdigest()==VENDOR_SHA
    path=directory/'vendor-core-install.yaml';path.write_bytes(content)
    vendor=parse_vendor_output(kube('create','--dry-run=client','--validate=false','-f',str(path),'-o','json'))
    docs=resources(vendor)
    if not args.apply:print(json.dumps({'gitopsCorePlan':'ready','resources':len(docs),'clusterAdminGranted':False}));return
    for image in (ARGO,REDIS):subprocess.run([str(BINARY),'ctr','-n','k8s.io','images','pull',image],check=True,timeout=240,stdout=subprocess.DEVNULL)
    for item in docs:
        if item['kind']=='CustomResourceDefinition':kube('apply','--server-side','--field-manager=aegisai-gitops-bootstrap','-f','-',value=item)
    kube('wait','--for=condition=Established','crd/applications.argoproj.io','crd/appprojects.argoproj.io','--timeout=45s')
    for name in ('argocd-secret','argocd-redis'):
        item=object('Secret',name,type='Opaque',stringData={'auth':secrets.token_urlsafe(32)} if name=='argocd-redis' else {})
        if not json.loads(kube('get','secret',name,'-n','argocd','--ignore-not-found','-o','json') or '{}'):
            kube('create','-f','-',value=item)
    for item in docs:
        if item['kind']!='CustomResourceDefinition':kube('apply','--server-side','--field-manager=aegisai-gitops-bootstrap','-f','-',value=item)
    report={'gitopsCore':'installed','version':'3.6.1','clusterAdminGranted':False,'maximumMemoryMiB':608,
            'newAwsPermissions':False,'applicationAdopted':False,'installedAt':now()}
    (directory/'installation-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
