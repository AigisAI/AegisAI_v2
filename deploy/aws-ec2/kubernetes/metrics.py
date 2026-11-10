"""Small TLS-verified resource metrics using the installed, pinned airgap image."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess

from bootstrap import BINARY, ROOT, now
from foundation import kube

IMAGE='docker.io/rancher/mirrored-metrics-server@sha256:d9862115e7c7881280d3d75ca26bda8ffc0fc213315979575bf23ce9826205c0'
NS='aegisai-system'


def obj(kind,name,api='v1',namespace=NS,**fields):
    meta={'name':name}
    if namespace:meta['namespace']=namespace
    return {'apiVersion':api,'kind':kind,'metadata':meta,**fields}


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    ca=ROOT/'data/server/tls/server-ca.crt';key=ca.with_suffix('.key')
    assert ca.is_file() and key.is_file() and key.stat().st_uid==0
    images=subprocess.check_output([str(BINARY),'ctr','-n','k8s.io','images','ls','-q'],text=True)
    assert IMAGE in images.splitlines()
    if not args.apply:print(json.dumps({'resourceMetricsPlan':'ready','maximumMemoryMiB':64,'tlsVerification':True}));return
    directory=ROOT/'resource-metrics';directory.mkdir(mode=0o700,exist_ok=True)
    if not (directory/'tls.crt').exists():
        subprocess.run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-noenc',
            '-keyout',str(directory/'tls.key'),'-out',str(directory/'request.csr'),'-subj','/CN=metrics-server.aegisai-system.svc'],
            check=True,capture_output=True,timeout=15)
        extension=directory/'extensions';extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:metrics-server.aegisai-system.svc,DNS:metrics-server.aegisai-system.svc.cluster.local,IP:10.45.0.50\n')
        subprocess.run(['openssl','x509','-req','-in',str(directory/'request.csr'),'-CA',str(ca),'-CAkey',str(key),
            '-set_serial','0x'+secrets.token_hex(16),'-days','180','-extfile',str(extension),'-out',str(directory/'tls.crt')],
            check=True,capture_output=True,timeout=15)
    ca_pem=ca.read_text()
    docs=[obj('ServiceAccount','metrics-server'),
          obj('ConfigMap','metrics-server-ca',data={'ca.crt':ca_pem}),
          obj('Secret','metrics-server-serving',type='kubernetes.io/tls',stringData={
              'tls.crt':(directory/'tls.crt').read_text(),'tls.key':(directory/'tls.key').read_text()})]
    rbac='rbac.authorization.k8s.io/v1'
    subject={'kind':'ServiceAccount','name':'metrics-server','namespace':NS}
    docs += [obj('ClusterRole','aegisai:metrics-reader',api=rbac,namespace=None,rules=[
        {'apiGroups':[''],'resources':['nodes/metrics'],'verbs':['get']},
        {'apiGroups':[''],'resources':['nodes','pods'],'verbs':['get','list','watch']}])]
    for name,role in (('aegisai:metrics-reader','aegisai:metrics-reader'),('aegisai:metrics-auth-delegator','system:auth-delegator')):
        docs.append(obj('ClusterRoleBinding',name,api=rbac,namespace=None,
            roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':role},subjects=[subject]))
    docs.append(obj('RoleBinding','aegisai-metrics-auth-reader',api=rbac,namespace='kube-system',
        roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'extension-apiserver-authentication-reader'},subjects=[subject]))
    pod={'serviceAccountName':'metrics-server','automountServiceAccountToken':True,'enableServiceLinks':False,
        'securityContext':{'runAsNonRoot':True,'runAsUser':1000,'runAsGroup':1000,'fsGroup':1000,'seccompProfile':{'type':'RuntimeDefault'}},
        'containers':[{'name':'metrics-server','image':IMAGE,'imagePullPolicy':'Never',
            'args':['--secure-port=10250','--tls-cert-file=/etc/serving/tls.crt','--tls-private-key-file=/etc/serving/tls.key',
                    '--kubelet-preferred-address-types=InternalIP','--kubelet-use-node-status-port','--metric-resolution=15s',
                    '--kubelet-certificate-authority=/etc/kubelet-ca/ca.crt'],
            'ports':[{'name':'https','containerPort':10250}],
            'securityContext':{'readOnlyRootFilesystem':True,'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']}},
            'resources':{'requests':{'cpu':'25m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'64Mi'}},
            'startupProbe':{'httpGet':{'path':'/livez','port':'https','scheme':'HTTPS'},'periodSeconds':3,'failureThreshold':20},
            'readinessProbe':{'httpGet':{'path':'/readyz','port':'https','scheme':'HTTPS'},'periodSeconds':5},
            'livenessProbe':{'httpGet':{'path':'/livez','port':'https','scheme':'HTTPS'},'periodSeconds':10},
            'volumeMounts':[{'name':'tmp','mountPath':'/tmp'},{'name':'serving','mountPath':'/etc/serving','readOnly':True},
                            {'name':'kubelet-ca','mountPath':'/etc/kubelet-ca','readOnly':True}]}],
        'volumes':[{'name':'tmp','emptyDir':{'medium':'Memory','sizeLimit':'8Mi'}},
                   {'name':'serving','secret':{'secretName':'metrics-server-serving','defaultMode':0o440}},
                   {'name':'kubelet-ca','configMap':{'name':'metrics-server-ca'}}]}
    docs += [obj('Deployment','metrics-server',api='apps/v1',spec={'replicas':1,'revisionHistoryLimit':1,
        'strategy':{'type':'Recreate'},'selector':{'matchLabels':{'app.kubernetes.io/name':'private-metrics-server'}},
        'template':{'metadata':{'labels':{'app.kubernetes.io/name':'private-metrics-server'}},'spec':pod}}),
        obj('Service','metrics-server',spec={'type':'ClusterIP','clusterIP':'10.45.0.50',
            'selector':{'app.kubernetes.io/name':'private-metrics-server'},'ports':[{'port':443,'targetPort':'https'}]}),
        obj('APIService','v1beta1.metrics.k8s.io',api='apiregistration.k8s.io/v1',namespace=None,spec={
            'service':{'name':'metrics-server','namespace':NS},'group':'metrics.k8s.io','version':'v1beta1',
            'caBundle':base64.b64encode(ca_pem.encode()).decode(),'groupPriorityMinimum':100,'versionPriority':100})]
    docs.append(obj('NetworkPolicy','private-metrics-server',api='networking.k8s.io/v1',spec={
        'podSelector':{'matchLabels':{'app.kubernetes.io/name':'private-metrics-server'}},'policyTypes':['Ingress','Egress'],
        'ingress':[{'from':[{'ipBlock':{'cidr':'172.31.55.151/32'}},{'ipBlock':{'cidr':'10.44.0.1/32'}}],
                    'ports':[{'protocol':'TCP','port':10250}]}],
        'egress':[{'to':[{'ipBlock':{'cidr':'172.31.55.151/32'}},{'ipBlock':{'cidr':'10.45.0.1/32'}}],
                   'ports':[{'protocol':'TCP','port':443},{'protocol':'TCP','port':6443},{'protocol':'TCP','port':10250}]}]}))
    for value in docs:kube('apply','--server-side','--field-manager=aegisai-resource-metrics','-f','-',value=value)
    report={'resourceMetrics':'installed','image':IMAGE,'tlsVerifiedBothDirections':True,'maximumMemoryMiB':64,
            'newAwsPermissions':False,'actualMetricsVerified':False,'installedAt':now()}
    (directory/'installation-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
