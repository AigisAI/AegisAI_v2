"""Advertise only named healthy Docker backends to the restricted API Pods."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess

from foundation import kube

NETWORKS={'data':('aegisai-ec2-demo_default','172.18.0.0/16'),
          'observability':('aegisai-observability','172.29.240.0/24')}


def call(*args,value=None):
    return kube('--cache-dir=/run/aegisai-data-bridge-cache',*args,value=value)


def endpoint(container,kind,health=False):
    value=json.loads(subprocess.check_output(['docker','inspect',container],text=True,timeout=5))[0]
    network,cidr=NETWORKS[kind]
    address=value['NetworkSettings']['Networks'][network]['IPAddress']
    assert ipaddress.ip_address(address) in ipaddress.ip_network(cidr)
    ready=bool(value['State']['Running']) and (not health or value['State']['Health']['Status']=='healthy')
    return address,ready


def slice_for(name,address,port,ready):
    return {'apiVersion':'discovery.k8s.io/v1','kind':'EndpointSlice','metadata':{
        'name':'host-'+name,'namespace':'aegisai-private','labels':{
            'kubernetes.io/service-name':name,'endpointslice.kubernetes.io/managed-by':'aegisai-host-bridge'}},
        'addressType':'IPv4','ports':[{'name':'tcp','protocol':'TCP','port':port}],
        'endpoints':[{'addresses':[address],'conditions':{'ready':ready}}]}


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    routes=[]
    for name,container,network,port,health in (
        ('postgres','aegisai-ec2-demo-postgres-1','data',5432,True),
        ('redis','aegisai-ec2-demo-redis-1','data',6379,True),
        ('alloy','aegisai-observability-alloy-1','observability',4318,False)):
        address,ready=endpoint(container,network,health)
        call('apply','--server-side','--field-manager=aegisai-host-bridge','-f','-',
             value=slice_for(name,address,port,ready))
        if ready:routes.append({'to':[{'ipBlock':{'cidr':address+'/32'}}],
                                'ports':[{'protocol':'TCP','port':port}]})
    call('apply','--server-side','--field-manager=aegisai-host-bridge','-f','-',value={
        'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{
            'name':'api-host-backends','namespace':'aegisai-private'},'spec':{
            'podSelector':{'matchLabels':{'app.kubernetes.io/name':'aegisai-private','app.kubernetes.io/component':'api'}},
            'policyTypes':['Egress'],'egress':routes}})
    prometheus,ready=endpoint('aegisai-observability-prometheus-1','observability')
    assert ready
    # The observability bridge intentionally has no default route. Grant only
    # the private Pod CIDR; app NetworkPolicies still admit metrics port9465 only.
    inspection=json.loads(subprocess.check_output(['docker','inspect','aegisai-observability-prometheus-1'],text=True,timeout=5))[0]
    pid=inspection['State']['Pid'];assert isinstance(pid,int) and pid>1
    subprocess.run(['nsenter','-t',str(pid),'-n','ip','route','replace','10.44.0.0/16',
                    'via','172.29.240.1','dev','eth0'],check=True,timeout=5,capture_output=True)
    call('apply','--server-side','--field-manager=aegisai-host-bridge','-f','-',value={
        'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{
            'name':'api-private-metrics','namespace':'aegisai-private'},'spec':{
            'podSelector':{'matchLabels':{'app.kubernetes.io/name':'aegisai-private','app.kubernetes.io/component':'api'}},
            'policyTypes':['Ingress'],'ingress':[{'from':[{'ipBlock':{'cidr':prometheus+'/32'}}],
                                               'ports':[{'protocol':'TCP','port':9465}]}]}})
    # File discovery is prepared only; Prometheus keeps its original target until
    # the separately accepted traffic/telemetry migration. No private env is read.
    ledger=json.loads(Path('/opt/aegisai/kubernetes/approved-app-images.json').read_text())
    pods=json.loads(call('get','pods','-n','aegisai-private','-l',
        'app.kubernetes.io/name=aegisai-private,app.kubernetes.io/component=api','-o','json'))['items']
    assert len(pods)<=3
    targets=[]
    for pod in pods:
        if not any(c['type']=='Ready' and c['status']=='True' for c in pod['status'].get('conditions',[])):continue
        address=pod['status'].get('podIP')
        assert ipaddress.ip_address(address) in ipaddress.ip_network('10.44.0.0/16')
        image=pod['spec']['containers'][0]['image']
        assert image==ledger['images']['api']['reference']
        targets.append({'targets':[address+':9465'],'labels':{
            'runtime':'kubernetes','approved_source':ledger['approvedSource'][:12]}})
    directory=Path('/opt/aegisai/observability/discovery')
    directory.mkdir(mode=0o755,exist_ok=True)
    assert directory.resolve()==directory and directory.stat().st_uid==0 and not directory.stat().st_mode&0o022
    directory.chmod(0o755)  # public metric targets; readable by the non-root scraper
    path=directory/'private-api-targets.json';assert not path.is_symlink()
    pending=directory/'private-api-targets.pending';assert not pending.is_symlink()
    pending.write_text(json.dumps(targets));pending.chmod(0o644);pending.replace(path)


if __name__=='__main__':main()
