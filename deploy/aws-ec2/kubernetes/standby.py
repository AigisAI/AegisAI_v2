"""Install only signed restricted standby; original ingress is never changed."""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from bootstrap import ROOT, SOURCE, digest, now, snapshot
from foundation import kube

PUBLIC={'NODE_ENV','PORT','APP_URL','FRONTEND_URL','COOKIE_SECURE','ANALYSIS_CLIENT_MODE','USE_INTERNAL_AI',
        'AWS_REGION','AWS_AUTH_SECRET_ARN','AWS_SCM_SECRET_ARN','EVIDENCE_BUCKET','EVIDENCE_KMS_KEY_ARN',
        'AWS_EC2_METADATA_V1_DISABLED','ALLOWED_GITHUB_USER_IDS','GITHUB_LOGIN_KIND'}


def validate_managed_settings(values):
    for key in ('APP_URL','FRONTEND_URL'):
        assert values[key] in ('https://aegisai-aws.tailaca7d2.ts.net','https://aegisai-aws.tailaca7d2.ts.net/')
    assert values['USE_INTERNAL_AI']=='false' and values['COOKIE_SECURE']=='true'
    assert values['ALLOWED_GITHUB_USER_IDS']=='161540124' and values['GITHUB_LOGIN_KIND']=='github-app'


def public_environment(path):
    result={}
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        key,separator,raw=line.partition('=');assert separator
        assert not any(secret in key for secret in ('PASSWORD','SESSION_SECRET','CSRF_SECRET','TOKEN_ENCRYPTION_KEY','PRIVATE_KEY_PEM','CLIENT_SECRET'))
        if key not in PUBLIC:continue
        parts=shlex.split(raw);assert len(parts)==1
        result[key]=parts[0]
    assert result['NODE_ENV']=='production' and result['PORT']=='3000' and result['AWS_REGION']=='ap-northeast-2'
    for scope in ('AUTH','SCM'):
        assert re.fullmatch(r'arn:aws:secretsmanager:ap-northeast-2:024139495514:secret:aegisai/private-runtime/'+scope.lower()+r'-[A-Za-z0-9]+',result['AWS_'+scope+'_SECRET_ARN'])
    for key in ('APP_URL','FRONTEND_URL'):
        if key in result:assert result[key] in ('https://aegisai-aws.tailaca7d2.ts.net','https://aegisai-aws.tailaca7d2.ts.net/')
    assert result['EVIDENCE_BUCKET']=='aegisai-private-024139495514-apne2'
    assert re.fullmatch(r'arn:aws:kms:ap-northeast-2:024139495514:key/[a-f0-9-]{36}',result['EVIDENCE_KMS_KEY_ARN'])
    for key,expected in (('USE_INTERNAL_AI','false'),('COOKIE_SECURE','true'),
                         ('AWS_EC2_METADATA_V1_DISABLED','true'),('ALLOWED_GITHUB_USER_IDS','161540124'),
                         ('GITHUB_LOGIN_KIND','github-app')):
        if key in result:assert result[key]==expected
    result.update(RUNTIME_CATALOG_MODE='projected',RUNTIME_TELEMETRY_ENABLED='true',NODE_OPTIONS='--max-old-space-size=160')
    return result


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    ledger=json.loads((ROOT/'approved-app-images.json').read_text())
    projection=json.loads((ROOT/'catalog-projection-result.json').read_text())
    assert projection['nativeProjectedCatalog']=='passed'
    refs=public_environment(Path('/opt/aegisai/shared/runtime-public.env'))
    # Existing managed values stay in captured memory, never in a ConfigMap or
    # installer output. Validate the same bundles the API will load at startup.
    trusted=Path('/opt/aegisai/operator/supply-chain/current/deploy/aws-ec2/managed_runtime.py')
    assert trusted.resolve().is_relative_to(Path('/opt/aegisai/operator/supply-chain/releases'))
    assert trusted.stat().st_uid==0 and not trusted.stat().st_mode&0o022
    module=importlib.util.spec_from_file_location('trusted_managed_runtime',trusted)
    managed=importlib.util.module_from_spec(module);module.loader.exec_module(managed)
    _,bundles=managed.load_bundles()
    validate_managed_settings(bundles['auth']);del bundles
    ingress=json.loads(subprocess.check_output(['docker','inspect','aegisai-ingress'],text=True))[0]
    addresses=[]
    for name,cidr in (('aegisai-ec2-demo_default','172.18.0.0/16'),('aegisai-observability','172.29.240.0/24')):
        address=ingress['NetworkSettings']['Networks'][name]['IPAddress']
        assert ipaddress.ip_address(address) in ipaddress.ip_network(cidr)
        addresses.append(address+'/32')
    values={'images':{kind:value['reference'] for kind,value in ledger['images'].items()},
            'revision':ledger['approvedSource'],'apiReplicas':1,'frontendIngressCidrs':addresses}
    helm=Path('/opt/aegisai/platform/tools/helm/v4.3.1/helm')
    assert helm.stat().st_uid==0 and not helm.stat().st_mode&0o022
    assert digest(helm)==json.loads(helm.with_name('verified-install.json').read_text())['binarySha256']
    before=snapshot()
    if not args.apply:
        print(json.dumps({'standbyPlan':'ready','revision':values['revision'],'trafficMoved':False}));return
    target=ROOT/'standby';target.mkdir(mode=0o700,exist_ok=True)
    path=target/'values.json';path.write_text(json.dumps(values,indent=2))
    kube('apply','--server-side','--field-manager=aegisai-operator-runtime','-f','-',value={
        'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'api-public','namespace':'aegisai-private'},'data':refs})
    code=target/'bridge-code';assert not code.exists();code.mkdir(mode=0o700)
    for name in ('data_bridge.py','foundation.py','bootstrap.py','toolchain.json'):
        shutil.copyfile(SOURCE/name,code/name);(code/name).chmod(0o600)
    service='\n'.join(['[Unit]','Description=Bridge existing AegisAI backend endpoints',
        'After=aegisai-k3s.service docker.service','Requires=aegisai-k3s.service','[Service]','Type=oneshot',
        'ExecStart=/usr/bin/python3 '+str(code/'data_bridge.py'),
        'RuntimeDirectory=aegisai-data-bridge-cache','RuntimeDirectoryMode=0700','RuntimeDirectoryPreserve=yes',
        'MemoryMax=128M','CPUQuota=15%','TimeoutStartSec=30','NoNewPrivileges=yes','PrivateTmp=yes',''])
    timer='\n'.join(['[Unit]','Description=Refresh private backend endpoint bindings','[Timer]',
        'OnBootSec=20s','OnUnitActiveSec=15s','AccuracySec=1s','Unit=aegisai-data-bridge.service',
        '[Install]','WantedBy=timers.target',''])
    Path('/etc/systemd/system/aegisai-data-bridge.service').write_text(service)
    Path('/etc/systemd/system/aegisai-data-bridge.timer').write_text(timer)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','start','aegisai-data-bridge.service'],check=True,timeout=35)
    subprocess.run(['systemctl','enable','--now','aegisai-data-bridge.timer'],check=True)
    subprocess.run([str(helm),'upgrade','--install','aegisai-private',str(SOURCE/'chart'),
        '-n','aegisai-private','-f',str(path),'--kubeconfig',str(ROOT/'kubeconfig.yaml'),
        '--wait','--timeout','180s','--history-max','3'],check=True,timeout=200)
    assert snapshot()==before
    report={'kubernetesStandby':'ready','revision':values['revision'],'apiReplicas':1,'webReplicas':1,
        'restrictedPodSecurity':True,'hostPathAdded':False,'existingDockerApplicationUnchanged':True,
        'trafficMoved':False,'newMigrationsApplied':False,'newScanExecuted':False,'verifiedAt':now()}
    (ROOT/'standby-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
