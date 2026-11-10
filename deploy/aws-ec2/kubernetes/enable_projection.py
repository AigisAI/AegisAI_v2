"""Reviewable root-only catalog publisher installation; default is read-only."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from bootstrap import ROOT, SOURCE, configuration, now, snapshot, wait_ready
from foundation import kube


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    parser=argparse.ArgumentParser()
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    assert re.fullmatch('[a-f0-9]{40}',args.source_commit)
    actual=json.loads((ROOT/'config.yaml').read_text())
    expected=configuration()
    previous=copy.deepcopy(expected)
    previous['kubelet-arg'].remove('sync-frequency=10s')
    assert actual in (expected,previous), 'UNRELATED_CONTROL_CONFIGURATION_DRIFT'
    before=snapshot()
    if not args.apply:
        print(json.dumps({'catalogProjectionPlan':'ready','kubeletSyncSeconds':10,
            'publisherPeriodSeconds':5,'kubeletRestartRequired':actual!=expected,'trafficMoved':False}))
        return
    if actual!=expected:
        backup=ROOT/'config-before-catalog-projection.yaml'
        assert not backup.exists()
        shutil.copyfile(ROOT/'config.yaml',backup)
        (ROOT/'config.yaml').write_text(json.dumps(expected,indent=2))
        subprocess.run(['systemctl','restart','aegisai-k3s.service'],check=True,timeout=260)
    wait_ready()
    configz=json.loads(kube('get','--raw','/api/v1/nodes/aegisai-private/proxy/configz'))['kubeletconfig']
    assert configz['syncFrequency']=='10s' and configz['configMapAndSecretChangeDetectionStrategy']=='Watch'
    code=ROOT/'catalog-publisher'/args.source_commit
    assert not code.exists()
    code.mkdir(mode=0o700,parents=True)
    for name in ('catalog_publisher.py','foundation.py','bootstrap.py','toolchain.json'):
        shutil.copyfile(SOURCE/name,code/name);(code/name).chmod(0o600)
    service='\n'.join(['[Unit]','Description=Publish non-secret AegisAI scanner status',
        'After=aegisai-k3s.service','Requires=aegisai-k3s.service','[Service]','Type=oneshot',
        'ExecStart=/usr/bin/python3 '+str(code/'catalog_publisher.py'),
        'RuntimeDirectory=aegisai-catalog-cache','RuntimeDirectoryMode=0700','RuntimeDirectoryPreserve=yes',
        'MemoryMax=96M','CPUQuota=10%','TimeoutStartSec=15','NoNewPrivileges=yes',
        'ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','CapabilityBoundingSet=',
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6','IPAddressDeny=any',
        'IPAddressAllow=127.0.0.0/8','IPAddressAllow=::1/128','IPAddressAllow=172.31.55.151/32',''])
    timer='\n'.join(['[Unit]','Description=Refresh bounded private scanner status',
        'After=aegisai-k3s.service','[Timer]','OnBootSec=15s','OnUnitActiveSec=5s','AccuracySec=1s',
        'Unit=aegisai-catalog-publisher.service','[Install]','WantedBy=timers.target',''])
    Path('/etc/systemd/system/aegisai-catalog-publisher.service').write_text(service)
    Path('/etc/systemd/system/aegisai-catalog-publisher.timer').write_text(timer)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','start','aegisai-catalog-publisher.service'],check=True,timeout=20)
    subprocess.run(['systemctl','enable','--now','aegisai-catalog-publisher.timer'],check=True)
    # Reconcile the documented DNS budget after the control-plane restart.
    kube('patch','deployment','coredns','-n','kube-system','--type=strategic','-p',json.dumps({
        'spec':{'template':{'spec':{'containers':[{'name':'coredns','resources':{
            'requests':{'cpu':'50m','memory':'32Mi'},'limits':{'cpu':'200m','memory':'64Mi'}}}]}}}}))
    kube('rollout','status','deployment/coredns','-n','kube-system','--timeout=60s')
    assert snapshot()==before
    cm=json.loads(kube('get','configmap','runtime-catalog','-n','aegisai-private','-o','json'))
    status=json.loads(cm['data']['current.json'])
    assert set(status).issubset({'ready','busy','ai','updatedAt','scannerSetVersion','policyVersion'})
    report={'catalogPublisher':'installed','sourceCommit':args.source_commit,'kubeletSyncSeconds':10,
        'projectionCache':'Watch','publisherPeriodSeconds':5,'timestampPreserved':True,
        'applicationUnchanged':True,'trafficMoved':False,'podProjectionPropagationVerified':False,'verifiedAt':now()}
    (ROOT/'catalog-publisher-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
