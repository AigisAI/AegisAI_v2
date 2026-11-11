"""Reconcile the private CoreDNS Deployment's approved resource and rollout settings."""
import argparse
import json
import os
from pathlib import Path
import subprocess

from foundation import kube

NAME = 'aegisai-coredns-limits'
UNITS = Path('/etc/systemd/system')
RESOURCES = {'requests': {'cpu': '50m', 'memory': '32Mi'}, 'limits': {'cpu': '200m', 'memory': '64Mi'}}
STRATEGY = {'type': 'RollingUpdate', 'rollingUpdate': {'maxSurge': 1, 'maxUnavailable': 0}}


def reconcile():
    target = ['deployment', 'coredns', '-n', 'kube-system']
    cache = '--cache-dir=/run/' + NAME
    deployment = json.loads(kube(cache, 'get', *target, '-o', 'json'))
    spec = deployment['spec']
    containers = spec['template']['spec']['containers']
    assert spec['selector']['matchLabels'] == {'k8s-app': 'kube-dns'}
    assert spec['replicas'] == 1 and [c['name'] for c in containers] == ['coredns']
    if containers[0].get('resources') == RESOURCES and spec['strategy'] == STRATEGY:
        return
    patch = [{'op': 'test', 'path': '/spec/template/spec/containers/0/name', 'value': 'coredns'},
        {'op': 'add', 'path': '/spec/template/spec/containers/0/resources', 'value': RESOURCES},
        {'op': 'replace', 'path': '/spec/strategy', 'value': STRATEGY}]
    kube(cache, 'patch', *target, '--type=json', '-p', json.dumps(patch))
    kube(cache, 'rollout', 'status', 'deployment/coredns', '-n', 'kube-system', '--timeout=60s')
    print('CoreDNS resource limits and ready replacement confirmed')


def install():
    source = str(Path(__file__).resolve())
    assert ' ' not in source and source.startswith('/opt/aegisai/operator/')
    files = {NAME+'.service': f'''[Unit]
Description=Maintain private CoreDNS resource limits
After=aegisai-k3s.service
ConditionPathExists=/opt/aegisai/kubernetes/kubeconfig.yaml
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B {source} reconcile
RuntimeDirectory={NAME}
RuntimeDirectoryMode=0700
TimeoutStartSec=80
CPUQuota=25%
MemoryMax=128M
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
''', NAME+'.timer': f'''[Unit]
Description=Reapply private CoreDNS limits after boot and drift
[Timer]
OnBootSec=45s
OnUnitInactiveSec=60s
AccuracySec=1s
Unit={NAME}.service
[Install]
WantedBy=timers.target
'''}
    for name, content in files.items():
        path = UNITS / name
        if path.exists():
            assert path.read_text() == content, 'EXISTING_DNS_UNIT_DIFFERS'
        else:
            with path.open('x') as file:
                file.write(content)
    subprocess.run(['systemctl', 'daemon-reload'], check=True, timeout=15)
    subprocess.run(['systemctl', 'start', NAME+'.service'], check=True, timeout=85)
    subprocess.run(['systemctl', 'enable', '--now', NAME+'.timer'], check=True, timeout=15)


if __name__ == '__main__':
    assert os.geteuid() == 0 and __debug__
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['install', 'reconcile'])
    args = parser.parse_args()
    if args.mode == 'install': install()
    else: reconcile()
