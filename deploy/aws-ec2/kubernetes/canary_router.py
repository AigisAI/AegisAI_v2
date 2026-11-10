"""Bounded tokenless router and root-only translation of exact Rollouts weights."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

from bootstrap import BINARY, ROOT, SOURCE, now, snapshot
from foundation import kube
from gitops import object, rule, parse_vendor_output

PIN = json.loads((SOURCE/'canary-pin.json').read_text())
NS = 'aegisai-system'
APP = 'aegisai-private'
NAME = 'private-canary-router'


def weights(value):
    assert value['metadata']['name'] == 'api-canary' and value['metadata']['namespace'] == APP
    assert set(value['spec']) == {'weighted'} and set(value['spec']['weighted']) == {'services'}
    services = value['spec']['weighted']['services']
    assert len(services) == 2
    result = {}
    for service in services:
        assert set(service) == {'name', 'port', 'weight'} and service['port'] == 3000
        assert service['name'] in ('api-canary-stable', 'api-canary-candidate')
        assert service['name'] not in result and type(service['weight']) is int and 0 <= service['weight'] <= 100
        result[service['name']] = service['weight']
    assert sum(result.values()) == 100
    return result


def configuration(distribution):
    assert set(distribution) == {'api-canary-stable', 'api-canary-candidate'}
    return {'http': {'routers': {'private-api': {'entryPoints': ['web'], 'rule': 'PathPrefix(`/api/`)', 'service': 'weighted-api'}},
        'services': {'weighted-api': {'weighted': {'services': [
            {'name': 'stable', 'weight': distribution['api-canary-stable']},
            {'name': 'canary', 'weight': distribution['api-canary-candidate']}]}},
            'stable': {'loadBalancer': {'servers': [{'url': 'http://10.45.0.65:3000'}], 'serversTransport': 'bounded'}},
            'canary': {'loadBalancer': {'servers': [{'url': 'http://10.45.0.66:3000'}], 'serversTransport': 'bounded'}}},
        'serversTransports': {'bounded': {'forwardingTimeouts': {'dialTimeout': '2s', 'responseHeaderTimeout': '5s', 'idleConnTimeout': '30s'}}}}}


def configmap(distribution):
    return object('ConfigMap', NAME, namespace=NS, data={'dynamic.yaml': json.dumps(configuration(distribution))})


def publish():
    raw = kube('get', 'traefikservice', 'api-canary', '-n', APP, '--ignore-not-found', '-o', 'json')
    distribution = weights(json.loads(raw)) if raw.strip() else {'api-canary-stable': 100, 'api-canary-candidate': 0}
    current = json.loads(kube('get', 'configmap', NAME, '-n', NS, '-o', 'json'))
    desired = configmap(distribution)
    if current.get('data') != desired['data']:
        kube('apply', '--server-side', '--field-manager=aegisai-canary-projector', '-f', '-', value=desired)
    # Root publishes only non-secret Pod scrape addresses; the existing Prometheus
    # container retains its Pod-only route and read-only discovery directory.
    pods = json.loads(kube('get', 'pods', '-n', NS, '-l', 'app.kubernetes.io/name=' + NAME, '-o', 'json'))['items']
    targets = [{'targets': [p['status']['podIP']+':9000'], 'labels': {'runtime': 'private-canary-router'}}
        for p in pods if not p['metadata'].get('deletionTimestamp') and any(
            c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', []))]
    assert len(targets) <= 1
    directory = Path('/opt/aegisai/observability/discovery'); assert not directory.is_symlink()
    path = directory/'private-canary-router-targets.json'; pending = directory/'private-canary-router-targets.pending'
    assert not path.is_symlink() and not pending.is_symlink()
    pending.write_text(json.dumps(targets)); pending.chmod(0o644); pending.replace(path)
    return distribution


def resources():
    def obj(kind, name, spec=None, **kwargs): return object(kind, name, spec, namespace=NS, **kwargs)
    prometheus = json.loads(subprocess.check_output(['docker', 'inspect', 'aegisai-observability-prometheus-1']))[0]
    ip = prometheus['NetworkSettings']['Networks']['aegisai-observability']['IPAddress']
    import ipaddress
    assert ipaddress.ip_address(ip) in ipaddress.ip_network('172.29.240.0/24')
    app_peer = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': APP}},
        'podSelector': {'matchLabels': {'app.kubernetes.io/component': 'web'}}}
    labels = {'app.kubernetes.io/name': NAME, 'app.kubernetes.io/component': 'router'}
    return [obj('ServiceAccount', NAME, automountServiceAccountToken=False),
        configmap({'api-canary-stable': 100, 'api-canary-candidate': 0}),
        obj('Service', NAME, {'type': 'ClusterIP', 'clusterIP': '10.45.0.64', 'selector': labels,
            'ports': [{'name': 'http', 'port': 3000, 'targetPort': 'http'}, {'name': 'metrics', 'port': 9000, 'targetPort': 'admin'}]}),
        obj('NetworkPolicy', NAME, {'podSelector': {'matchLabels': labels}, 'policyTypes': ['Ingress', 'Egress'],
            'ingress': [{'from': [app_peer], 'ports': [{'protocol': 'TCP', 'port': 8080}]},
                {'from': [{'ipBlock': {'cidr': ip+'/32'}}], 'ports': [{'protocol': 'TCP', 'port': 9000}]}],
            'egress': [{'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': APP}},
                'podSelector': {'matchLabels': {'app.kubernetes.io/component': 'api'}}}],
                'ports': [{'protocol': 'TCP', 'port': 3000}]}]}, api='networking.k8s.io/v1'),
        obj('Deployment', NAME, {'replicas': 1, 'strategy': {'type': 'Recreate'},
            'selector': {'matchLabels': labels}, 'template': {'metadata': {'labels': labels}, 'spec': {
                'serviceAccountName': NAME, 'automountServiceAccountToken': False, 'enableServiceLinks': False,
                'terminationGracePeriodSeconds': 15,
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                    'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': 'router', 'image': PIN['image'], 'imagePullPolicy': 'IfNotPresent',
                    'args': ['--entryPoints.web.address=:8080', '--entryPoints.traefik.address=:9000',
                        '--entryPoints.web.forwardedHeaders.trustedIPs=10.44.0.0/16,172.31.55.151/32',
                        '--providers.file.directory=/etc/aegisai-router', '--providers.file.watch=true',
                        '--providers.providersThrottleDuration=500ms', '--api.insecure=true', '--api.dashboard=false',
                        '--ping=true', '--metrics.prometheus=true', '--metrics.prometheus.entryPoint=traefik',
                        '--metrics.prometheus.addServicesLabels=true', '--accesslog=false', '--log.level=WARN',
                        '--global.checkNewVersion=false', '--global.sendAnonymousUsage=false'],
                    'env': [{'name': 'GOMEMLIMIT', 'value': '72MiB'}],
                    'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'}, 'limits': {'cpu': '250m', 'memory': '96Mi'}},
                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}},
                    'ports': [{'name': 'http', 'containerPort': 8080}, {'name': 'admin', 'containerPort': 9000}],
                    'readinessProbe': {'httpGet': {'path': '/ping', 'port': 'admin'}, 'periodSeconds': 3},
                    'livenessProbe': {'httpGet': {'path': '/ping', 'port': 'admin'}, 'initialDelaySeconds': 20},
                    'volumeMounts': [{'name': 'dynamic', 'mountPath': '/etc/aegisai-router', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}]}],
                'volumes': [{'name': 'dynamic', 'configMap': {'name': NAME}}, {'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}}]}}}, api='apps/v1')]


def install():
    before = snapshot(); directory = ROOT/'canary'; directory.mkdir(mode=0o700, exist_ok=True)
    with urllib.request.urlopen(PIN['crdUrl'], timeout=30) as response: raw = response.read(2*1024**2)
    assert hashlib.sha256(raw).hexdigest() == PIN['crdSha256']
    file = directory/'traefikservices.yaml'; file.write_bytes(raw)
    crds = parse_vendor_output(kube('create', '--dry-run=client', '--validate=false', '-f', str(file), '-o', 'json'))
    assert len(crds) == 1 and crds[0]['metadata']['name'] == 'traefikservices.traefik.io'
    subprocess.run([str(BINARY), 'ctr', '-n', 'k8s.io', 'images', 'pull', PIN['image']], check=True, timeout=240, stdout=subprocess.DEVNULL)
    kube('apply', '--server-side', '--field-manager=aegisai-canary-bootstrap', '-f', '-', value=crds[0])
    kube('wait', '--for=condition=Established', 'crd/traefikservices.traefik.io', '--timeout=45s')
    for item in resources():
        kube('apply', '--server-side', '--field-manager=' + ('aegisai-canary-projector' if item['kind'] == 'ConfigMap' else 'aegisai-canary-bootstrap'), '-f', '-', value=item)
    kube('rollout', 'status', 'deployment/' + NAME, '-n', NS, '--timeout=90s')
    unit = Path('/etc/systemd/system/aegisai-canary-projector.service')
    assert not unit.exists()
    unit.write_text('[Unit]\nAfter=aegisai-k3s.service\nRequires=aegisai-k3s.service\n[Service]\nType=simple\nExecStart=/usr/bin/python3 '+str(Path(__file__).resolve())+' daemon\nRestart=on-failure\nRestartSec=3\nUMask=0077\nCPUQuota=10%\nMemoryMax=96M\nNoNewPrivileges=true\nPrivateTmp=true\n[Install]\nWantedBy=multi-user.target\n')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', unit.name], check=True, capture_output=True)
    publish(); assert snapshot() == before
    (directory/'router-installation-result.json').write_text(json.dumps({'privateCanaryRouter': 'ready',
        'version': PIN['version'], 'image': PIN['image'], 'tokenless': True, 'applicationUnchanged': True, 'trafficMoved': False, 'verifiedAt': now()}, indent=2))
    print('Pinned tokenless private router Ready; application traffic unchanged')


def main():
    assert os.geteuid() == 0 and __debug__; os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('mode', choices=['install', 'publish', 'daemon']); args = parser.parse_args()
    if args.mode == 'install': install()
    elif args.mode == 'publish': print(json.dumps(publish()))
    else:
        while True:
            publish(); time.sleep(2)


if __name__ == '__main__': main()
