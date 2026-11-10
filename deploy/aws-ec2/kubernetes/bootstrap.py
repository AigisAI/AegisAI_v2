"""Explicit root operator bootstrap; default validates without mutating the host."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

ROOT = Path('/opt/aegisai/kubernetes')
SOURCE = Path(__file__).resolve().parent
INSTANCE = 'i-0d24d0502cfc5a9c5'
NODE_IP = '172.31.55.151'
POD_CIDR = '10.44.0.0/16'
SERVICE_CIDR = '10.45.0.0/16'
PIN = json.loads((SOURCE / 'toolchain.json').read_text())['k3s']
BINARY = Path('/opt/aegisai/platform/tools/k3s') / PIN['version'] / 'k3s'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, timeout=kwargs.pop('timeout', 60), **kwargs)


def output(*args):
    return subprocess.check_output(list(args), text=True, timeout=30)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot():
    result = {}
    for name in ('api', 'web', 'postgres', 'redis'):
        value = json.loads(output('docker', 'inspect', 'aegisai-ec2-demo-' + name + '-1'))[0]
        assert value['State']['Health']['Status'] == 'healthy'
        result[name] = {'id': value['Id'], 'image': value['Image']}
    result['release'] = Path('/opt/aegisai/shared/candidate-release').read_text().strip()
    return result


def validate(facts):
    assert facts['instanceId'] == INSTANCE, 'WRONG_HOST'
    assert facts['cpuCount'] == 2 and facts['architecture'] == 'x86_64', 'WRONG_CAPACITY_CLASS'
    assert facts['memoryAvailableMiB'] >= 4096, 'INSUFFICIENT_MEMORY'
    assert facts['diskFreeBytes'] >= 6 * 1024**3, 'INSUFFICIENT_DISK'
    assert facts['scannerReady'] and not facts['scannerBusy'], 'SCANNER_NOT_IDLE_READY'
    assert NODE_IP in facts['addresses'], 'WRONG_NODE_ADDRESS'
    desired = [ipaddress.ip_network(POD_CIDR), ipaddress.ip_network(SERVICE_CIDR)]
    for route in facts['routes']:
        if route == 'default':
            continue
        network = ipaddress.ip_network(route, strict=False)
        assert not any(network.overlaps(value) for value in desired), 'NETWORK_OVERLAP'


def inventory():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request('http://169.254.169.254/latest/api/token', method='PUT',
                                 headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'})
    with opener.open(req, timeout=3) as response:
        token = response.read(4096).decode()
    req = urllib.request.Request('http://169.254.169.254/latest/meta-data/instance-id',
                                 headers={'X-aws-ec2-metadata-token': token})
    with opener.open(req, timeout=3) as response:
        instance = response.read(128).decode()
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    catalog = json.loads(Path('/opt/aegisai/scanner/catalog/current.json').read_text())
    age = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(catalog['updatedAt'])
    assert 0 <= age.total_seconds() < 60, 'STALE_SCANNER_CATALOG'
    for service in ('aegisai-scan-supervisor', 'aegisai-private-broker', 'aegisai-runtime-secrets'):
        run('systemctl', 'is-active', '--quiet', service)
    routes = json.loads(output('ip', '-json', 'route'))
    addresses = json.loads(output('ip', '-json', '-4', 'address'))
    facts = {'instanceId': instance, 'cpuCount': os.cpu_count(), 'architecture': os.uname().machine,
             'memoryAvailableMiB': int(memory['MemAvailable'].split()[0]) // 1024,
             'diskFreeBytes': shutil.disk_usage('/opt/aegisai').free,
             'scannerReady': catalog['ready'], 'scannerBusy': catalog['busy'],
             'routes': [row['dst'] for row in routes],
             'addresses': [a['local'] for row in addresses for a in row.get('addr_info', [])]}
    validate(facts)
    with opener.open('http://127.0.0.1:8081/api/health', timeout=10) as response:
        assert response.status == 200
    return facts


def download(item, path):
    assert not path.is_symlink()
    if path.exists():
        assert path.stat().st_size == item['bytes'] and digest(path) == item['sha256'], 'VENDOR_FILE_DRIFT'
        return
    temporary = path.with_suffix('.incoming')
    assert not temporary.exists()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(PIN['releaseBase'] + item['name'], headers={'User-Agent': 'AegisAI-operator'})
    total = 0
    try:
        with opener.open(request, timeout=30) as response, temporary.open('xb') as destination:
            assert response.geturl().startswith(('https://github.com/', 'https://release-assets.githubusercontent.com/'))
            while content := response.read(1024**2):
                total += len(content)
                assert total <= item['bytes'], 'OVERSIZED_VENDOR_FILE'
                destination.write(content)
        assert total == item['bytes'] and digest(temporary) == item['sha256'], 'VENDOR_CHECKSUM_MISMATCH'
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()  # Exact transient file only; no recursive cleanup.


def configuration():
    return {'data-dir': str(ROOT / 'data'), 'node-name': 'aegisai-private', 'node-ip': NODE_IP,
            'bind-address': NODE_IP, 'advertise-address': NODE_IP,
            'tls-san': [NODE_IP, '127.0.0.1'], 'write-kubeconfig': str(ROOT / 'kubeconfig.yaml'),
            'write-kubeconfig-mode': '0600', 'secrets-encryption': True,
            'cluster-cidr': POD_CIDR, 'service-cidr': SERVICE_CIDR, 'cluster-dns': '10.45.0.10',
            'flannel-backend': 'host-gw', 'flannel-iface': 'enp39s0',
            'disable': ['traefik', 'servicelb', 'local-storage', 'metrics-server'],
            'disable-helm-controller': True, 'resolv-conf': '/run/systemd/resolve/resolv.conf',
            'service-node-port-range': '32760-32767',
            'kube-proxy-arg': ['proxy-mode=iptables'],
            'kube-apiserver-arg': ['anonymous-auth=false', 'audit-policy-file=' + str(ROOT / 'audit-policy.json'),
                'audit-log-path=' + str(ROOT / 'audit.log'), 'audit-log-maxage=7',
                'audit-log-maxbackup=2', 'audit-log-maxsize=5'],
            'kubelet-arg': ['address=' + NODE_IP, 'read-only-port=0', 'anonymous-auth=false',
                'sync-frequency=10s',
                'authorization-mode=Webhook', 'pod-max-pids=128', 'max-pods=24',
                'system-reserved=cpu=400m,memory=4096Mi', 'kube-reserved=cpu=200m,memory=1024Mi',
                'eviction-hard=memory.available<512Mi,nodefs.available<10%,imagefs.available<10%',
                'container-log-max-size=5Mi', 'container-log-max-files=2',
                'image-gc-high-threshold=75', 'image-gc-low-threshold=65']}


def wait_ready(timeout=120):
    # systemd READY means the API is serving, not that kubelet registered yet.
    deadline = time.monotonic() + timeout
    command = [str(BINARY), 'kubectl', '--kubeconfig', str(ROOT / 'kubeconfig.yaml')]
    while time.monotonic() < deadline:
        value = subprocess.run([*command, 'get', 'node/aegisai-private', '-o', 'json'],
                               capture_output=True, text=True, timeout=10)
        if value.returncode == 0:
            node = json.loads(value.stdout)
            if any(c['type'] == 'Ready' and c['status'] == 'True'
                   for c in node.get('status', {}).get('conditions', [])):
                return node
        time.sleep(2)
    raise TimeoutError('NODE_NOT_READY_WITHIN_BOUND')


def main():
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    options = parser.parse_args()
    facts = inventory()
    before = snapshot()
    config = configuration()
    if not options.apply:
        print(json.dumps({'bootstrapPreflight': 'passed', 'facts': facts, 'application': before,
                          'productionChanged': False, 'k3sVersion': PIN['version']}))
        return
    assert not ROOT.exists(), 'EXISTING_KUBERNETES_STATE_REQUIRES_RECONCILIATION'
    ROOT.mkdir(mode=0o700, parents=True)
    (ROOT / 'before-bootstrap.json').write_text(json.dumps({'facts': facts, 'application': before}, indent=2))
    (ROOT / 'config.yaml').write_text(json.dumps(config, indent=2))
    (ROOT / 'audit-policy.json').write_text(json.dumps({'apiVersion': 'audit.k8s.io/v1', 'kind': 'Policy',
        'omitStages': ['RequestReceived'], 'rules': [{'level': 'Metadata'}]}))
    BINARY.parent.mkdir(parents=True, mode=0o700)
    download(PIN['binary'], BINARY)
    BINARY.chmod(0o755)
    images = ROOT / 'data/agent/images'
    images.mkdir(parents=True, mode=0o700)
    download(PIN['images'], images / PIN['images']['name'])
    run(str(BINARY), '--version')
    shutil.copyfile(SOURCE / 'firewall.py', ROOT / 'firewall.py')
    (ROOT / 'firewall.py').chmod(0o700)
    unit = '\n'.join(['[Unit]', 'Description=AegisAI private single-host Kubernetes',
        'Wants=network-online.target', 'After=network-online.target docker.service', '[Service]',
        'Type=notify', 'Environment=K3S_KUBECONFIG_MODE=600',
        'ExecStartPre=/usr/bin/python3 ' + str(ROOT / 'firewall.py'),
        'ExecStart=' + str(BINARY) + ' server --config ' + str(ROOT / 'config.yaml'),
        'Restart=on-failure', 'RestartSec=10', 'KillMode=process', 'Delegate=yes',
        'LimitNOFILE=1048576', 'LimitNPROC=infinity', 'TasksMax=2048',
        'MemoryHigh=1024M', 'MemoryMax=1536M', 'CPUQuota=100%', 'CPUWeight=50',
        'OOMScoreAdjust=-250', 'TimeoutStartSec=240', 'TimeoutStopSec=30', '[Install]',
        'WantedBy=multi-user.target', ''])
    Path('/etc/systemd/system/aegisai-k3s.service').write_text(unit)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', '--now', 'aegisai-k3s.service', timeout=260)
    wait_ready()
    assert snapshot() == before, 'EXISTING_APPLICATION_CHANGED'
    with urllib.request.urlopen('http://127.0.0.1:8081/api/health', timeout=10) as response:
        assert response.status == 200
    report = {'privateK3sBootstrap': 'ready', 'version': PIN['version'], 'binarySha256': digest(BINARY),
              'applicationUnchanged': True, 'existingRelease': before['release'],
              'generalQualification': 'NOT_QUALIFIED', 'newComputeCreated': False,
              'appTrafficMoved': False, 'rolloutOrHpaCompletion': False, 'verifiedAt': now()}
    (ROOT / 'bootstrap-result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    main()
