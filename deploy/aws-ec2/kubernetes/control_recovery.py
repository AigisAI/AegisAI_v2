"""Restore the protected K3s backup into a loopback-only, agentless API."""
import argparse
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

from bootstrap import BINARY, PIN, ROOT, digest, now, snapshot
from foundation import kube
from traffic import STATE, request

TRIALS = ROOT / 'control-rehearsals'
PORT = '16443'


def boot(directory):
    assert directory.parent == TRIALS and directory.name.startswith('trial-')
    assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino
    assert not (ROOT / 'data/server/db/state.db').exists(), 'LIVE_DATA_MUST_BE_INACCESSIBLE'
    subprocess.run(['ip', 'addr', 'add', '192.0.2.1/32', 'dev', 'lo'], check=True, timeout=5)
    command = [str(BINARY), 'server', '--config', str(directory/'config.json')]
    os.execv(command[0], command)


def production():
    state = json.loads(STATE.read_text())
    application = json.loads(kube('get', 'application', 'aegisai-private', '-n', 'argocd', '-o', 'json'))
    pods = json.loads(kube('get', 'pods', '-n', 'aegisai-private', '-o', 'json'))['items']
    assert state['backend'] == 'kubernetes' and not state.get('deliveryProfile')
    assert application['status']['sync']['status'] == 'Synced' and application['status']['health']['status'] == 'Healthy'
    assert request(8081, '/api/health')[0] == 200
    return state, sorted(p['metadata']['uid'] for p in pods)


def rehearse(backup):
    assert digest(BINARY) == PIN['binary']['sha256']
    memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    assert int(memory['MemAvailable'].split()[0]) >= 4096 * 1024
    assert shutil.disk_usage(ROOT).free >= 6 * 1024**3
    catalog = json.loads(Path('/opt/aegisai/scanner/catalog/current.json').read_text())
    assert catalog['ready'] and not catalog['busy']
    assert backup.resolve() == backup and backup.parent == ROOT/'control-backups'
    assert backup.stat().st_uid == 0 and not backup.stat().st_mode & 0o077
    state, pod_ids = production()
    docker = snapshot()
    saved = json.loads((backup/'application-traffic.json').read_text())
    assert saved['gitRevision'] == state['gitRevision'] and saved['images'] == state['images']
    TRIALS.mkdir(mode=0o700, exist_ok=True)
    assert TRIALS.resolve() == TRIALS and not TRIALS.stat().st_mode & 0o077
    directory = Path(tempfile.mkdtemp(prefix='trial-', dir=TRIALS))
    unit = 'aegisai-control-' + directory.name + '.service'
    log = TRIALS / (directory.name + '.log')
    started = time.monotonic()
    try:
        data = directory/'data'
        database = data/'server/db/state.db'
        database.parent.mkdir(mode=0o700, parents=True)
        for name in ('state.db', 'token', 'encryption-config.json'):
            path = backup/name
            assert not path.is_symlink() and path.stat().st_uid == 0 and not path.stat().st_mode & 0o077
        with closing(sqlite3.connect((backup/'state.db').as_uri()+'?mode=ro', uri=True)) as source:
            with closing(sqlite3.connect(database)) as target:
                source.backup(target)
                assert target.execute('PRAGMA quick_check').fetchone() == ('ok',)
                row = target.execute('SELECT value, deleted FROM kine WHERE name=? ORDER BY id DESC LIMIT 1',
                    ('/registry/secrets/argocd/argocd-redis',)).fetchone()
                assert row and row[1] == 0 and row[0].startswith(b'k8s:enc:')
        shutil.copyfile(backup/'token', directory/'server-token')
        encryption = json.loads((backup/'encryption-config.json').read_text())
        provider = next(iter(encryption['resources'][0]['providers'][0]))
        assert provider in ('aescbc', 'secretbox')
        config = {'data-dir': str(data), 'token-file': str(directory/'server-token'), 'disable-agent': True,
            'disable-scheduler': True, 'disable-controller-manager': True, 'disable-cloud-controller': True,
            'disable-helm-controller': True, 'disable-network-policy': True,
            'disable': ['traefik', 'servicelb', 'local-storage', 'metrics-server'],
            'bind-address': '127.0.0.1', 'https-listen-port': int(PORT), 'advertise-address': '192.0.2.1',
            'node-ip': '192.0.2.1', 'node-name': 'aegisai-control-rehearsal', 'egress-selector-mode': 'disabled',
            'cluster-cidr': '10.44.0.0/16', 'service-cidr': '10.45.0.0/16', 'cluster-dns': '10.45.0.10',
            'write-kubeconfig': str(directory/'kubeconfig'), 'write-kubeconfig-mode': '0600',
            'secrets-encryption': True, 'secrets-encryption-provider': provider,
            'kube-apiserver-arg': ['anonymous-auth=false']}
        (directory/'config.json').write_text(json.dumps(config))
        log.touch(mode=0o600)
        properties = ['PrivateNetwork=yes', 'PrivateTmp=yes', 'PrivateDevices=yes', 'ProtectSystem=strict',
            'ProtectHome=yes', 'NoNewPrivileges=yes', 'ReadWritePaths='+str(directory),
            'InaccessiblePaths='+str(ROOT/'data')+' '+str(ROOT/'kubeconfig.yaml')+' -/run/k3s -/run/containerd -/run/docker.sock',
            'RuntimeMaxSec=120', 'TimeoutStopSec=10', 'CPUQuota=50%', 'MemoryMax=900M', 'UMask=0077',
            'StandardOutput=append:'+str(log), 'StandardError=inherit']
        subprocess.run(['systemd-run', '--quiet', '--unit='+unit, *['--property='+p for p in properties],
            '/usr/bin/python3', str(Path(__file__).resolve()), 'boot', str(directory)], check=True, timeout=15)

        def read(*args):
            return subprocess.check_output(['nsenter', '--target', str(pid), '--net', str(BINARY), 'kubectl',
                '--kubeconfig', str(directory/'kubeconfig'), '--server=https://127.0.0.1:'+PORT,
                '--request-timeout=4s', *args], text=True, stderr=subprocess.DEVNULL, timeout=8)

        for _ in range(34):
            pid = int(subprocess.check_output(['systemctl', 'show', unit, '-p', 'MainPID', '--value'], timeout=5))
            if pid and (directory/'kubeconfig').exists():
                try:
                    if read('get', '--raw=/readyz').strip() == 'ok': break
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
            if subprocess.run(['systemctl', 'is-failed', '--quiet', unit], timeout=5).returncode == 0:
                raise RuntimeError('ISOLATED_K3S_FAILED: '+str(log))
            time.sleep(2)
        else:
            raise RuntimeError('ISOLATED_K3S_NOT_READY: '+str(log))
        assert os.stat(f'/proc/{pid}/ns/net').st_ino != os.stat('/proc/self/ns/net').st_ino
        application = json.loads(read('get', 'application', 'aegisai-private', '-n', 'argocd', '-o', 'json'))
        assert application['spec']['source']['targetRevision'] == state['gitRevision']
        for component in ('api', 'web'):
            deployment = json.loads(read('get', 'deployment', component, '-n', 'aegisai-private', '-o', 'json'))
            assert deployment['spec']['template']['spec']['containers'][0]['image'] == state['images'][component]['reference']
        for name in ('api-blue-green', 'api-canary'):
            rollout = json.loads(read('get', 'rollout', name, '-n', 'aegisai-private', '-o', 'json'))
            assert rollout['spec']['replicas'] == 0
        assert read('get', 'secret', 'argocd-redis', '-n', 'argocd', '-o', 'jsonpath={.type}') == 'Opaque'
        assert production() == (state, pod_ids) and snapshot() == docker
        report = {'isolatedControlApiRestore': 'passed', 'backup': backup.name, 'gitRevision': state['gitRevision'],
            'approvedApiAndWebImagesRecovered': True, 'inactiveRolloutProfilesRecovered': 2,
            'encryptedSecretReadableByApi': True, 'liveApplicationPodsUnchanged': True,
            'composeContainersPreserved': True, 'seconds': round(time.monotonic()-started, 3), 'verifiedAt': now()}
    finally:
        subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=20)
        status = subprocess.run(['systemctl', 'show', unit, '-p', 'MainPID', '--value'], capture_output=True, text=True, timeout=5)
        assert status.stdout.strip() in ('', '0'), 'ISOLATED_SERVER_DID_NOT_STOP'
        shutil.rmtree(directory)
    (ROOT/'control-recovery-result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['rehearse', 'boot'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.mode == 'boot': boot(args.directory)
    else:
        with Path('/opt/aegisai/operator/signed-deployment.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            rehearse(args.directory)
