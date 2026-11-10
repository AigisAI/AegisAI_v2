"""Bounded real private Blue/Green switch/back; independently recoverable."""
import argparse
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from bootstrap import ROOT, now, snapshot
from foundation import kube
from image_retention import require_pinned, candidate_directory
from traffic import INGRESS, STATE, reload, checks
from verify_shared_limits import owner_cookie

APP = 'aegisai-private'
OPERATOR = Path('/opt/aegisai/operator')
NORMAL = 'set $application http://10.45.0.40:80;'
GREEN = 'set $application http://10.45.0.63:80;'


def get(kind, name): return json.loads(kube('get', kind, name, '-n', APP, '-o', 'json'))


def ready_pods():
    pods = json.loads(kube('get', 'pods', '-n', APP, '-o', 'json'))['items']
    assert sum(p['metadata']['labels'].get('app.kubernetes.io/component') == 'api' for p in pods) <= 3
    assert sum(p['metadata']['labels'].get('app.kubernetes.io/component') == 'web' for p in pods) <= 2
    return [p for p in pods if not p['metadata'].get('deletionTimestamp') and any(
        c['type'] == 'Ready' and c['status'] == 'True' for c in p['status'].get('conditions', []))]


def selected(service):
    selector = get('service', service)['spec']['selector']
    pods = [p for p in ready_pods() if all(p['metadata']['labels'].get(k) == v for k, v in selector.items())]
    assert len(pods) == 1, 'ONE_READY_VERSION_ENDPOINT_REQUIRED'
    p = pods[0]
    return {'pod': p['metadata']['name'], 'uid': p['metadata']['uid'], 'image': p['spec']['containers'][0]['image'],
        'source': p['metadata']['labels']['app.kubernetes.io/version'], 'selector': selector}


def request(host, port, path, cookie=None):
    client = http.client.HTTPConnection(host, port, timeout=5, source_address=('172.31.55.151', 0) if host != '127.0.0.1' else None)
    start = time.monotonic()
    try:
        headers = {'Host': 'aegisai-aws.tailaca7d2.ts.net', 'X-Forwarded-Proto': 'https'}
        if cookie: headers['Cookie'] = cookie
        client.request('GET', path, headers=headers); response = client.getresponse(); body = response.read(2*1024**2)
        assert response.status == 200, 'PRIVATE_BLUE_GREEN_HTTP_FAILED'
        return body, round((time.monotonic()-start)*1000, 3)
    finally: client.close()


def restore(directory):
    assert directory.parent == ROOT/'blue-green' and directory.name.startswith('run-')
    assert directory.stat().st_uid == 0 and not directory.stat().st_mode & 0o077
    saved = json.loads((directory/'saved.json').read_text())
    reload(saved['ingress'])  # original service first; never require candidate readiness for recovery
    STATE.write_text(saved['traffic'])
    (directory/'RESTORED').touch(mode=0o600)
    for kind, name in (('rollout', 'api-blue-green'), ('deployment', 'web-bg')):
        if kube('get', kind, name, '-n', APP, '--ignore-not-found', '-o', 'name').strip():
            kube('patch', kind, name, '-n', APP, '--type=merge', '-p', json.dumps({'spec': {'replicas': 0}}))
    # Wait for all strategy Pods to disappear before re-enabling fallback autoscaling.
    for _ in range(60):
        pods = json.loads(kube('get', 'pods', '-n', APP, '-l', 'aegisai.io/delivery=blue-green', '-o', 'json'))['items']
        if not pods: break
        time.sleep(2)
    else: raise RuntimeError('BLUE_GREEN_PODS_NOT_STOPPED')
    kube('patch', 'hpa', 'api', '-n', APP, '--type=merge', '-p', json.dumps({'spec': saved['hpa']}))
    checks(json.loads(saved['traffic'])['originalHtmlSha256'])
    (directory/'recovery-result.json').write_text(json.dumps({'restored': True, 'verifiedAt': now()}))


def resources(current):
    api = copy.deepcopy(get('deployment', 'api')['spec']['template'])
    api['metadata'].pop('annotations', None)
    api['metadata']['labels']['aegisai.io/delivery'] = 'blue-green'
    selector = {k: api['metadata']['labels'][k] for k in ('app.kubernetes.io/name', 'app.kubernetes.io/component', 'aegisai.io/delivery')}
    rollout = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Rollout',
        'metadata': {'name': 'api-blue-green', 'namespace': APP}, 'spec': {
            'replicas': 1, 'revisionHistoryLimit': 2, 'progressDeadlineSeconds': 120, 'progressDeadlineAbort': True,
            'rollbackWindow': {'revisions': 2}, 'selector': {'matchLabels': selector}, 'template': api,
            'strategy': {'blueGreen': {'activeService': 'api-bg-active', 'previewService': 'api-bg-preview',
                'autoPromotionEnabled': False, 'scaleDownDelaySeconds': 60, 'scaleDownDelayRevisionLimit': 1}}}}
    docs = []
    for name, address in (('api-bg-active', '10.45.0.61'), ('api-bg-preview', '10.45.0.62')):
        docs.append({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': APP},
            'spec': {'type': 'ClusterIP', 'clusterIP': address, 'selector': selector,
                'ports': [{'name': 'http', 'port': 3000, 'targetPort': 'http'}]}})
    config = get('configmap', 'web-nginx')['data']['nginx.conf']
    assert config.count('http://api:3000') == 1
    config = config.replace('http://api:3000', 'http://api-bg-active:3000')
    docs.append({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'web-nginx-bg', 'namespace': APP}, 'data': {'nginx.conf': config}})
    web = copy.deepcopy(get('deployment', 'web')['spec']['template'])
    web['metadata']['labels']['aegisai.io/delivery'] = 'blue-green'
    web['metadata'].pop('annotations', None)
    for volume in web['spec']['volumes']:
        if volume['name'] == 'web-config': volume['configMap']['name'] = 'web-nginx-bg'
    docs.append({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'web-bg', 'namespace': APP},
        'spec': {'replicas': 1, 'revisionHistoryLimit': 1, 'selector': {'matchLabels': {
            'app.kubernetes.io/component': 'web', 'aegisai.io/delivery': 'blue-green'}}, 'template': web}})
    docs.append({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'web-bg', 'namespace': APP},
        'spec': {'type': 'ClusterIP', 'clusterIP': '10.45.0.63', 'selector': {
            'app.kubernetes.io/component': 'web', 'aegisai.io/delivery': 'blue-green'},
            'ports': [{'name': 'http', 'port': 80, 'targetPort': 'http'}]}})
    return docs, rollout


def main():
    assert os.geteuid() == 0 and __debug__; os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('mode', choices=['verify', 'restore'])
    parser.add_argument('directory', nargs='?', type=Path); parser.add_argument('--apply', action='store_true'); args = parser.parse_args()
    if args.mode == 'restore': restore(args.directory); return
    lock = (OPERATOR/'signed-deployment.lock').open('a'); fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
    traffic_raw = STATE.read_text(); traffic = json.loads(traffic_raw)
    assert traffic['backend'] == 'kubernetes' and NORMAL in INGRESS.read_text() and GREEN not in INGRESS.read_text()
    assert get('service', 'api')['spec']['selector']['aegisai.io/delivery'] == 'deployment'
    assert get('service', 'web')['spec']['selector']['aegisai.io/delivery'] == 'deployment'
    ledger = json.loads((ROOT/'approved-app-images.json').read_text()); releases = ledger['approvedReleases']; assert len(releases) == 2
    current = next(r for r in releases if r['approvedSource'] == traffic['approvedSource'])
    previous = next(r for r in releases if r['approvedSource'] != traffic['approvedSource'])
    trusted = OPERATOR/'supply-chain/current/deploy/aws-ec2/supply-chain'
    assert trusted.resolve().is_relative_to(OPERATOR/'supply-chain/releases')
    sys.path.insert(0, str(trusted)); from verify_candidate import verify
    for release in releases:
        require_pinned(release['images'])
        verify(candidate_directory(release), release['manifestSha256'], release['approvedSource'], target=True)
    cookie = owner_cookie(); before = snapshot()
    hpa = get('hpa', 'api')['spec']; assert hpa['minReplicas'] == 1 and hpa['maxReplicas'] == 2
    docs, rollout = resources(current)
    assert selected('api')['image'] == current['images']['api']['reference']
    if not args.apply: print(json.dumps({'blueGreenPlan': 'ready', 'freshSignedVersions': 2})); return
    directory = ROOT/'blue-green'/('run-' + str(int(time.time()))); directory.mkdir(mode=0o700, parents=True)
    saved = {'ingress': INGRESS.read_text(), 'traffic': traffic_raw, 'hpa': hpa}
    (directory/'saved.json').write_text(json.dumps(saved))
    timer = 'aegisai-blue-green-restore-' + directory.name
    subprocess.run(['systemd-run', '--quiet', '--unit=' + timer, '--on-active=8m', '/usr/bin/python3',
        str(Path(__file__).resolve()), 'restore', str(directory)], check=True, capture_output=True, timeout=10)
    samples = []; phases = []; passed = False

    def guard(): assert not (directory/'RESTORED').exists(), 'RECOVERY_ALREADY_TRIGGERED'

    def wait(test, timeout=120):
        start = time.monotonic()
        while time.monotonic()-start < timeout:
            guard(); _, latency = request('127.0.0.1', 8081, '/api/health')
            samples.append({'at': now(), 'health': 200, 'latencyMs': latency})
            ready_pods()
            if test(): return round(time.monotonic()-start, 3)
            time.sleep(2)
        raise RuntimeError('BLUE_GREEN_PHASE_TIMEOUT')

    def active_is(release):
        try: endpoint = selected('api-bg-active')
        except AssertionError: return False
        return endpoint['image'] == release['images']['api']['reference']

    def session(host, port):
        body, latency = request(host, port, '/api/auth/me', cookie)
        assert json.loads(body)['authenticated'] is True
        return latency

    try:
        kube('patch', 'hpa', 'api', '-n', APP, '--type=merge', '-p', json.dumps({'spec': {'maxReplicas': 1}}))
        wait(lambda: get('deployment', 'api')['status'].get('replicas') == 1)
        for item in docs: kube('apply', '--server-side', '--field-manager=aegisai-blue-green', '-f', '-', value=item)
        kube('apply', '--server-side', '--field-manager=aegisai-blue-green', '-f', '-', value=rollout)
        wait(lambda: active_is(current))
        kube('rollout', 'status', 'deployment/web-bg', '-n', APP, '--timeout=90s')
        initial = selected('api-bg-active'); session('10.45.0.61', 3000)
        # Argo CD must still serve the original Deployment through its narrow selector.
        assert selected('api')['image'] == current['images']['api']['reference']
        template = copy.deepcopy(rollout['spec']['template'])
        template['metadata']['labels']['app.kubernetes.io/version'] = previous['approvedSource']
        template['spec']['containers'][0]['image'] = previous['images']['api']['reference']
        kube('patch', 'rollout', 'api-blue-green', '-n', APP, '--type=merge', '-p', json.dumps({'spec': {'template': template}}))

        def preview_ready():
            try: preview = selected('api-bg-preview')
            except AssertionError: return False
            ro = get('rollout', 'api-blue-green')
            return preview['image'] == previous['images']['api']['reference'] and bool(ro['status'].get('pauseConditions'))

        preview_seconds = wait(preview_ready)
        preview = selected('api-bg-preview'); session('10.45.0.62', 3000)
        assert active_is(current)
        guard(); traffic['deliveryProfile'] = 'blue-green'; traffic['strategyState'] = str(directory)
        traffic['activeApiSource'] = current['approvedSource']; STATE.write_text(json.dumps(traffic, indent=2))
        reload(saved['ingress'].replace(NORMAL, GREEN))
        checks(traffic['originalHtmlSha256']); session('127.0.0.1', 8081)
        # Same status patch as the vendor promote command; no full/skip-analysis shortcut.
        guard(); kube('patch', 'rollout', 'api-blue-green', '-n', APP, '--subresource=status', '--type=merge',
            '-p', json.dumps({'status': {'pauseConditions': None}}))
        seconds = wait(lambda: active_is(previous))
        traffic['activeApiSource'] = previous['approvedSource']; STATE.write_text(json.dumps(traffic, indent=2))
        latency = session('127.0.0.1', 8081)
        phases.append({'phase': 'promoted-previous-signed-api', 'seconds': seconds, 'endpoint': selected('api-bg-active'), 'ownerSessionLatencyMs': latency})
        guard(); kube('patch', 'rollout', 'api-blue-green', '-n', APP, '--type=merge',
            '-p', json.dumps({'spec': {'template': rollout['spec']['template']}}))
        seconds = wait(lambda: active_is(current))
        traffic['activeApiSource'] = current['approvedSource']; STATE.write_text(json.dumps(traffic, indent=2))
        phases.append({'phase': 'rolled-back-current-signed-api', 'seconds': seconds,
            'endpoint': selected('api-bg-active'), 'ownerSessionLatencyMs': session('127.0.0.1', 8081)})
        assert snapshot() == before
        passed = True
        result = {'actualPrivateBlueGreen': 'passed', 'scope': 'API versions; unchanged signed original frontend',
            'initial': initial, 'preview': preview, 'previewReadySeconds': preview_seconds, 'phases': phases,
            'allObservedHealth200': True, 'actualSamples': samples, 'existingOwnerSessionPreserved': True,
            'noSyntheticSessionCreated': True, 'newScanExecuted': False, 'newMigrationsApplied': False, 'verifiedAt': now()}
        (directory/'acceptance-result.json').write_text(json.dumps(result, indent=2))
        (ROOT/'blue-green/acceptance-result.json').write_text(json.dumps(result, indent=2))
        print(json.dumps({k: v for k, v in result.items() if k != 'actualSamples'}))
    finally:
        restore(directory)
        subprocess.run(['systemctl', 'stop', timer + '.timer'], capture_output=True, timeout=10)
        if not passed:
            (directory/'failed-attempt.json').write_text(json.dumps({'phases': phases, 'actualSamples': samples, 'recoveredAt': now()}, indent=2))


if __name__ == '__main__': main()
