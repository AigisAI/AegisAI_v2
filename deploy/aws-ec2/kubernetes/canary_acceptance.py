"""Actual weighted requests and native AnalysisRun abort, with independent recovery."""
import argparse
import collections
import copy
import fcntl
import http.client
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from bootstrap import BINARY, ROOT, now, snapshot
from foundation import kube
from blue_green import APP, get, selected, ready_pods, request
from image_retention import require_pinned, candidate_directory
from traffic import INGRESS, STATE, reload, checks
from verify_shared_limits import owner_cookie

OPERATOR = Path('/opt/aegisai/operator')
NORMAL = 'set $application http://10.45.0.40:80;'
CANARY = 'set $application http://10.45.0.67:80;'


def router(path):
    with urllib.request.urlopen('http://10.45.0.64:9000'+path, timeout=5) as response: return response.read(2*1024**2)


def loaded_weight():
    services = json.loads(router('/api/http/services'))
    value = next(s for s in services if s['name'] == 'weighted-api@file')
    return next(s['weight'] for s in value['weighted']['services'] if s['name'] == 'canary')


def counters():
    result = collections.Counter()
    for line in router('/metrics').decode().splitlines():
        match = re.fullmatch(r'traefik_service_requests_total\{([^}]+)\} ([0-9.eE+-]+)', line)
        if not match: continue
        labels = dict(re.findall(r'(\w+)="([^"\\]*)"', match[1]))
        if labels.get('service') in ('stable@file', 'canary@file'):
            result[(labels['service'], labels['code'])] += int(float(match[2]))
    return result


def measure(count=60):
    before = counters(); timings = []; statuses = collections.Counter()
    client = http.client.HTTPConnection('127.0.0.1', 8081, timeout=5)
    try:
        for _ in range(count):
            start = time.monotonic()
            client.request('GET', '/api/health', headers={'Host': 'aegisai-aws.tailaca7d2.ts.net'})
            response = client.getresponse(); response.read(65536)
            elapsed = time.monotonic()-start; timings.append(elapsed); statuses[str(response.status)] += 1
            time.sleep(max(0, 0.5-elapsed))
    finally: client.close()
    after = counters(); delta = after-before
    stable = sum(v for (service, _), v in delta.items() if service == 'stable@file')
    candidate = sum(v for (service, _), v in delta.items() if service == 'canary@file')
    assert stable+candidate == count, 'ACTUAL_ROUTER_COUNTS_NOT_EQUAL_CONTROLLED_REQUESTS'
    return {'requests': count, 'statuses': dict(statuses), 'stableRequests': stable, 'candidateRequests': candidate,
        'candidate5xx': sum(v for (s, code), v in delta.items() if s == 'canary@file' and code.startswith('5')),
        'p95Seconds': sorted(timings)[math.ceil(len(timings)*0.95)-1]}


def restore(directory):
    assert directory.parent == ROOT/'canary' and directory.name.startswith('run-')
    assert directory.stat().st_uid == 0 and not directory.stat().st_mode & 0o077
    saved = json.loads((directory/'saved.json').read_text())
    reload(saved['ingress']); STATE.write_text(saved['traffic']); (directory/'RESTORED').touch(mode=0o600)
    for kind, name in (('rollout', 'api-canary'), ('deployment', 'web-canary')):
        if kube('get', kind, name, '-n', APP, '--ignore-not-found', '-o', 'name').strip():
            kube('patch', kind, name, '-n', APP, '--type=merge', '-p', json.dumps({'spec': {'replicas': 0}}))
    for _ in range(60):
        if not json.loads(kube('get', 'pods', '-n', APP, '-l', 'aegisai.io/delivery=canary', '-o', 'json'))['items']: break
        time.sleep(2)
    else: raise RuntimeError('CANARY_PODS_NOT_STOPPED')
    if kube('get', 'service', 'api-canary-candidate', '-n', APP, '--ignore-not-found', '-o', 'name').strip():
        kube('patch', 'service', 'api-canary-candidate', '-n', APP, '--type=json',
            '-p', json.dumps([{'op': 'replace', 'path': '/spec/ports/0/targetPort', 'value': 'http'}]))
    kube('delete', 'networkpolicy', 'private-canary-fault-port', '-n', 'aegisai-system', '--ignore-not-found')
    kube('patch', 'hpa', 'api', '-n', APP, '--type=merge', '-p', json.dumps({'spec': saved['hpa']}))
    checks(json.loads(saved['traffic'])['originalHtmlSha256'])
    (directory/'recovery-result.json').write_text(json.dumps({'restored': True, 'verifiedAt': now()}))


def resources(current, previous, instance, run):
    template = copy.deepcopy(get('deployment', 'api')['spec']['template'])
    template['metadata']['labels'].update({'aegisai.io/delivery': 'canary', 'aegisai.io/canary-run': run})
    selector = {k: template['metadata']['labels'][k] for k in ('app.kubernetes.io/name', 'app.kubernetes.io/component', 'aegisai.io/delivery')}
    args = [{'name': 'start-requests', 'value': '0'}, {'name': 'start-errors', 'value': '0'}, {'name': 'router-instance', 'value': instance}]
    steps = []
    for weight in (10, 50, 100):
        steps += [{'setWeight': weight}, {'pause': {}}, {'analysis': {'templates': [{'templateName': 'private-canary-health'}], 'args': args}}]
    rollout = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Rollout',
        'metadata': {'name': 'api-canary', 'namespace': APP, 'labels': {'aegisai.io/managed-profile': 'canary'}},
        'spec': {'replicas': 1, 'minReadySeconds': 5, 'revisionHistoryLimit': 2, 'progressDeadlineSeconds': 180,
            'progressDeadlineAbort': True, 'selector': {'matchLabels': selector}, 'template': template,
            'strategy': {'canary': {'maxSurge': 1, 'maxUnavailable': 0, 'stableService': 'api-canary-stable',
                'canaryService': 'api-canary-candidate', 'trafficRouting': {'traefik': {'weightedTraefikServiceName': 'api-canary'}}, 'steps': steps}}}}
    docs = []
    for name, address in (('api-canary-stable', '10.45.0.65'), ('api-canary-candidate', '10.45.0.66')):
        docs.append({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': APP},
            'spec': {'type': 'ClusterIP', 'clusterIP': address, 'selector': selector,
                'ports': [{'name': 'http', 'port': 3000, 'targetPort': 'http'}]}})
    docs.append({'apiVersion': 'traefik.io/v1alpha1', 'kind': 'TraefikService', 'metadata': {'name': 'api-canary', 'namespace': APP},
        'spec': {'weighted': {'services': [{'name': 'api-canary-stable', 'port': 3000, 'weight': 100},
            {'name': 'api-canary-candidate', 'port': 3000, 'weight': 0}]}}})
    config = get('configmap', 'web-nginx')['data']['nginx.conf']
    assert config.count('http://api:3000') == 1
    docs.append({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'web-nginx-canary', 'namespace': APP},
        'data': {'nginx.conf': config.replace('http://api:3000', 'http://10.45.0.64:3000')}})
    web = copy.deepcopy(get('deployment', 'web')['spec']['template']); web['metadata']['labels']['aegisai.io/delivery'] = 'canary'
    web['metadata'].pop('annotations', None)
    for volume in web['spec']['volumes']:
        if volume['name'] == 'web-config': volume['configMap']['name'] = 'web-nginx-canary'
    docs.append({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'web-canary', 'namespace': APP},
        'spec': {'replicas': 1, 'revisionHistoryLimit': 1, 'selector': {'matchLabels': {'aegisai.io/delivery': 'canary', 'app.kubernetes.io/component': 'web'}}, 'template': web}})
    docs.append({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'web-canary', 'namespace': APP},
        'spec': {'type': 'ClusterIP', 'clusterIP': '10.45.0.67', 'selector': {'aegisai.io/delivery': 'canary', 'app.kubernetes.io/component': 'web'},
            'ports': [{'name': 'http', 'port': 80, 'targetPort': 'http'}]}})
    docs.append({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy', 'metadata': {'name': 'private-canary-web', 'namespace': APP},
        'spec': {'podSelector': {'matchLabels': {'aegisai.io/delivery': 'canary', 'app.kubernetes.io/component': 'web'}},
            'policyTypes': ['Egress'], 'egress': [{'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'aegisai-system'}},
                'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'private-canary-router'}}}], 'ports': [{'protocol': 'TCP', 'port': 8080}]}]}})
    return docs, rollout


def main():
    assert os.geteuid() == 0 and __debug__; os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('mode', choices=['normal', 'fault', 'restore']); parser.add_argument('directory', nargs='?', type=Path)
    parser.add_argument('--routing-only-without-session', action='store_true'); args = parser.parse_args()
    if args.mode == 'restore': restore(args.directory); return
    lock = (OPERATOR/'signed-deployment.lock').open('a'); fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
    traffic_raw = STATE.read_text(); traffic = json.loads(traffic_raw); assert traffic['backend'] == 'kubernetes'
    assert NORMAL in INGRESS.read_text() and CANARY not in INGRESS.read_text()
    assert get('service', 'api')['spec']['selector']['aegisai.io/delivery'] == 'deployment'
    ledger = json.loads((ROOT/'approved-app-images.json').read_text()); releases = ledger['approvedReleases']; assert len(releases) == 2
    current = next(r for r in releases if r['approvedSource'] == traffic['approvedSource']); previous = next(r for r in releases if r != current)
    trusted = OPERATOR/'supply-chain/current/deploy/aws-ec2/supply-chain'
    assert trusted.resolve().is_relative_to(OPERATOR/'supply-chain/releases'); sys.path.insert(0, str(trusted))
    from verify_candidate import verify
    for release in releases:
        require_pinned(release['images']); verify(candidate_directory(release), release['manifestSha256'], release['approvedSource'], target=True)
    def available_owner_cookie():
        try: return owner_cookie()
        except AssertionError as error:
            if str(error) != 'UNEXPIRED_OWNER_SESSION_NOT_AVAILABLE' or not args.routing_only_without_session: raise
            return None
    cookie = available_owner_cookie(); before = snapshot(); hpa = get('hpa', 'api')['spec']; assert hpa['minReplicas'] == 1 and hpa['maxReplicas'] == 2
    directory = ROOT/'canary'/('run-'+str(int(time.time()))+'-'+args.mode); directory.mkdir(mode=0o700)
    saved = {'ingress': INGRESS.read_text(), 'traffic': traffic_raw, 'hpa': hpa}; (directory/'saved.json').write_text(json.dumps(saved))
    timer = 'aegisai-canary-restore-'+directory.name
    subprocess.run(['systemd-run', '--quiet', '--unit='+timer, '--on-active=10m', '/usr/bin/python3', str(Path(__file__).resolve()),
        'restore', str(directory)], check=True, capture_output=True, timeout=10)
    phases = []; passed = False
    def guard(): assert not (directory/'RESTORED').exists(), 'CANARY_RECOVERY_ALREADY_TRIGGERED'
    def wait(condition, timeout=120):
        start = time.monotonic()
        while time.monotonic()-start < timeout:
            guard(); ready_pods()
            if condition(): return round(time.monotonic()-start, 3)
            time.sleep(2)
        raise RuntimeError('CANARY_PHASE_TIMEOUT')
    def endpoint(service, release):
        try: return selected(service)['image'] == release['images']['api']['reference']
        except AssertionError: return False
    def prometheus(query):
        public = json.loads((ROOT/'canary/control-installation-result.json').read_text())
        url = 'http://'+public['prometheus']+'/api/v1/query?'+urllib.parse.urlencode({'query': query})
        with urllib.request.urlopen(url, timeout=5) as response: value = json.load(response)
        assert value['status'] == 'success' and len(value['data']['result']) == 1
        return float(value['data']['result'][0]['value'][1])
    try:
        kube('patch', 'hpa', 'api', '-n', APP, '--type=merge', '-p', json.dumps({'spec': {'maxReplicas': 1}}))
        wait(lambda: len([p for p in json.loads(kube('get', 'pods', '-n', APP, '-o', 'json'))['items'] if p['metadata']['labels'].get('app.kubernetes.io/component') == 'api']) == 1)
        existing = kube('get', 'rollout', 'api-canary', '-n', APP, '--ignore-not-found', '-o', 'json')
        if existing.strip():
            ro = json.loads(existing); assert ro['spec']['replicas'] == 0 and ro['metadata']['labels']['aegisai.io/managed-profile'] == 'canary'
            kube('delete', 'rollout', 'api-canary', '-n', APP, '--cascade=foreground', '--wait=true', '--timeout=60s')
        # A fresh router instance also gives an unambiguous per-run Prometheus identity.
        kube('scale', 'deployment/private-canary-router', '-n', 'aegisai-system', '--replicas=0')
        kube('wait', '--for=delete', 'pod', '-n', 'aegisai-system', '-l', 'app.kubernetes.io/name=private-canary-router', '--timeout=45s')
        kube('scale', 'deployment/private-canary-router', '-n', 'aegisai-system', '--replicas=1')
        kube('rollout', 'status', 'deployment/private-canary-router', '-n', 'aegisai-system', '--timeout=60s')
        rp = json.loads(kube('get', 'pods', '-n', 'aegisai-system', '-l', 'app.kubernetes.io/name=private-canary-router', '-o', 'json'))['items']; assert len(rp) == 1
        instance = rp[0]['status']['podIP']+':9000'; router_uid = rp[0]['metadata']['uid']
        docs, rollout = resources(current, previous, instance, directory.name)
        for item in docs:
            if item['kind'] == 'Service' and item['metadata']['name'] in ('api-canary-stable', 'api-canary-candidate'):
                if kube('get', 'service', item['metadata']['name'], '-n', APP, '--ignore-not-found', '-o', 'name').strip():
                    kube('patch', 'service', item['metadata']['name'], '-n', APP, '--type=json', '-p', json.dumps([{'op': 'replace', 'path': '/spec/selector', 'value': item['spec']['selector']}]))
            kube('apply', '--server-side', '--force-conflicts', '--field-manager=aegisai-canary-profile', '-f', '-', value=item)
        kube('apply', '--server-side', '--field-manager=aegisai-canary-profile', '-f', '-', value=rollout)
        def initialized():
            ro = get('rollout', 'api-canary')
            return (ro.get('status', {}).get('phase') == 'Healthy' and endpoint('api-canary-stable', current)
                and get('service', 'api-canary-stable')['spec']['selector'].get('rollouts-pod-template-hash')
                and loaded_weight() == 0)
        wait(initialized)
        kube('rollout', 'status', 'deployment/web-canary', '-n', APP, '--timeout=60s')
        guard(); traffic.update(deliveryProfile='canary', strategyState=str(directory), activeStableSource=current['approvedSource'], candidateSource=previous['approvedSource'])
        STATE.write_text(json.dumps(traffic, indent=2)); reload(saved['ingress'].replace(NORMAL, CANARY)); checks(traffic['originalHtmlSha256'])
        if cookie:
            body, _ = request('127.0.0.1', 8081, '/api/auth/me', cookie); assert json.loads(body)['authenticated'] is True
        template = copy.deepcopy(rollout['spec']['template']); template['metadata']['labels']['app.kubernetes.io/version'] = previous['approvedSource']
        template['spec']['containers'][0]['image'] = previous['images']['api']['reference']
        kube('patch', 'rollout', 'api-canary', '-n', APP, '--type=merge', '-p', json.dumps({'spec': {'template': template}}))
        for index, target in enumerate((10,) if args.mode == 'fault' else (10, 50, 100)):
            wait(lambda: get('rollout', 'api-canary').get('status', {}).get('currentStepIndex') == index*3+1
                and bool(get('rollout', 'api-canary')['status'].get('pauseConditions')) and loaded_weight() == target
                and endpoint('api-canary-candidate', previous))
            if args.mode == 'fault':
                kube('apply', '--server-side', '--field-manager=aegisai-canary-fault', '-f', '-', value={
                    'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': 'private-canary-fault-port', 'namespace': 'aegisai-system'},
                    'spec': {'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'private-canary-router'}},
                        'policyTypes': ['Egress'], 'egress': [{'to': [{
                            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': APP}},
                            'podSelector': {'matchLabels': {'aegisai.io/delivery': 'canary', 'app.kubernetes.io/component': 'api'}}}],
                            'ports': [{'protocol': 'TCP', 'port': 3001}]}]}})
                kube('patch', 'service', 'api-canary-candidate', '-n', APP, '--type=json', '-p', json.dumps([
                    {'op': 'replace', 'path': '/spec/ports/0/targetPort', 'value': 3001}]))
                time.sleep(3)
            guard(); result = measure(); ratio = result['candidateRequests']/result['requests']*100
            assert abs(ratio-target) <= 10
            if args.mode == 'normal': assert result['statuses'] == {'200': 60} and result['p95Seconds'] <= 1
            else: assert result['candidate5xx'] >= 3 and result['statuses'].get('200', 0) >= 30
            result.update(weight=target, actualCandidatePercent=ratio, stableEndpoint=selected('api-canary-stable'), candidateEndpoint=selected('api-canary-candidate'))
            # Observe the exact run's real counter samples before releasing native analysis.
            total = sum(v for (service, _), v in counters().items() if service == 'canary@file')
            wait(lambda: prometheus('sum(traefik_service_requests_total{job="aegisai-canary-router",instance="'+instance+'",service="canary@file"}) or vector(0)') >= total, 45)
            old_runs = {v['metadata']['uid'] for v in json.loads(kube('get', 'analysisruns', '-n', APP, '-o', 'json'))['items']}
            guard(); kube('patch', 'rollout', 'api-canary', '-n', APP, '--subresource=status', '--type=merge', '-p', json.dumps({'status': {'pauseConditions': None}}))
            expected = 'Failed' if args.mode == 'fault' else 'Successful'
            completed = []
            def analyzed():
                runs = json.loads(kube('get', 'analysisruns', '-n', APP, '-o', 'json'))['items']
                completed[:] = [r for r in runs if r['metadata']['uid'] not in old_runs and r.get('status', {}).get('phase') == expected]
                return bool(completed)
            result['analysisSeconds'] = wait(analyzed, 90)
            result['nativeAnalysis'] = [{'name': r['metadata']['name'], 'phase': r['status']['phase'], 'metricResults': r['status'].get('metricResults', [])} for r in completed]
            phases.append(result)
        if args.mode == 'fault':
            seconds = wait(lambda: get('rollout', 'api-canary')['status'].get('abort') is True and loaded_weight() == 0 and endpoint('api-canary-stable', current), 90)
            recovery = measure(10); assert recovery['statuses'] == {'200': 10} and recovery['candidateRequests'] == 0
            recovery['automaticAbortSecondsAfterAnalysis'] = seconds
        else:
            wait(lambda: get('rollout', 'api-canary')['status'].get('phase') == 'Healthy' and get('rollout', 'api-canary')['status'].get('stableRS') == get('rollout', 'api-canary')['status'].get('currentPodHash'))
            recovery = None
            cookie = available_owner_cookie()
            if cookie:
                body, _ = request('127.0.0.1', 8081, '/api/auth/me', cookie); assert json.loads(body)['authenticated'] is True
        assert snapshot() == before
        rps = json.loads(kube('get', 'pods', '-n', 'aegisai-system', '-l', 'app.kubernetes.io/name=private-canary-router', '-o', 'json'))['items']
        assert len(rps) == 1 and rps[0]['metadata']['uid'] == router_uid and rps[0]['status']['containerStatuses'][0]['restartCount'] == 0
        report = {'actualPrivateCanary': 'passed', 'scenario': args.mode, 'routerInstance': instance, 'phases': phases,
            'existingOwnerSessionVerified': bool(cookie), 'routingOnlyIfNoOwnerSession': not bool(cookie),
            'automaticRecovery': recovery, 'newScanExecuted': False, 'newMigrationsApplied': False, 'verifiedAt': now()}
        (directory/'acceptance-result.json').write_text(json.dumps(report, indent=2)); (ROOT/'canary'/('acceptance-'+args.mode+'.json')).write_text(json.dumps(report, indent=2))
        passed = True; print(json.dumps(report))
    finally:
        restore(directory); subprocess.run(['systemctl', 'stop', timer+'.timer'], capture_output=True, timeout=10)
        if not passed: (directory/'failed-attempt.json').write_text(json.dumps({'phases': phases, 'recoveredAt': now()}, indent=2))


if __name__ == '__main__': main()
