"""Delegate only private Canary reconciliation and native Prometheus analysis."""
import json
import os
from pathlib import Path
import subprocess
import time

from bootstrap import BINARY, ROOT, now
from foundation import kube
from gitops import object, rule
from rollouts import USER

APP = 'aegisai-private'


def analysis(prometheus):
    total = '(sum(traefik_service_requests_total{job="aegisai-canary-router",instance="{{args.router-instance}}",service="canary@file"}) or vector(0))'
    failed = '(sum(traefik_service_requests_total{job="aegisai-canary-router",instance="{{args.router-instance}}",service="canary@file",code=~"5.."}) or vector(0))'
    query = '('+failed+' - {{args.start-errors}}) / clamp_min(('+total+' - {{args.start-requests}}), 1)'
    latency = 'histogram_quantile(0.95, sum by (le) (rate(traefik_service_request_duration_seconds_bucket{job="aegisai-canary-router",instance="{{args.router-instance}}",service="canary@file"}[1m])))'
    metrics = []
    for name, expression, success, failure in (
        ('actual-candidate-requests', total+' - {{args.start-requests}}', 'result[0] >= 3', 'result[0] < 3'),
        ('candidate-error-ratio', query, 'result[0] <= 0.01', 'result[0] > 0.01'),
        ('candidate-p95', latency, '!isNaN(result[0]) && result[0] <= 1', 'isNaN(result[0]) || result[0] > 1')):
        metrics.append({'name': name, 'count': 1, 'interval': '5s', 'failureLimit': 0, 'consecutiveErrorLimit': 1,
            'successCondition': success, 'failureCondition': failure,
            'provider': {'prometheus': {'address': 'http://'+prometheus+':9090', 'query': expression}}})
    return object('AnalysisTemplate', 'private-canary-health', namespace=APP, api='argoproj.io/v1alpha1', spec={
        'args': [{'name': 'start-requests'}, {'name': 'start-errors'}, {'name': 'router-instance'}], 'metrics': metrics})


def main():
    assert os.geteuid() == 0 and __debug__; os.umask(0o077)
    directory = ROOT/'canary'; assert directory.is_dir()
    # Keep the proven G1 ownership boundary and add only the second named profile.
    p = json.loads(kube('get', 'validatingadmissionpolicy', 'aegisai-rollout-replicasets', '-o', 'json'))
    expression = p['spec']['validations'][0]['expression']
    for prefix in ('object', 'oldObject'):
        expression = expression.replace(prefix+".metadata.name.startsWith('api-blue-green-')",
            '('+prefix+".metadata.name.startsWith('api-blue-green-') || "+prefix+".metadata.name.startsWith('api-canary-'))")
    expression = expression.replace("o.name == 'api-blue-green'", "o.name in ['api-blue-green', 'api-canary']")
    kube('patch', 'validatingadmissionpolicy', p['metadata']['name'], '--type=json', '-p', json.dumps([
        {'op': 'replace', 'path': '/spec/validations/0/expression', 'value': expression}]))
    policy = {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicy',
        'metadata': {'name': 'aegisai-owned-canary-analysis'}, 'spec': {'failurePolicy': 'Fail',
            'matchConstraints': {'resourceRules': [{'apiGroups': ['argoproj.io'], 'apiVersions': ['v1alpha1'],
                'operations': ['CREATE', 'UPDATE', 'DELETE'], 'resources': ['analysisruns']}]},
            'matchConditions': [{'name': 'controller', 'expression': "request.userInfo.username == '"+USER+"'"}],
            'validations': [{'expression': "request.operation == 'DELETE' ? oldObject.metadata.name.startsWith('api-canary-') : (object.metadata.name.startsWith('api-canary-') && has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(o, o.kind == 'Rollout' && o.name == 'api-canary' && o.controller == true))",
                'message': 'Only the owned private Canary analysis may be reconciled'}]}}
    for value in (policy, {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicyBinding',
        'metadata': {'name': policy['metadata']['name']}, 'spec': {'policyName': policy['metadata']['name'], 'validationActions': ['Deny', 'Audit']}}):
        kube('apply', '--server-side', '--field-manager=aegisai-canary-control', '-f', '-', value=value)
    # Admission must actually reject an unowned creation before dynamic CREATE delegation.
    invalid = object('AnalysisRun', 'unowned-analysis-probe', namespace=APP, api='argoproj.io/v1alpha1',
        spec={'metrics': [{'name': 'probe', 'count': 1, 'provider': {'web': {'url': 'http://127.0.0.1/'}}}]})
    for _ in range(30):
        result = subprocess.run([str(BINARY), 'kubectl', '--kubeconfig', str(ROOT/'kubeconfig.yaml'),
            '--as='+USER, '--as-group=system:masters', 'create', '--dry-run=server', '-f', '-'],
            input=json.dumps(invalid), capture_output=True, text=True, timeout=15)
        if result.returncode and 'Only the owned private Canary analysis' in result.stderr: break
        time.sleep(0.5)
    else: raise RuntimeError('CANARY_ANALYSIS_ADMISSION_NOT_ACTIVE')
    role = json.loads(kube('get', 'role', 'private-rollouts', '-n', APP, '-o', 'json'))
    rules = role['rules']
    for r in rules:
        if 'resourceNames' not in r: continue
        if 'api-blue-green' in r['resourceNames']: r['resourceNames'] = sorted(set(r['resourceNames']+['api-canary']))
        if 'api-bg-active' in r['resourceNames']: r['resourceNames'] = sorted(set(r['resourceNames']+['api-canary-stable', 'api-canary-candidate']))
    additions = [rule('argoproj.io', ['analysisruns', 'analysisruns/finalizers'], ['create', 'update', 'patch', 'delete']),
        rule('traefik.io', ['traefikservices'], ['get', 'list', 'watch']),
        rule('traefik.io', ['traefikservices'], ['update', 'patch'], ['api-canary'])]
    for r in additions:
        if r not in rules: rules.append(r)
    kube('patch', 'role', 'private-rollouts', '-n', APP, '--type=merge', '-p', json.dumps({'rules': rules}))
    # Native Traefik provider watches the current API group, while the router
    # itself has no Kubernetes credentials and reads only the projected config.
    deployment = json.loads(kube('get', 'deployment', 'argo-rollouts', '-n', 'aegisai-rollouts', '-o', 'json'))
    args = deployment['spec']['template']['spec']['containers'][0]['args']
    if '--traefik-api-group=traefik.io' not in args:
        args += ['--traefik-api-group=traefik.io']
        kube('patch', 'deployment', 'argo-rollouts', '-n', 'aegisai-rollouts', '--type=json',
            '-p', json.dumps([{'op': 'replace', 'path': '/spec/template/spec/containers/0/args', 'value': args}]))
    prometheus = json.loads(subprocess.check_output(['docker', 'inspect', 'aegisai-observability-prometheus-1']))[0]
    ip = prometheus['NetworkSettings']['Networks']['aegisai-observability']['IPAddress']
    import ipaddress
    assert ipaddress.ip_address(ip) in ipaddress.ip_network('172.29.240.0/24')
    kube('apply', '--server-side', '--field-manager=aegisai-canary-control', '-f', '-', value=object(
        'NetworkPolicy', 'private-canary-analysis', namespace='aegisai-rollouts', api='networking.k8s.io/v1', spec={
            'podSelector': {'matchLabels': {'app.kubernetes.io/name': 'argo-rollouts'}}, 'policyTypes': ['Egress'],
            'egress': [{'to': [{'ipBlock': {'cidr': ip+'/32'}}], 'ports': [{'protocol': 'TCP', 'port': 9090}]}]}))
    kube('apply', '--server-side', '--field-manager=aegisai-canary-control', '-f', '-', value=analysis(ip))
    config = Path('/opt/aegisai/observability/config/prometheus.yaml'); text = config.read_text()
    if 'job_name: aegisai-canary-router' not in text:
        (directory/'pre-canary-prometheus.yaml').write_text(text)
        config.write_text(text+'''  - job_name: aegisai-canary-router
    scrape_interval: 5s
    file_sd_configs:
      - files: ['/etc/aegisai/discovery/private-canary-router-targets.json']
        refresh_interval: 5s
''')
        try:
            subprocess.run(['docker', 'exec', 'aegisai-observability-prometheus-1', '/bin/promtool', 'check', 'config', '/etc/aegisai/prometheus.yaml'],
                check=True, capture_output=True, timeout=20)
            subprocess.run(['docker', 'kill', '--signal=HUP', 'aegisai-observability-prometheus-1'], check=True, capture_output=True, timeout=15)
        except Exception:
            config.write_text(text)
            raise
    kube('rollout', 'status', 'deployment/argo-rollouts', '-n', 'aegisai-rollouts', '--timeout=90s')
    report = {'privateCanaryControl': 'ready', 'nativeUnownedAnalysisRejected': True, 'prometheus': ip+':9090',
        'applicationTrafficMoved': False, 'verifiedAt': now()}
    (directory/'control-installation-result.json').write_text(json.dumps(report, indent=2)); print(json.dumps(report))


if __name__ == '__main__': main()
