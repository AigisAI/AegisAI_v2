"""Pinned namespace-scoped Rollouts; no application or traffic mutation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

from bootstrap import BINARY, ROOT, SOURCE, now, snapshot
from foundation import kube
from gitops import object, rule, parse_vendor_output

NS = 'aegisai-rollouts'
APP = 'aegisai-private'
ACCOUNT = 'argo-rollouts'
USER = 'system:serviceaccount:' + NS + ':' + ACCOUNT
PIN = json.loads((SOURCE / 'rollouts-pin.json').read_text())


def obj(kind, name, spec=None, **extra):
    return object(kind, name, spec, namespace=NS, **extra)


def resources():
    api = [{'ipBlock': {'cidr': ip}} for ip in ('172.31.55.151/32', '10.45.0.1/32')]
    values = [
        {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {
            'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.37'}}},
        obj('ResourceQuota', 'bounded-controller', {'hard': {'pods': '1', 'requests.cpu': '250m',
            'limits.memory': '96Mi', 'secrets': '2', 'configmaps': '4'}}),
        obj('ServiceAccount', 'default', automountServiceAccountToken=False),
        obj('ServiceAccount', ACCOUNT, automountServiceAccountToken=True),
        obj('ConfigMap', 'argo-rollouts-config', data={}),
        obj('Role', 'controller-config', api='rbac.authorization.k8s.io/v1', rules=[
            rule('', ['configmaps', 'secrets'], ['get', 'list', 'watch'])]),
        obj('RoleBinding', 'controller-config', api='rbac.authorization.k8s.io/v1',
            roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'controller-config'},
            subjects=[{'kind': 'ServiceAccount', 'name': ACCOUNT, 'namespace': NS}]),
        object('Role', 'private-rollouts', namespace=APP, api='rbac.authorization.k8s.io/v1', rules=[
            rule('argoproj.io', ['rollouts', 'analysisruns', 'experiments', 'analysistemplates'], ['get', 'list', 'watch']),
            rule('argoproj.io', ['rollouts', 'rollouts/status', 'rollouts/finalizers'], ['update', 'patch'], ['api-blue-green']),
            rule('apps', ['replicasets'], ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']),
            rule('apps', ['deployments'], ['get', 'list', 'watch']),
            rule('batch', ['jobs'], ['get', 'list', 'watch']),
            rule('networking.k8s.io', ['ingresses'], ['get', 'list', 'watch']),
            rule('', ['services', 'pods', 'podtemplates'], ['get', 'list', 'watch']),
            rule('', ['services'], ['update', 'patch'], ['api-bg-active', 'api-bg-preview']),
            rule('', ['events'], ['create', 'update', 'patch'])]),
        object('RoleBinding', 'private-rollouts', namespace=APP, api='rbac.authorization.k8s.io/v1',
            roleRef={'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'private-rollouts'},
            subjects=[{'kind': 'ServiceAccount', 'name': ACCOUNT, 'namespace': NS}]),
        obj('NetworkPolicy', 'private-controller', {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'],
            'ingress': [], 'egress': [{'to': api, 'ports': [{'protocol': 'TCP', 'port': 443}, {'protocol': 'TCP', 'port': 6443}]}]},
            api='networking.k8s.io/v1'),
        obj('Deployment', ACCOUNT, {'replicas': 1, 'strategy': {'type': 'Recreate'},
            'selector': {'matchLabels': {'app.kubernetes.io/name': ACCOUNT}},
            'template': {'metadata': {'labels': {'app.kubernetes.io/name': ACCOUNT}}, 'spec': {
                'serviceAccountName': ACCOUNT, 'automountServiceAccountToken': True, 'enableServiceLinks': False,
                'terminationGracePeriodSeconds': 20,
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 999, 'runAsGroup': 999, 'fsGroup': 999,
                    'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': ACCOUNT, 'image': PIN['image'], 'imagePullPolicy': 'IfNotPresent',
                    'args': ['--namespaced', '--namespace=' + APP, '--leader-elect=false', '--loglevel=warn',
                        '--rollout-threads=1', '--service-threads=1', '--analysis-threads=1', '--experiment-threads=1'],
                    'env': [{'name': 'POD_NAMESPACE', 'value': NS}, {'name': 'GOMEMLIMIT', 'value': '72MiB'}],
                    'resources': {'requests': {'cpu': '50m', 'memory': '48Mi'},
                        'limits': {'cpu': '250m', 'memory': '96Mi', 'ephemeral-storage': '64Mi'}},
                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                        'capabilities': {'drop': ['ALL']}},
                    'ports': [{'name': 'healthz', 'containerPort': 8080}],
                    'readinessProbe': {'httpGet': {'path': '/healthz', 'port': 'healthz'}, 'periodSeconds': 3},
                    'livenessProbe': {'httpGet': {'path': '/healthz', 'port': 'healthz'}, 'initialDelaySeconds': 30},
                    'volumeMounts': [{'name': 'tmp', 'mountPath': '/tmp'},
                        {'name': 'plugins', 'mountPath': '/home/argo-rollouts/plugin-bin'}]}],
                'volumes': [{'name': 'tmp', 'emptyDir': {'sizeLimit': '16Mi'}},
                    {'name': 'plugins', 'emptyDir': {'sizeLimit': '8Mi'}}]}}}, api='apps/v1')]
    # Enforce ReplicaSet ownership before granting its unavoidable dynamic-name RBAC.
    rs = "object.metadata.name.startsWith('api-blue-green-') && has(object.metadata.ownerReferences) && object.metadata.ownerReferences.exists(o, o.kind == 'Rollout' && o.name == 'api-blue-green' && o.controller == true)"
    for name, group, resource, expression in (
        ('aegisai-rollout-replicasets', 'apps', 'replicasets', rs),
        ('aegisai-rollout-root-spec', 'argoproj.io', 'rollouts', 'object.spec == oldObject.spec')):
        operations = ['CREATE', 'UPDATE', 'DELETE'] if resource == 'replicasets' else ['UPDATE']
        check = '(' + expression + ')'
        if resource == 'replicasets':
            check = "request.operation == 'DELETE' ? (" + rs.replace('object.', 'oldObject.') + ') : ' + check
        policy = {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicy',
            'metadata': {'name': name}, 'spec': {'failurePolicy': 'Fail',
                'matchConstraints': {'resourceRules': [{'apiGroups': [group], 'apiVersions': ['*'],
                    'operations': operations, 'resources': [resource]}]},
                'matchConditions': [{'name': 'only-controller', 'expression': "request.userInfo.username == '" + USER + "'"}],
                'validations': [{'expression': check, 'message': 'Rollouts may reconcile only its own ReplicaSets and cannot change desired release spec'}]}}
        values.insert(0, policy)
        values.insert(1, {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicyBinding',
            'metadata': {'name': name}, 'spec': {'policyName': name, 'validationActions': ['Deny', 'Audit']}})
    return values


def main():
    assert os.geteuid() == 0 and __debug__; os.umask(0o077)
    parser = argparse.ArgumentParser(); parser.add_argument('--apply', action='store_true'); args = parser.parse_args()
    before = snapshot(); path = ROOT / 'rollouts'; path.mkdir(mode=0o700, exist_ok=True)
    crds = []
    for name, sha in PIN['files'].items():
        with urllib.request.urlopen(PIN['base'] + name, timeout=30) as response: content = response.read(2*1024**2)
        assert hashlib.sha256(content).hexdigest() == sha
        file = path / Path(name).name; file.write_bytes(content)
        if name.startswith('crds/'):
            crds.extend(parse_vendor_output(kube('create', '--dry-run=client', '--validate=false', '-f', str(file), '-o', 'json')))
    docs = resources()
    if not args.apply:
        print(json.dumps({'rolloutsPlan': 'ready', 'crds': len(crds), 'resources': len(docs)})); return
    subprocess.run([str(BINARY), 'ctr', '-n', 'k8s.io', 'images', 'pull', PIN['image']],
        check=True, timeout=240, stdout=subprocess.DEVNULL)
    for item in crds: kube('apply', '--server-side', '--field-manager=aegisai-rollouts-bootstrap', '-f', '-', value=item)
    for item in crds: kube('wait', '--for=condition=Established', 'crd/' + item['metadata']['name'], '--timeout=45s')
    for item in docs:
        if item['kind'] in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'):
            kube('apply', '--server-side', '--field-manager=aegisai-rollouts-bootstrap', '-f', '-', value=item)
    # Prove native admission propagation before delegating dynamic ReplicaSet writes.
    import time
    probe = json.loads(kube('get', 'deployment', 'api', '-n', APP, '-o', 'json'))
    invalid = {'apiVersion': 'apps/v1', 'kind': 'ReplicaSet', 'metadata': {'name': 'unowned-replicaset-probe', 'namespace': APP},
        'spec': {'replicas': 0, 'selector': probe['spec']['selector'], 'template': probe['spec']['template']}}
    for attempt in range(30):
        check = subprocess.run([str(BINARY), 'kubectl', '--kubeconfig', str(ROOT/'kubeconfig.yaml'),
            '--as=' + USER, '--as-group=system:masters', 'create', '--dry-run=server', '-f', '-'],
            input=json.dumps(invalid), capture_output=True, text=True, timeout=20)
        if check.returncode and 'Rollouts may reconcile only' in check.stderr: break
        time.sleep(0.5)
    else: raise AssertionError('ROLLOUT_ADMISSION_NOT_ACTIVE')
    for item in docs:
        if item['kind'] not in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'):
            kube('apply', '--server-side', '--field-manager=aegisai-rollouts-bootstrap', '-f', '-', value=item)
    kube('rollout', 'status', 'deployment/' + ACCOUNT, '-n', NS, '--timeout=90s')
    denied = []
    for verb, resource, namespace in [('get', 'secrets', APP), ('get', 'secrets', 'argocd'),
        ('patch', 'deployments/api', APP), ('patch', 'services/api', APP), ('create', 'pods', APP),
        ('get', 'nodes', None), ('create', 'clusterrolebindings', None)]:
        command = ['auth', 'can-i', verb, resource, '--as=' + USER]
        if namespace: command += ['-n', namespace]
        result = subprocess.run([str(BINARY), 'kubectl', '--kubeconfig', str(ROOT/'kubeconfig.yaml'), *command],
            capture_output=True, text=True, timeout=15)
        assert result.stdout.strip() == 'no', (verb, resource)
        denied.append(resource)
    assert snapshot() == before
    result = {'privateRolloutsController': 'ready', 'version': PIN['version'], 'image': PIN['image'],
        'maximumMemoryMiB': 96, 'watchedNamespace': APP, 'deniedResources': denied,
        'applicationUnchanged': True, 'trafficMoved': False, 'verifiedAt': now()}
    (path / 'installation-result.json').write_text(json.dumps(result, indent=2)); print(json.dumps(result))


if __name__ == '__main__': main()
