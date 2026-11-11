"""Read the AWS delivery check for the exact immutable Git release revision."""
import hashlib
import json
import re
import urllib.parse
import urllib.request

REPOSITORY = 'AigisAI/AegisAI_v2'
BRANCH = 'release/375-private-aws-gate'
WORKFLOW = 'private-aws-delivery-gate.yml'
WORKFLOW_PATH = '.github/workflows/' + WORKFLOW
WORKFLOW_SHA256 = 'd01eca6db754293d31d02a3d0d4a606f58a4537c16f0732f21064eadc49d4ba8'
API = 'https://api.github.com/repos/' + REPOSITORY + '/actions/'


def read(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'AegisAI-private-release'})
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read(256 * 1024 + 1)
    if len(body) > 256 * 1024:
        raise ValueError('AWS_DELIVERY_GATE_RESPONSE_TOO_LARGE')
    return body


def require_aws_delivery_gate(revision):
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('IMMUTABLE_DELIVERY_REVISION_REQUIRED')
    workflow = read(f'https://raw.githubusercontent.com/{REPOSITORY}/{revision}/{WORKFLOW_PATH}')
    if hashlib.sha256(workflow).hexdigest() != WORKFLOW_SHA256:
        raise ValueError('AWS_DELIVERY_WORKFLOW_CHANGED')
    query = urllib.parse.urlencode({'head_sha': revision, 'branch': BRANCH, 'event': 'push', 'per_page': 5})
    response = json.loads(read(f'{API}workflows/{WORKFLOW}/runs?{query}'))
    for run in response['workflow_runs']:
        if (run['head_sha'], run['head_branch'], run['event'], run['path']) != (
            revision, BRANCH, 'push', WORKFLOW_PATH
        ):
            continue
        if (run['status'], run['conclusion']) != ('completed', 'success'):
            break
        jobs = json.loads(read(f"{API}runs/{int(run['id'])}/jobs?per_page=5"))['jobs']
        if len(jobs) == 1 and jobs[0]['name'] == 'aws' and jobs[0]['conclusion'] == 'success':
            if any(step['name'] == 'Verify the private deployment destination' and step['conclusion'] == 'success'
                   for step in jobs[0]['steps']):
                return int(run['id'])
        break
    raise ValueError('AWS_DELIVERY_GATE_NOT_PASSED_FOR_RELEASE')
