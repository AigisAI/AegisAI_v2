"""Expose only private login verification; all product routes remain gated."""
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time
import urllib.error
import urllib.request

os.umask(0o077)
root = pathlib.Path('/opt/aegisai')
release = (root / 'shared/candidate-release').read_text().strip()
assert re.fullmatch(r'ec2-runtime-\d{8}-\d{6}', release)
for component in ('api', 'web'):
    container = json.loads(subprocess.check_output(['docker', 'inspect', 'aegisai-ec2-demo-' + component + '-1']))[0]
    assert container['Config']['Image'] == 'aegisai-' + component + ':' + release
    assert container['State']['Health']['Status'] == 'healthy'
web_config = subprocess.check_output(['docker', 'exec', 'aegisai-ec2-demo-web-1',
                                     'cat', '/etc/nginx/conf.d/default.conf'], text=True)
assert 'log_format aegisai_api' in web_config and '"path":"$uri"' in web_config
api_env = dict(value.split('=', 1) for value in json.loads(subprocess.check_output(
    ['docker', 'inspect', 'aegisai-ec2-demo-api-1']))[0]['Config']['Env'] if '=' in value)
assert api_env['ALLOWED_GITHUB_USER_IDS'] == '161540124' and api_env['GITHUB_LOGIN_KIND'] == 'github-app'
network = 'aegisai-ec2-demo_default'
settings = json.loads(subprocess.check_output(['docker', 'inspect', 'aegisai-ingress']))[0]['NetworkSettings']['Networks']
if network not in settings:
    subprocess.run(['docker', 'network', 'connect', network, 'aegisai-ingress'], check=True)
source = root / 'releases' / release / 'deploy/aws-ec2/ingress-pending.conf'
content = source.read_text()
script = re.search(r'<script>(.*?)</script>', content).group(1)
digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
policy = "default-src 'none'; script-src 'sha256-" + digest + "'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
content = content.replace('    default_type text/html;',
    '    default_type text/html;\n    charset utf-8;\n    add_header Content-Security-Policy "' + policy + '" always;')
destination = root / 'shared/ingress-pending.conf'
old = destination.read_text()
(root / 'shared' / ('ingress.before-auth-' + str(time.time_ns()) + '.conf')).write_text(old)
try:
    # Preserve the inode of the file mounted read-only into the proxy container.
    destination.write_text(content)
    subprocess.run(['docker', 'exec', 'aegisai-ingress', 'nginx', '-t'], check=True)
    subprocess.run(['docker', 'exec', 'aegisai-ingress', 'nginx', '-s', 'reload'], check=True)
except Exception:
    destination.write_text(old)
    subprocess.run(['docker', 'exec', 'aegisai-ingress', 'nginx', '-s', 'reload'], check=False)
    raise
print(json.dumps({'privateAuthenticationPreflight': 'enabled', 'applicationIngressPromoted': False,
                  'entrypoint': 'https://aegisai-aws.tailaca7d2.ts.net/auth-check'}))
