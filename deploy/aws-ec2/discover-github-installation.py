"""Operator preflight: verify real organization installation; never logs tokens."""
import base64
import json
import os
import pathlib
import subprocess
import time
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


opener = urllib.request.build_opener(NoRedirect())
os.umask(0o077)
root = pathlib.Path('/opt/aegisai')
app = json.loads((root / 'operator/github-app-org-registration.json').read_text())
assert app['ownerId'] == 241095585 and app['permissions'] == {'metadata': 'read', 'contents': 'read', 'members': 'read'}


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


now = int(time.time())
body = encode(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode()) + '.' + encode(json.dumps({
    'iss': str(app['id']), 'iat': now - 60, 'exp': now + 540
}).encode())
signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign',
    str(root / 'shared/scm-keys/github-app-org.pem')], input=body.encode())
jwt = body + '.' + encode(signature)


def call(path, token, method='GET', data=None):
    request = urllib.request.Request('https://api.github.com' + path,
        data=json.dumps(data).encode() if data is not None else None, method=method,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json', 'User-Agent': 'AegisAI', 'X-GitHub-Api-Version': '2026-03-10'})
    with opener.open(request, timeout=15) as response:
        if response.status == 204:
            return None
        raw = response.read(1024 * 1024 + 1)
        assert len(raw) <= 1024 * 1024
        return json.loads(raw)


installations = call('/app/installations?per_page=100', jwt)
eligible = [item for item in installations if item['app_id'] == app['id']
            and item['account']['id'] == app['ownerId'] and item['account']['type'] == 'Organization'
            and item['suspended_at'] is None]
assert len(eligible) == 1, 'Exactly one active AigisAI installation is required'
installation = eligible[0]
issued = call('/app/installations/' + str(installation['id']) + '/access_tokens', jwt, 'POST',
              {'permissions': {'metadata': 'read', 'members': 'read'}})
token = issued['token']
try:
    assert issued['permissions'] == {'metadata': 'read', 'members': 'read'}
    identity = call('/user/161540124', token)
    assert identity['id'] == 161540124 and identity['login'] == 'goodtu02'
    membership = call('/orgs/AigisAI/memberships/goodtu02', token)
    assert membership['role'] == 'admin' and membership['state'] == 'active'
    assert membership['user']['id'] == 161540124 and membership['organization']['id'] == 241095585
    listed = call('/installation/repositories?per_page=100&page=1', token)
    assert 0 < listed['total_count'] <= 100 and len(listed['repositories']) == listed['total_count']
    report = {'appId': app['id'], 'installationId': installation['id'], 'organizationId': 241095585,
              'verifiedAdministratorId': 161540124, 'repositories': [
                  {'id': repo['id'], 'fullName': repo['full_name']} for repo in listed['repositories']]}
finally:
    call('/installation/token', token, 'DELETE')
report['discoveryTokenRevoked'] = True
(root / 'operator/github-live-installation.json').write_text(json.dumps(report, indent=2))
(root / 'operator/github-live-installation.json').chmod(0o600)
print(json.dumps(report))
