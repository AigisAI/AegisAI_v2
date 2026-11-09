"""Configuration smoke check only; it does not complete a provider login."""
import json
import urllib.error
import urllib.parse
import urllib.request

from managed_runtime import load_values


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


runtime = load_values()
opener = urllib.request.build_opener(NoRedirect())
request = urllib.request.Request('http://127.0.0.1:8080/api/auth/github',
                                 headers={'X-Forwarded-Proto': 'https'})
try:
    response = opener.open(request, timeout=10)
except urllib.error.HTTPError as error:
    response = error
with response:
    assert response.status == 302, response.status
    target = urllib.parse.urlparse(response.headers['Location'])
    params = urllib.parse.parse_qs(target.query)
    assert target.scheme == 'https' and target.netloc == 'github.com'
    assert target.path == '/login/oauth/authorize'
    assert params['client_id'] == [runtime['GITHUB_CLIENT_ID']]
    assert params['redirect_uri'] == ['https://aegisai-aws.tailaca7d2.ts.net/api/auth/github/callback']
    if runtime.get('GITHUB_LOGIN_KIND') == 'github-app':
        assert 'scope' not in params  # Identity App permissions, not OAuth scopes.
    else:
        assert params['scope'] == ['read:user user:email']
    assert params['code_challenge_method'] == ['S256']
    assert len(params['state'][0]) > 32 and len(params['code_challenge'][0]) == 43
    cookies = response.headers.get_all('Set-Cookie') or []
    assert any('Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=Lax' in cookie for cookie in cookies)
    assert response.headers['Cache-Control'] == 'no-store'
print(json.dumps({'oauthConfiguration': 'passed', 'pkce': 'S256',
                  'cookie': 'secure/httponly/lax', 'loginCompleted': False,
                  'callbackRegistrationVerified': False}))
