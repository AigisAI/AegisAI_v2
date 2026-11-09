"""Separate identity-only GitHub App. SCM signing keys/permissions are not reused."""
import html
import http.cookies
import http.server
import importlib.util
import json
import os
import pathlib
import re
import secrets
import signal
import time
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location('registration_base', pathlib.Path(__file__).with_name('github-app-registration.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
base.BASE = '/ops/github-login'
ORIGIN, BASE = base.ORIGIN, base.BASE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def validated_login(app):
    assert isinstance(app.get('id'), int) and app['id'] > 0
    assert app.get('owner', {}).get('id') == 161540124 and app['owner'].get('type') == 'User'
    permissions = app.get('permissions', {})
    assert permissions.get('emails') == 'read'
    assert set(permissions) <= {'emails', 'metadata'} and set(permissions.values()) == {'read'}
    assert not app.get('events')
    assert re.fullmatch(r'[a-z0-9][a-z0-9-]{0,99}', app.get('slug', ''))
    assert re.fullmatch(r'[A-Za-z0-9_.-]{10,100}', app.get('client_id', ''))
    secret = app.get('client_secret', '')
    assert isinstance(secret, str) and 32 <= len(secret) <= 128 and all(33 <= ord(c) <= 126 for c in secret)
    return {'GITHUB_CLIENT_ID': app['client_id'], 'GITHUB_CLIENT_SECRET': secret, 'GITHUB_LOGIN_KIND': 'github-app'}


class LoginRegistration(base.Registration):
    def manifest(self):
        return {'name': 'aegisai-user-login-' + secrets.token_hex(3), 'url': ORIGIN,
            'redirect_url': ORIGIN + BASE + '/' + self.nonce + '/callback',
            'callback_urls': [ORIGIN + '/api/auth/github/callback'], 'public': False,
            'request_oauth_on_install': False,
            'hook_attributes': {'url': ORIGIN + '/api/webhooks/identity-unused', 'active': False},
            'default_permissions': {'emails': 'read'}, 'default_events': [],
            'description': 'AegisAI user login only. Email read permission; no repository content, organization membership or write authority. No installation required.'}

    def convert(self, code):
        if self.used or not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', code):
            raise ValueError('Invalid or reused callback')
        self.used = True
        request = urllib.request.Request('https://api.github.com/app-manifests/' + code + '/conversions', data=b'{}',
            headers={'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                     'User-Agent': 'AegisAI', 'X-GitHub-Api-Version': '2026-03-10'})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(65537)
            assert len(raw) <= 65536
            app = json.loads(raw)
        values = validated_login(app)
        path = self.root / 'shared/login-client.pending.json'
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(values, stream)
        self.app = {'id': app['id'], 'slug': app['slug'], 'permissions': app['permissions'], 'ownerId': 161540124}
        path = self.root / 'operator/github-login-registration.json'
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(self.app, stream)
        # Do not retain the identity App's signing key or unused webhook secret.


def handler_for(registration):
    Parent = base.handler_for(registration)

    class Handler(Parent):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            roots = ('/' + registration.nonce, BASE + '/' + registration.nonce)
            if time.monotonic() >= registration.deadline or not any(parsed.path in (root, root + '/callback') for root in roots):
                return self.respond(404, 'Not found')
            if parsed.path.endswith('/callback'):
                try:
                    cookie = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
                    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True, max_num_fields=3)
                    assert cookie.get('github_ops') and cookie['github_ops'].value == registration.nonce
                    assert query.get('state') == [registration.nonce] and len(query.get('code', [])) == 1
                    registration.convert(query['code'][0])
                except Exception:
                    return self.respond(503, '<h1>등록 확인 실패</h1><p>실패했다고 알려주세요. 코드나 키를 채팅에 보내지 마세요.</p>')
            if registration.app:
                return self.respond(200, '<h1>로그인 앱 등록 완료</h1><p>로그인 설정이 서버에 자동 저장됐습니다. 이 앱은 저장소에 설치할 필요가 없습니다. 에이전트에게 완료했다고 알려주세요.</p>')
            manifest = html.escape(json.dumps(registration.manifest()), quote=True)
            return self.respond(200, '<h1>AWS 전용 GitHub 로그인 앱</h1><p>goodtu02 개인 계정으로 로그인 전용 비공개 앱을 만듭니다. 이메일 읽기만 요청하며 저장소 내용·조직 구성원·쓰기 권한은 요청하지 않습니다. 저장소용 조직 App과 별개입니다.</p><p>GitHub 공식 화면에서 Create GitHub App을 승인하면 로그인용 ID와 비밀 값은 서버에 자동 저장됩니다. 설치나 키 복사는 필요 없습니다.</p><form method="post" action="https://github.com/settings/apps/new?state=' + registration.nonce + '"><input type="hidden" name="manifest" value="' + manifest + '"><button>GitHub 공식 등록 화면 열기</button></form>')
    return Handler


def main():
    os.umask(0o077)
    root = pathlib.Path('/opt/aegisai')
    assert not (root / 'shared/login-client.pending.json').exists(), 'Identity client already staged; reuse it'
    registration = LoginRegistration(root)
    signal.signal(signal.SIGTERM, lambda *_: setattr(registration, 'deadline', 0))
    server = http.server.HTTPServer(('127.0.0.1', 8769), handler_for(registration))
    server.timeout = 1
    (root / 'operator/github-login-session.json').write_text(json.dumps({
        'url': ORIGIN + BASE + '/' + registration.nonce, 'expiresSeconds': 1800
    }))
    try:
        while time.monotonic() < registration.deadline:
            server.handle_request()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
