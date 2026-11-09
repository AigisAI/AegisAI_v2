"""Ephemeral operator-only GitHub App manifest flow; never log callback codes/keys."""
import html
import http.cookies
import http.server
import json
import os
import pathlib
import re
import secrets
import signal
import subprocess
import time
import urllib.parse
import urllib.request

ORIGIN = 'https://aegisai-aws.tailaca7d2.ts.net'
BASE = '/ops/github-app'
OWNER_ID = 241095585
OWNER_LOGIN = 'AigisAI'
OWNER_TYPE = 'Organization'
PERMISSIONS = {'contents': 'read', 'metadata': 'read', 'members': 'read'}


def validate_app(app):
    assert isinstance(app.get('id'), int) and app['id'] > 0
    assert app.get('owner', {}).get('id') == OWNER_ID
    assert app['owner'].get('type') == OWNER_TYPE
    assert re.fullmatch(r'[a-z0-9][a-z0-9-]{0,99}', app.get('slug', ''))
    assert app.get('permissions') == PERMISSIONS
    assert not app.get('events')
    pem = app.get('pem', '')
    assert isinstance(pem, str) and len(pem) <= 16384 and 'PRIVATE KEY' in pem
    result = subprocess.run(['openssl', 'pkey', '-check', '-noout'], input=pem.encode(),
                            capture_output=True, timeout=5)
    assert result.returncode == 0
    return pem


class Registration:
    def __init__(self, root):
        self.root = root
        self.nonce = secrets.token_urlsafe(32)
        self.deadline = time.monotonic() + 1800
        self.used = False
        self.app = None

    def manifest(self):
        return {
            'name': 'aegisai-aigisai-runtime-' + secrets.token_hex(3),
            'url': ORIGIN,
            'redirect_url': ORIGIN + BASE + '/' + self.nonce + '/callback',
            'public': False, 'request_oauth_on_install': False,
            'hook_attributes': {'url': ORIGIN + '/api/webhooks/github', 'active': False},
            'default_permissions': PERMISSIONS,
            'default_events': [],
            'description': 'Private AigisAI organization repository reading and administrator verification. No write permission.'
        }

    def convert(self, code):
        if self.used or not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', code):
            raise ValueError('Invalid or reused registration callback')
        self.used = True
        request = urllib.request.Request('https://api.github.com/app-manifests/' + code + '/conversions',
            data=b'{}', headers={'Accept': 'application/vnd.github+json', 'Content-Type': 'application/json',
                                 'User-Agent': 'AegisAI', 'X-GitHub-Api-Version': '2026-03-10'})
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(65537)
            assert len(raw) <= 65536
            app = json.loads(raw)
        pem = validate_app(app)
        key = self.root / 'shared/scm-keys/github-app-org.pem'
        fd = os.open(str(key), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(pem)
        self.app = {name: app[name] for name in ('id', 'slug')}
        self.app['ownerId'] = OWNER_ID
        self.app['permissions'] = app['permissions']
        self.app['webhooksEnabled'] = False
        metadata = self.root / 'operator/github-app-org-registration.json'
        fd = os.open(str(metadata), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(self.app, stream)
        # OAuth client/webhook secrets returned by the manifest are not used or retained.


def handler_for(registration):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status, body):
            data = ('<!doctype html><html lang="ko"><meta name="viewport" content="width=device-width"><title>AegisAI GitHub 연결</title><style>body{max-width:40rem;margin:2rem auto;padding:1rem;font:18px sans-serif;line-height:1.7}button,a{font-size:1rem;padding:.7rem}</style>' + body + '</html>').encode()
            self.send_response(status)
            for key, value in {
                'Content-Type': 'text/html; charset=utf-8', 'Content-Length': str(len(data)),
                'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
                'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com; frame-ancestors 'none'; base-uri 'none'",
                'Set-Cookie': 'github_ops=' + registration.nonce + '; Secure; HttpOnly; SameSite=Lax; Path=' + BASE + '; Max-Age=1800'
            }.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            valid_roots = ('/' + registration.nonce, BASE + '/' + registration.nonce)
            if time.monotonic() >= registration.deadline or not any(path in (root, root + '/callback') for root in valid_roots):
                return self.respond(404, 'Not found')
            if path.endswith('/callback'):
                try:
                    cookie = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
                    query = urllib.parse.parse_qs(parsed.query, strict_parsing=True, max_num_fields=3)
                    assert cookie.get('github_ops') and cookie['github_ops'].value == registration.nonce
                    assert query.get('state') == [registration.nonce] and len(query.get('code', [])) == 1
                    registration.convert(query['code'][0])
                except Exception:
                    # Never render exception text: provider exceptions may contain callback URLs.
                    return self.respond(503, '<h1>등록 확인 실패</h1><p>실패했다고 에이전트에게 알려주세요. 키나 코드를 보내지 마세요.</p>')
            if registration.app:
                url = 'https://github.com/apps/' + registration.app['slug'] + '/installations/new'
                return self.respond(200, '<h1>App 등록·키 저장 완료</h1><p>다음 단계에서 Only select repositories를 선택하고, AigisAI 조직을 선택하고 검증할 조직 저장소만 선택해 설치하세요.</p><a rel="noreferrer" href="' + html.escape(url, quote=True) + '">선택 저장소에 설치</a>')
            manifest = html.escape(json.dumps(registration.manifest()), quote=True)
            return self.respond(200, '<h1>GitHub 저장소 연동 등록</h1><p>goodtu02 계정으로 진행하세요. AigisAI 조직 소유의 비공개 GitHub App을 만들며 Contents·Metadata·조직 Members 읽기 권한만 요청합니다. Members는 로그인 사용자의 조직 관리자 자격 검증에 사용합니다. 쓰기·관리 권한은 없습니다. Webhook은 비활성입니다. 로그인 OAuth 설정과는 별개입니다.</p><p>GitHub 공식 화면에서 권한을 확인하고 Create GitHub App을 승인하면 키가 이 서버에 자동 저장됩니다. 키를 내려받거나 채팅에 보낼 필요가 없습니다.</p><form method="post" action="https://github.com/organizations/AigisAI/settings/apps/new?state=' + registration.nonce + '"><input type="hidden" name="manifest" value="' + manifest + '"><button>GitHub 공식 등록 화면 열기</button></form>')
    return Handler


def main():
    os.umask(0o077)
    root = pathlib.Path('/opt/aegisai')
    assert not (root / 'shared/scm-keys/github-app-org.pem').exists(), 'Organization signing key already exists; reuse it'
    registration = Registration(root)
    signal.signal(signal.SIGTERM, lambda *_: setattr(registration, 'deadline', 0))
    server = http.server.HTTPServer(('127.0.0.1', 8767), handler_for(registration))
    server.timeout = 1
    (root / 'operator/github-app-org-session.json').write_text(json.dumps({
        'url': ORIGIN + BASE + '/' + registration.nonce, 'expiresSeconds': 1800
    }))
    try:
        while time.monotonic() < registration.deadline:
            server.handle_request()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
