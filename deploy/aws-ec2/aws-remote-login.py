"""Short-lived tailnet-only handoff for official AWS CLI cross-device login.

No request or subprocess output is logged. Authorization codes stay in memory;
temporary AWS credentials are cached only in the root-owned operator directory.
Run independently from the application; this is never a user-facing product flow.
"""
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
import threading
import time
import urllib.parse

ORIGIN = 'https://aegisai-aws.tailaca7d2.ts.net'
BASE = '/ops/aws-login'
IMAGE = 'public.ecr.aws/aws-cli/aws-cli@sha256:0cea63506f28774b70b1a3dd1934f49bc202d9784dee23370acc81438e8d0292'


def valid_authorization_url(value):
    try:
        parsed = urllib.parse.urlparse(value)
        endpoint = (parsed.hostname, parsed.path)
        return (parsed.scheme == 'https' and endpoint in (
            ('ap-northeast-2.signin.amazonaws.com', '/authorize'),
            ('signin.ap-northeast-2.amazonaws.com', '/authorize'),
            ('ap-northeast-2.signin.aws.amazon.com', '/v1/authorize')
        ) and parsed.port in (None, 443) and not parsed.username and not parsed.password
            and not parsed.fragment)
    except ValueError:
        return False


def valid_code(value):
    return 16 <= len(value) <= 4096 and all(33 <= ord(character) <= 126 for character in value)


class LoginSession:
    def __init__(self, directory):
        self.directory = directory
        self.nonce = secrets.token_urlsafe(32)
        self.deadline = time.monotonic() + 900
        self.url = None
        self.status = 'starting'
        self.submitted = False
        self.lock = threading.Lock()
        self.container = 'aegisai-aws-login-' + secrets.token_hex(8)
        self.process = None

    def start(self):
        self.process = subprocess.Popen([
            'docker', 'run', '--rm', '-i', '--name', self.container,
            '--log-driver', 'none', '--ulimit', 'core=0',
            '--memory=256m', '--cpus=0.5',
            '-v', str(self.directory / 'aws') + ':/root/.aws',
            '-e', 'AWS_CLI_AUTO_PROMPT=off', '-e', 'AWS_PAGER=', IMAGE,
            'login', '--remote', '--region', 'ap-northeast-2', '--profile', 'aegisai-deploy'
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        threading.Thread(target=self.read_output, daemon=True).start()

    def read_output(self):
        for line in self.process.stdout:
            if len(line) > 8192:
                continue
            for value in re.findall(r'https://[^\s]+', line):
                if valid_authorization_url(value):
                    with self.lock:
                        self.url = value
                        self.status = 'awaiting_authorization'
        result = self.process.wait()
        with self.lock:
            self.status = 'connected' if result == 0 else 'failed'

    def submit(self, code):
        with self.lock:
            if (time.monotonic() >= self.deadline or self.status != 'awaiting_authorization'
                    or self.submitted or not valid_code(code)):
                return False
            self.submitted = True
            self.status = 'verifying'
            try:
                self.process.stdin.write(code + '\n')
                self.process.stdin.flush()
            except (OSError, BrokenPipeError):
                self.status = 'failed'
                return False
            return True

    def close(self):
        if self.process:
            subprocess.run(['docker', 'stop', '--time', '2', self.container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


def handler_for(session):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def permitted_path(self):
            return self.path in ('/' + session.nonce, BASE + '/' + session.nonce)

        def respond(self, status, content, cookie=False):
            body = content.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if cookie:
                self.send_header('Set-Cookie', 'aws_ops=' + session.nonce + '; Secure; HttpOnly; SameSite=Strict; Path=' + BASE + '; Max-Age=900')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.permitted_path() or time.monotonic() >= session.deadline:
                return self.respond(404, 'Not found')
            with session.lock:
                status, url = session.status, session.url
            if status == 'awaiting_authorization' and not session.submitted:
                content = '<a target="_blank" rel="noopener noreferrer" href="' + html.escape(url, quote=True) + '">1. AWS 공식 로그인 열기</a>'
                content += '<p>AWS에서 표시한 인증 코드를 아래에 붙여 넣으세요. 비밀번호나 코드를 채팅으로 보내지 마세요.</p>'
                content += '<form method="post"><input name="csrf" type="hidden" value="' + session.nonce + '"><label>2. 인증 코드 <input name="code" required autocomplete="off" maxlength="4096"></label><button>연결</button></form>'
            else:
                messages = {'starting': 'AWS 로그인 준비 중입니다. 잠시 뒤 새로고침하세요.',
                            'verifying': '확인 중입니다. 잠시 뒤 새로고침하세요.',
                            'connected': 'AWS 임시 인증 연결이 완료됐습니다. 이 창을 닫아도 됩니다.',
                            'failed': 'AWS 인증이 완료되지 않았습니다. 담당 에이전트에게 실패했다고 알려주세요.'}
                content = '<p>' + messages.get(status, '대기 중') + '</p>'
            self.respond(200, '<!doctype html><html lang="ko"><meta name="viewport" content="width=device-width"><title>AegisAI AWS 인증</title><style>body{max-width:38rem;margin:3rem auto;padding:1rem;font:18px sans-serif;line-height:1.7}input{display:block;width:95%;padding:.7rem;margin:1rem 0}button,a{font-size:1rem;padding:.7rem}</style><h1>AWS 임시 인증 연결</h1><p>기존 IAM 계정으로 로그인합니다. AWS의 권한 승인 내용을 확인한 뒤 진행하세요. 임시 세션은 이 서버의 배포 작업에 사용됩니다.</p>' + content + '</html>', cookie=True)

        def do_POST(self):
            if not self.permitted_path() or self.headers.get('Origin') != ORIGIN:
                return self.respond(403, 'Forbidden')
            cookie = http.cookies.SimpleCookie()
            try:
                cookie.load(self.headers.get('Cookie', ''))
                length = int(self.headers.get('Content-Length', '0'))
            except (ValueError, http.cookies.CookieError):
                return self.respond(400, 'Invalid request')
            if (not cookie.get('aws_ops') or cookie['aws_ops'].value != session.nonce
                    or not 0 < length <= 16384
                    or self.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded'):
                return self.respond(403, 'Forbidden')
            self.connection.settimeout(5)
            try:
                form = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'), strict_parsing=True, max_num_fields=2)
            except (ValueError, UnicodeError, OSError):
                return self.respond(400, 'Invalid request')
            if set(form) != {'code', 'csrf'} or form['csrf'] != [session.nonce] or len(form['code']) != 1:
                return self.respond(403, 'Forbidden')
            if not session.submit(form['code'][0].strip()):
                return self.respond(409, '이미 제출됐거나 만료된 요청입니다.')
            return self.respond(200, '인증 확인 중입니다. 잠시 후 이 페이지를 새로고침하세요.')

    return Handler


def main():
    os.umask(0o077)
    directory = pathlib.Path('/opt/aegisai/operator')
    (directory / 'aws').mkdir(mode=0o700, parents=True, exist_ok=True)
    session = LoginSession(directory)
    signal.signal(signal.SIGTERM, lambda *_: setattr(session, 'deadline', 0))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 8766), handler_for(session))
    server.daemon_threads = True
    server.timeout = 1
    session.start()
    metadata = directory / 'aws-login-session.json'
    metadata.write_text(json.dumps({'url': ORIGIN + BASE + '/' + session.nonce, 'expiresSeconds': 900}))
    try:
        while time.monotonic() < session.deadline:
            server.handle_request()
    finally:
        server.server_close()
        session.close()


if __name__ == '__main__':
    main()
