"""One-time 15 minute tailnet-only Slack webhook handoff. No request logging."""
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import time
import urllib.parse

from slack_alerts import ROOT, private_json, send, valid_webhook

ORIGIN = 'https://aegisai-aws.tailaca7d2.ts.net'
BASE = '/ops/slack-setup'


class Session:
    def __init__(self, root=ROOT):
        self.root = root
        self.nonce = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.deadline = time.monotonic() + 900
        self.done = False
        self.attempts = 0
        previous = root/'setup-session.json'
        if previous.exists():
            saved = json.loads(previous.read_text())
            remaining = saved['expiresAt'] - time.time()
            prefix = ORIGIN + BASE + '/'
            candidate = saved['url'][len(prefix):] if saved['url'].startswith(prefix) else ''
            if 0 < remaining <= 900 and len(candidate) == 43 and all(c.isalnum() or c in '-_' for c in candidate):
                self.nonce = candidate
                self.deadline = time.monotonic() + remaining


def handler_for(session):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass

        def respond(self, status, content):
            payload = ('<!doctype html><html lang="ko"><meta name="viewport" content="width=device-width">'
                       '<title>AegisAI Slack 연결</title><style>body{font:18px sans-serif;line-height:1.7;max-width:38rem;margin:2rem auto;padding:1rem}input{width:95%;padding:.7rem}button{padding:1rem;margin-top:1rem}</style>' + content + '</html>').encode()
            self.send_response(status)
            for name, value in {'Content-Type':'text/html; charset=utf-8', 'Cache-Control':'no-store',
                                'Referrer-Policy':'no-referrer', 'X-Content-Type-Options':'nosniff',
                                'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}.items():
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def admitted(self):
            if self.path not in ('/'+session.nonce, BASE+'/'+session.nonce):
                self.respond(404, '주소를 확인해 주세요.')
                return False
            if time.monotonic() >= session.deadline:
                self.respond(410, '연결 시간이 만료됐습니다.')
                return False
            return True

        def do_GET(self):
            if not self.admitted():
                return
            if session.done:
                self.respond(200, '<h1>Slack 연결 완료</h1><p>Slack이 확인 알림을 수락했습니다. 지정한 채널에서 메시지를 확인해 주세요.</p>')
                return
            manifest = {'display_information':{'name':'AegisAI Alerts'},
                        'settings':{'incoming_webhooks':{'incoming_webhooks_enabled':True}},
                        'oauth_config':{'scopes':{'bot':['incoming-webhook']}}}
            link = 'https://api.slack.com/apps?' + urllib.parse.urlencode({'new_app':'1','manifest_json':json.dumps(manifest)})
            self.respond(200, '<h1>Slack 운영 알림 연결</h1><p>기존 Incoming Webhook이 있으면 아래에 붙여 넣어 주세요.</p>'
                         '<ol><li><a rel="noreferrer" target="_blank" href="'+html.escape(link, quote=True)+'">Slack 알림 앱 만들기</a>에서 워크스페이스를 고릅니다.</li>'
                         '<li>Incoming Webhooks → Add New Webhook to Workspace에서 알림 채널을 선택하고 승인합니다.</li>'
                         '<li>생성된 Webhook URL을 복사해 아래에 붙여 넣습니다. 채팅에는 보내지 마세요.</li></ol>'
                         '<form method="post"><input type="hidden" name="csrf" value="'+session.csrf+'">'
                         '<label>Slack Incoming Webhook URL<input name="webhook" type="password" required maxlength="256" autocomplete="off"></label>'
                         '<button>저장 후 확인 알림 보내기</button></form><p>비밀 주소는 서버에만 저장됩니다. 이 화면은 15분 뒤 만료됩니다.</p>')

        def do_POST(self):
            if not self.admitted():
                return
            if session.done:
                self.respond(409, '이미 연결됐습니다.')
                return
            if self.headers.get('Origin') != ORIGIN:
                self.respond(403, '원래 연결 화면에서 진행해 주세요.')
                return
            try:
                length = int(self.headers.get('Content-Length','0'))
                assert 0 < length <= 1024 and not self.headers.get('Transfer-Encoding')
                values = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'), strict_parsing=True, max_num_fields=2)
                assert set(values) == {'csrf','webhook'} and all(len(v)==1 for v in values.values())
                assert secrets.compare_digest(values['csrf'][0], session.csrf)
                value = values['webhook'][0].strip()
                assert valid_webhook(value)
            except (AssertionError, ValueError, UnicodeError):
                self.respond(400, '입력 내용을 확인하고 다시 진행해 주세요.')
                return
            if session.attempts >= 5:
                self.respond(429, '연결 시도 한도에 도달했습니다.')
                return
            session.attempts += 1
            if not send(value, '[AegisAI] Slack 연결 확인: 기존 EC2의 운영 알림을 이 채널로 보냅니다.'):
                self.respond(502, 'Slack 연결에 실패했습니다. Webhook 주소와 채널 승인을 확인해 주세요.')
                return
            private_json(session.root/'webhook.json', {'webhook':value})
            private_json(session.root/'connection-proof.json', {'slackTestAccepted':True,'verifiedAt':int(time.time())})
            session.done = True
            self.do_GET()
    return Handler


def main():
    assert os.geteuid() == 0
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    session = Session()
    private_json(ROOT/'setup-session.json', {'url':ORIGIN+BASE+'/'+session.nonce,'expiresAt':int(time.time() + session.deadline - time.monotonic())})
    server = HTTPServer(('127.0.0.1',8768), handler_for(session))
    server.timeout = 1
    try:
        while time.monotonic() < session.deadline:
            server.handle_request()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
