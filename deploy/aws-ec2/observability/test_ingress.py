"""Real Nginx fixture on disposable CI only; no production users or credentials."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

IMAGE = 'nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10'


class Stub(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/runtime/observability-auth':
            identity = self.headers.get('Cookie', '')
            status = 204 if identity == 'fixture_owner=valid' else 403 if identity == 'fixture_owner=forbidden' else 500 if identity == 'fixture_owner=error' else 401
            self.send_response(status)
            if status == 204:
                self.send_header('X-AegisAI-User', 'github-fixture')
                self.send_header('X-AegisAI-Role', 'Viewer')
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'path':self.path, 'user':self.headers.get('X-WEBAUTH-USER'),
                'role':self.headers.get('X-WEBAUTH-ROLE'), 'cookie':self.headers.get('Cookie'),
                'authorization':self.headers.get('Authorization')}).encode())

    def log_message(self, *_):
        pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Run only in disposable hosted CI'
    name = 'aegisai-auth-fixture-' + secrets.token_hex(6)
    network = name + '-net'
    server = None
    subprocess.run(['docker','network','create','--internal',network],check=True,stdout=subprocess.DEVNULL)
    try:
        metadata = json.loads(subprocess.check_output(['docker','network','inspect',network]))[0]
        gateway = metadata['IPAM']['Config'][0]['Gateway']
        server = ThreadingHTTPServer((gateway,0),Stub)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever,daemon=True).start()
        stub = f'http://{gateway}:{server.server_port}'
        here = Path(__file__).resolve().parent
        config = (here.parent/'ingress-production.conf').read_text()
        locations = (here/'ingress.locations.conf').read_text()
        config = config.replace('  location /ops/ { return 404; }',locations+'\n  location /ops/ { return 404; }')
        config = config.replace('http://aegisai-ec2-demo-web-1:80',stub).replace('http://aegisai-observability-grafana-1:3000',stub)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'default.conf'
            path.write_text(config)
            subprocess.run(['docker','run','-d','--name',name,'--network',network,
                '-p','127.0.0.1::80','--read-only','--cap-drop=ALL','--cap-add=NET_BIND_SERVICE',
                '--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN',
                '--security-opt=no-new-privileges','--memory=64m','--pids-limit=32',
                '--tmpfs','/var/cache/nginx','--tmpfs','/var/run',
                '-v',str(path)+':/etc/nginx/conf.d/default.conf:ro',
                '--entrypoint','/usr/sbin/nginx',IMAGE,'-g','daemon off;'],check=True,stdout=subprocess.DEVNULL)
            address = subprocess.check_output(['docker','port',name,'80/tcp'],text=True).strip()
            origin = 'http://' + address
            def request(route, headers=None):
                try:
                    response = urllib.request.build_opener(NoRedirect()).open(urllib.request.Request(origin+route,headers=headers or {}),timeout=3)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    return response.status, response.headers, response.read()
            for _ in range(30):
                try:
                    if request('/')[0] == 200:
                        break
                except (OSError,urllib.error.URLError):
                    time.sleep(.2)
            for headers in ({}, {'Cookie':'fixture_owner=expired'}, {'X-WEBAUTH-USER':'forged','X-WEBAUTH-ROLE':'Admin'}):
                status, response, _ = request('/ops/grafana/api/search',headers)
                assert status == 302 and response.get('Location','').endswith('/api/auth/github')
            assert request('/ops/grafana/api/search',{'Cookie':'fixture_owner=forbidden'})[0] == 403
            assert request('/ops/grafana/api/search',{'Cookie':'fixture_owner=error'})[0] == 500
            status, _, body = request('/ops/grafana/api/search',{'Cookie':'fixture_owner=valid',
                'X-WEBAUTH-USER':'forged','X-WEBAUTH-ROLE':'Admin','Authorization':'fixture-secret'})
            received = json.loads(body)
            assert status == 200 and received['user'] == 'github-fixture' and received['role'] == 'Viewer'
            assert received['cookie'] is None and received['authorization'] is None
            assert request('/_grafana_auth')[0] == 404
            assert request('/api/runtime/observability-auth')[0] == 404
            assert request('/ops/aws-login/expired')[0] == 404
            print('NGINX_AUTH_REQUEST_FIXTURE_PASSED: deny, redirect, admitted viewer, header overwrite, credential stripping')
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        if server:
            server.shutdown()
            server.server_close()
        subprocess.run(['docker','network','rm',network],check=True,stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
