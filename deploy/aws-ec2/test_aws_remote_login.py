import http.client
import http.server
import importlib.util
import io
import pathlib
import threading
import types
import unittest
import urllib.parse

spec = importlib.util.spec_from_file_location('aws_remote_login', pathlib.Path(__file__).with_name('aws-remote-login.py'))
login = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login)


class RemoteLoginBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.session = login.LoginSession(pathlib.Path('/unused-test-path'))
        self.session.url = 'https://ap-northeast-2.signin.amazonaws.com/authorize?client_id=test'
        self.session.status = 'awaiting_authorization'
        self.session.process = types.SimpleNamespace(stdin=io.StringIO())
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), login.handler_for(self.session))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path=None, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, path or login.BASE + '/' + self.session.nonce, body, headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def form(self, **changes):
        values = {'csrf': self.session.nonce, 'code': 'test-authorization-code'}
        values.update(changes)
        return urllib.parse.urlencode(values)

    def headers(self):
        return {'Origin': login.ORIGIN, 'Cookie': 'aws_ops=' + self.session.nonce,
                'Content-Type': 'application/x-www-form-urlencoded'}

    def test_requires_unguessable_path_and_disables_cache_and_embedding(self):
        self.assertEqual(self.request('GET', '/wrong')[0], 404)
        status, headers, body = self.request('GET')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertIn('Secure; HttpOnly; SameSite=Strict', headers['Set-Cookie'])
        self.assertIn('AWS', body)

    def test_rejects_missing_cookie_origin_and_csrf_before_submitting(self):
        self.assertEqual(self.request('POST', body=self.form(), headers={})[0], 403)
        headers = self.headers()
        headers['Origin'] = 'https://other.example'
        self.assertEqual(self.request('POST', body=self.form(), headers=headers)[0], 403)
        self.assertEqual(self.request('POST', body=self.form(csrf='wrong'), headers=self.headers())[0], 403)
        self.assertFalse(self.session.submitted)
        self.assertEqual(self.session.process.stdin.getvalue(), '')

    def test_passes_code_to_cli_once_without_echoing_it(self):
        status, _, body = self.request('POST', body=self.form(), headers=self.headers())
        self.assertEqual(status, 200)
        self.assertNotIn('test-authorization-code', body)
        self.assertEqual(self.session.process.stdin.getvalue(), 'test-authorization-code\n')
        self.assertEqual(self.request('POST', body=self.form(), headers=self.headers())[0], 409)
        self.assertNotIn('test-authorization-code', self.request('GET')[2])

    def test_rejects_expiry_newlines_and_excessive_input(self):
        self.assertEqual(self.request('POST', body=self.form(code='test-code\ninjected-code'), headers=self.headers())[0], 409)
        self.assertEqual(self.request('POST', body=self.form(code='x' * 17000), headers=self.headers())[0], 403)
        self.session.deadline = 0
        self.assertEqual(self.request('GET')[0], 404)
        self.assertEqual(self.request('POST', body=self.form(), headers=self.headers())[0], 409)
        self.assertFalse(self.session.submitted)

    def test_accepts_only_official_aws_regional_authorization_urls(self):
        self.assertTrue(login.valid_authorization_url(self.session.url))
        self.assertTrue(login.valid_authorization_url('https://ap-northeast-2.signin.aws.amazon.com/v1/authorize?test=1'))
        for url in ['http://ap-northeast-2.signin.amazonaws.com/authorize',
                    'https://ap-northeast-2.signin.amazonaws.com@evil.example/authorize',
                    'https://ap-northeast-2.signin.amazonaws.com.evil.example/authorize',
                    'https://ap-northeast-2.signin.amazonaws.com:bad/authorize',
                    'https://ap-northeast-2.signin.amazonaws.com/other']:
            self.assertFalse(login.valid_authorization_url(url))


if __name__ == '__main__':
    unittest.main()
