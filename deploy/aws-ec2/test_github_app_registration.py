import http.client
import http.server
import importlib.util
import json
import os
import pathlib
import shutil
import tempfile
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('github_app_registration', pathlib.Path(__file__).with_name('github-app-registration.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = pathlib.Path(tempfile.mkdtemp(prefix='aegisai-app-register-test-'))
        (self.directory / 'shared/scm-keys').mkdir(parents=True)
        (self.directory / 'operator').mkdir()
        self.registration = module.Registration(self.directory)
        self.server = http.server.HTTPServer(('127.0.0.1', 0), module.handler_for(self.registration))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        assert self.directory.resolve().parent == pathlib.Path(tempfile.gettempdir()).resolve()
        assert self.directory.name.startswith('aegisai-app-register-test-')
        shutil.rmtree(self.directory)

    def request(self, path, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request('GET', path, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def test_private_manifest_has_no_write_permissions_webhooks_or_login_grant(self):
        manifest = self.registration.manifest()
        self.assertFalse(manifest['public'])
        self.assertFalse(manifest['request_oauth_on_install'])
        self.assertFalse(manifest['hook_attributes']['active'])
        self.assertEqual(manifest['default_events'], [])
        self.assertEqual(manifest['default_permissions'], {'contents': 'read', 'metadata': 'read', 'members': 'read'})
        self.assertTrue(manifest['redirect_url'].startswith(module.ORIGIN + module.BASE))

    def test_requires_secret_path_and_protects_browser_response(self):
        self.assertEqual(self.request('/wrong')[0], 404)
        status, headers, body = self.request(module.BASE + '/' + self.registration.nonce)
        self.assertEqual(status, 200)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertIn('Secure; HttpOnly; SameSite=Lax', headers['Set-Cookie'])
        self.assertIn('https://github.com/organizations/AigisAI/settings/apps/new?state=', body)
        self.assertNotIn('PRIVATE KEY', body)

    def test_callback_requires_cookie_state_and_single_use_code(self):
        path = module.BASE + '/' + self.registration.nonce + '/callback?code=' + 'a' * 40 + '&state=' + self.registration.nonce
        with mock.patch.object(self.registration, 'convert') as convert:
            self.assertEqual(self.request(path)[0], 503)
            self.assertEqual(self.request(path.replace('state=', 'wrong='), {'Cookie': 'github_ops=' + self.registration.nonce})[0], 503)
            convert.assert_not_called()
        self.registration.used = True
        with self.assertRaises(ValueError):
            self.registration.convert('a' * 40)

    def test_rejects_other_owners_and_broader_permission_grants(self):
        base = {'id': 7, 'slug': 'aegisai-test', 'owner': {'id': module.OWNER_ID, 'type': module.OWNER_TYPE},
                'permissions': {'contents': 'read', 'metadata': 'read', 'members': 'read'}, 'events': []}
        for changes in [{'owner': {'id': 1, 'type': module.OWNER_TYPE}},
                        {'permissions': {'contents': 'write', 'metadata': 'read'}}, {'events': ['push']}]:
            with self.assertRaises(AssertionError):
                module.validate_app({**base, **changes})

    def test_stores_key_once_without_retaining_oauth_secret_or_rendering_key(self):
        app = {'id': 7, 'slug': 'aegisai-test', 'permissions': {'contents': 'read', 'metadata': 'read', 'members': 'read'},
               'client_secret': 'must-not-retain', 'pem': 'test-only-private-material'}
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(app).encode()
        with mock.patch.object(module.urllib.request, 'urlopen', return_value=response), \
                mock.patch.object(module, 'validate_app', return_value=app['pem']):
            self.registration.convert('a' * 40)
        key = self.directory / 'shared/scm-keys/github-app-org.pem'
        self.assertEqual(key.read_text(), 'test-only-private-material')
        if os.name == 'posix':
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        metadata = (self.directory / 'operator/github-app-org-registration.json').read_text()
        self.assertNotIn('must-not-retain', metadata)
        self.assertNotIn('private-material', metadata)
        _, _, body = self.request(module.BASE + '/' + self.registration.nonce)
        self.assertIn('/aegisai-test/installations/new', body)
        self.assertNotIn('private-material', body)
        self.assertNotIn('must-not-retain', body)


if __name__ == '__main__':
    unittest.main()
