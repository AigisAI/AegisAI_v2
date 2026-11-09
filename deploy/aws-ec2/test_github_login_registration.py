import importlib.util
import json
import os
import pathlib
import shutil
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('login_registration', pathlib.Path(__file__).with_name('github-login-registration.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class IdentityRegistrationTests(unittest.TestCase):
    def payload(self):
        return {'id': 8, 'slug': 'aegisai-user-login-test', 'owner': {'id': 161540124, 'type': 'User'},
                'permissions': {'emails': 'read', 'metadata': 'read'}, 'events': [],
                'client_id': 'test-identity-client-id', 'client_secret': 'x' * 40,
                'pem': 'must-not-retain-signing-key', 'webhook_secret': 'must-not-retain-webhook'}

    def test_identity_manifest_has_email_only_and_correct_callback(self):
        manifest = module.LoginRegistration(pathlib.Path('/unused')).manifest()
        self.assertEqual(manifest['default_permissions'], {'emails': 'read'})
        self.assertEqual(manifest['callback_urls'], [module.ORIGIN + '/api/auth/github/callback'])
        self.assertFalse(manifest['request_oauth_on_install'])
        self.assertFalse(manifest['public'])
        self.assertEqual(manifest['default_events'], [])

    def test_rejects_unexpected_owner_and_repository_authority(self):
        for changes in [{'owner': {'id': 241095585, 'type': 'Organization'}},
                        {'permissions': {'emails': 'write'}},
                        {'permissions': {'emails': 'read', 'contents': 'read'}},
                        {'permissions': {'emails': 'read', 'members': 'read'}}, {'events': ['push']}]:
            with self.assertRaises(AssertionError):
                module.validated_login({**self.payload(), **changes})

    def test_retains_only_the_separate_login_client_and_never_the_signing_key(self):
        directory = pathlib.Path(tempfile.mkdtemp(prefix='aegisai-login-register-test-'))
        try:
            (directory / 'shared').mkdir()
            (directory / 'operator').mkdir()
            registration = module.LoginRegistration(directory)
            response = mock.MagicMock()
            response.__enter__.return_value.read.return_value = json.dumps(self.payload()).encode()
            opener = mock.MagicMock()
            opener.open.return_value = response
            with mock.patch.object(module.urllib.request, 'build_opener', return_value=opener):
                registration.convert('a' * 40)
            path = directory / 'shared/login-client.pending.json'
            saved = json.loads(path.read_text())
            self.assertEqual(set(saved), {'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITHUB_LOGIN_KIND'})
            self.assertEqual(saved['GITHUB_LOGIN_KIND'], 'github-app')
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for file in directory.rglob('*'):
                if file.is_file():
                    self.assertNotIn('must-not-retain', file.read_text())
            self.assertNotIn('client_secret', json.dumps(registration.app))
        finally:
            assert directory.resolve().parent == pathlib.Path(tempfile.gettempdir()).resolve()
            assert directory.name.startswith('aegisai-login-register-test-')
            shutil.rmtree(directory)


if __name__ == '__main__':
    unittest.main()
