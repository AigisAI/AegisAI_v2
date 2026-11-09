"""Trusted operator tests: temporary files and fake secrets only, no production DB."""
import copy
import json
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import managed_runtime as runtime


@unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Requires Linux root permission checks')
class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='aegisai-credential-test-')
        self.root = pathlib.Path(self.temporary.name)
        self.ids = {scope: 'arn:aws:secretsmanager:ap-northeast-2:024139495514:secret:aegisai/private-runtime/' + scope + '-test01'
                    for scope in ('auth', 'scm')}
        self.auth = {'DATABASE_URL': 'postgresql://aegisai:test-only-database-password@postgres:5432/aegisai',
                     'SESSION_SECRET': 'test-only-session-value', 'GITHUB_CLIENT_SECRET': 'test-only-login-value',
                     'ALLOWED_GITHUB_USER_IDS': '161540124', 'GITHUB_LOGIN_KIND': 'github-app'}
        self.scm = {'DATABASE_URL': self.auth['DATABASE_URL'], 'ALLOWED_GITHUB_USER_IDS': '161540124',
                    'GITHUB_APP_ID': '123', 'GITHUB_APP_PRIVATE_KEY_PEM': 'test-only PRIVATE KEY material\n'}
        self.write('operator/data-plane-state.json', json.dumps({'secretArns': self.ids}))
        self.write('shared/runtime.env', '\n'.join([
            'DATABASE_URL=' + self.auth['DATABASE_URL'], 'SESSION_SECRET=' + self.auth['SESSION_SECRET'],
            'GITHUB_CLIENT_SECRET=' + self.auth['GITHUB_CLIENT_SECRET'], 'GITHUB_APP_ID=123',
            'POSTGRES_PASSWORD=test-only-database-password', 'NODE_ENV=production',
            'FRONTEND_URL=https://aegisai-aws.tailaca7d2.ts.net/auth-check']) + '\n')
        self.write('shared/private-broker.env', 'DATABASE_URL=' + self.auth['DATABASE_URL'] + '\nGITHUB_APP_ID=123\n')
        self.write('shared/scm-keys/github-app-org.pem', self.scm['GITHUB_APP_PRIVATE_KEY_PEM'])

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(value)
        path.chmod(0o600)

    def reader(self, secret_id):
        return copy.deepcopy(self.auth if secret_id == self.ids['auth'] else self.scm)

    def retire(self, validator=lambda root: None):
        return runtime.retire(self.root, self.reader, validator)

    def assert_all_present(self):
        self.assertTrue(all((self.root / name).exists() for name in runtime.TARGETS))

    def test_matching_files_retired_without_saving_secret_values_and_idempotent(self):
        result = self.retire()
        self.assertEqual(result['obsoleteLocalCopiesRetired'], 3)
        self.assertFalse(any((self.root / name).exists() for name in runtime.TARGETS))
        metadata = (self.root / 'operator/retired-local-credentials.json').read_text()
        self.assertNotIn(self.auth['SESSION_SECRET'], metadata)
        self.assertNotIn(self.auth['GITHUB_CLIENT_SECRET'], metadata)
        self.assertNotIn(self.scm['GITHUB_APP_PRIVATE_KEY_PEM'].strip(), metadata)
        self.assertTrue(self.retire()['alreadyRetired'])

    def test_mismatched_secret_blocks_every_removal(self):
        self.auth['SESSION_SECRET'] = 'different-test-value'
        with self.assertRaises(AssertionError):
            self.retire()
        self.assert_all_present()

    def test_unknown_field_blocks_removal(self):
        path = self.root / 'shared/runtime.env'
        path.write_text(path.read_text() + 'UNMANAGED_TOKEN=test-only\n')
        with self.assertRaises(AssertionError):
            self.retire()
        self.assert_all_present()

    def test_symlink_and_hardlink_are_not_retired(self):
        path = self.root / 'shared/runtime.env'
        value = path.read_text()
        path.unlink()
        self.write('other.env', value)
        path.symlink_to(self.root / 'other.env')
        with self.assertRaises((AssertionError, OSError)):
            self.retire()
        path.unlink()
        os.link(self.root / 'other.env', path)
        with self.assertRaises(AssertionError):
            self.retire()
        self.assert_all_present()

    def test_active_configuration_reference_blocks_removal(self):
        def invalid(root):
            raise AssertionError('ACTIVE_LEGACY_REFERENCE')
        with self.assertRaises(AssertionError):
            self.retire(invalid)
        self.assert_all_present()

    def test_cloud_read_failure_does_not_remove_files(self):
        def unavailable(secret_id):
            raise RuntimeError('synthetic unavailable')
        with self.assertRaises(RuntimeError):
            runtime.retire(self.root, unavailable, lambda root: None)
        self.assert_all_present()

    def test_native_reader_does_not_inherit_operator_credentials(self):
        reply = SimpleNamespace(returncode=0, stdout=b'{"version":1,"values":{}}')
        with patch.dict(os.environ, {'AWS_PROFILE': 'operator-test', 'AWS_ACCESS_KEY_ID': 'test-only'}):
            with patch.object(runtime.subprocess, 'run', return_value=reply) as execute:
                runtime.read_secret(self.ids['auth'])
        environment = execute.call_args.kwargs['env']
        self.assertNotIn('AWS_PROFILE', environment)
        self.assertNotIn('AWS_ACCESS_KEY_ID', environment)
        self.assertEqual(environment['AWS_CONFIG_FILE'], '/dev/null')
        self.assertEqual(environment['AWS_SHARED_CREDENTIALS_FILE'], '/dev/null')

    def test_partial_unlink_failure_restores_already_removed_file(self):
        original = {name: (self.root / name).read_bytes() for name in runtime.TARGETS}
        unlink = pathlib.Path.unlink
        def fail_one(path, *args, **kwargs):
            if path == self.root / 'shared/private-broker.env':
                raise OSError('synthetic failure')
            return unlink(path, *args, **kwargs)
        with patch.object(pathlib.Path, 'unlink', fail_one):
            with self.assertRaises(OSError):
                self.retire()
        self.assertEqual(original, {name: (self.root / name).read_bytes() for name in runtime.TARGETS})
        self.assertFalse((self.root / 'operator/retired-local-credentials.json').exists())

    def test_managed_recovery_reconstructs_values_in_protected_ram_directory(self):
        before = {name: (self.root / name).read_bytes() for name in runtime.TARGETS}
        self.retire()
        destination = self.root / 'recovery'
        with patch.object(runtime.subprocess, 'check_output', return_value='ext4\n'):
            with self.assertRaises(AssertionError):
                runtime.recover_to_ram(self.root, destination, self.reader)
        with patch.object(runtime.subprocess, 'check_output', return_value='tmpfs\n'):
            report = runtime.recover_to_ram(self.root, destination, self.reader)
        self.assertEqual(report['recoveryFilesCreatedInRam'], 3)
        for name, original in before.items():
            path = destination / name
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            if name.endswith('.env'):
                self.assertEqual(runtime.parse_env(original), runtime.parse_env(path.read_bytes()))
            else:
                self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
