import datetime
import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('checker', pathlib.Path(__file__).with_name('check-candidate.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class CandidateChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.commit = 'a' * 40
        self.profile = {'profile': 'private-single-host-v1', 'generalQualification': 'NOT_QUALIFIED',
            'migrations': [{'name': str(i), 'acceptedAppliedChecksums': [str(i) * 64]} for i in range(6)]}
        profile = json.dumps(self.profile).encode()
        (self.root / 'runtime-profile.json').write_bytes(profile)
        self.tar('ec2-runtime-20261109-000000.tar.gz', {'deploy/aws-ec2/runtime-profile.json': profile})
        self.images = {}
        for kind in ('api', 'web'):
            tag = 'aegisai-' + kind + ':fixture'
            config = json.dumps({'config': {'Labels': {'org.aegisai.runtime-profile': self.profile['profile'],
                'org.opencontainers.image.revision': self.commit}, 'Env': ['NODE_ENV=production']}}).encode()
            sha = hashlib.sha256(config).hexdigest()
            self.tar(kind + '.tar.gz', {sha + '.json': config,
                'manifest.json': json.dumps([{'Config': sha + '.json', 'RepoTags': [tag], 'Layers': []}]).encode()})
            self.images[kind] = {'tag': tag, 'id': 'sha256:' + sha, 'archive': kind + '.tar.gz', 'uncompressedBytes': len(config)}
        self.manifest = {'profile': self.profile['profile'], 'generalQualification': 'NOT_QUALIFIED',
            'sourceCommit': self.commit, 'releaseId': 'ec2-runtime-20261109-000000',
            'sourceArchive': 'ec2-runtime-20261109-000000.tar.gz', 'images': self.images,
            'deploymentPerformed': False, 'files': []}
        self.refresh()

    def tearDown(self):
        self.temp.cleanup()

    def tar(self, name, entries):
        with tarfile.open(self.root / name, 'w:gz') as stream:
            for path, value in entries.items():
                info = tarfile.TarInfo(path);info.size = len(value)
                stream.addfile(info, io.BytesIO(value))

    def refresh(self):
        self.manifest['files'] = [{'name': p.name, 'sha256': checker.digest(p)}
            for p in self.root.iterdir() if p.name != 'candidate.json']
        (self.root / 'candidate.json').write_text(json.dumps(self.manifest))
        self.sha = checker.digest(self.root / 'candidate.json')

    def test_offline_check_never_calls_production_or_loads_images(self):
        with patch.object(checker.subprocess, 'check_output', side_effect=AssertionError('unexpected command')):
            self.assertEqual(checker.check(self.root, self.sha)['sourceCommit'], self.commit)

    def test_tamper_in_any_candidate_file_is_rejected(self):
        (self.root / 'api.tar.gz').write_bytes(b'tamper')
        with self.assertRaises(AssertionError):checker.check(self.root, self.sha)

    def test_image_commit_substitution_rejected_after_valid_file_hashes(self):
        self.manifest['sourceCommit'] = 'b' * 40
        self.refresh()
        with self.assertRaises(AssertionError):checker.check(self.root, self.sha)

    def test_target_snapshot_must_be_fresh_idle_and_complete(self):
        rows = [{'migration_name': str(i), 'checksum': str(i) * 64, 'finished_at': 'fixture', 'rolled_back_at': None} for i in range(6)]
        snapshot = {'readOnly': True, 'instanceId': 'i-0d24d0502cfc5a9c5',
            'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'migrations': rows, 'scannerReady': True, 'scannerBusy': False,
            'workerSourceHashes': {name: hashlib.sha256(name.encode()).hexdigest() for name in checker.WORKERS},
            'diskFreeBytes': 100 * 1024 ** 3}
        entries = {'deploy/aws-ec2/runtime-profile.json': (self.root / 'runtime-profile.json').read_bytes()}
        entries.update({'apps/scanner/' + name: name.encode() for name in checker.WORKERS})
        self.tar(self.manifest['sourceArchive'], entries)
        self.refresh()
        self.assertEqual(checker.check(self.root, self.sha, snapshot=snapshot)['sourceCommit'], self.commit)
        for change in [
            {'scannerBusy': True}, {'instanceId': 'different-host'},
            {'observedAt': '2000-01-01T00:00:00+00:00'}, {'workerSourceHashes': {}}, {'diskFreeBytes': 0}
        ]:
            with self.assertRaises(AssertionError):checker.check(self.root, self.sha, snapshot={**snapshot, **change})

    def test_wrong_schema_and_incomplete_history_fail_before_target_mutations(self):
        rows = [{'migration_name': str(i), 'checksum': str(i) * 64, 'finished_at': 'fixture', 'rolled_back_at': None} for i in range(6)]
        checker.validate_history(self.profile, rows)
        wrong = copy.deepcopy(rows);wrong[0]['migration_name'] = 'general-schema'
        with self.assertRaises(AssertionError):checker.validate_history(self.profile, wrong)
        with self.assertRaises(AssertionError):checker.validate_history(self.profile, rows[:-1])


if __name__ == '__main__':
    unittest.main()
