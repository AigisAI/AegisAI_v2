"""Read-only candidate checks. No image load, migration, service or cloud mutation."""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def validate_history(profile, rows):
    expected = {item['name']: item for item in profile['migrations']}
    assert profile['profile'] == 'private-single-host-v1' and profile['generalQualification'] == 'NOT_QUALIFIED'
    assert len(expected) == len(rows) == 6 and len({r['migration_name'] for r in rows}) == 6
    for row in rows:
        entry = expected.get(row['migration_name'])
        assert entry and row['finished_at'] and not row['rolled_back_at']
        assert row['checksum'] in entry['acceptedAppliedChecksums'], 'TARGET_MIGRATION_DRIFT'


WORKERS = ('runtime.py', 'supervisor.py', 'broker_client.py', 'github_fetch.py', 'source_gateway.py', 'normalize.py', 'runtime_catalog.py')


def check(directory, expected_sha, target=False, snapshot=None):
    manifest_path = directory / 'candidate.json'
    assert not manifest_path.is_symlink() and digest(manifest_path) == expected_sha
    manifest = json.loads(manifest_path.read_text())
    assert manifest['profile'] == 'private-single-host-v1' and manifest['generalQualification'] == 'NOT_QUALIFIED'
    assert manifest['deploymentPerformed'] is False
    assert re.fullmatch(r'[a-f0-9]{40}', manifest['sourceCommit'])
    assert re.fullmatch(r'ec2-runtime-\d{8}-\d{6}', manifest['releaseId'])
    assert manifest['sourceArchive'] == manifest['releaseId'] + '.tar.gz'
    for item in manifest['files']:
        name = pathlib.PurePosixPath(item['name'])
        assert len(name.parts) == 1 and name.name not in ('', '.', '..')
        path = directory / name.name
        assert path.is_file() and not path.is_symlink() and digest(path) == item['sha256'], 'CANDIDATE_FILE_DRIFT'
    profile = json.loads((directory / 'runtime-profile.json').read_text())
    with tarfile.open(directory / manifest['sourceArchive'], 'r:gz') as source:
        for member in source.getmembers():
            name = pathlib.PurePosixPath(member.name)
            assert not name.is_absolute() and '..' not in name.parts
            assert member.isfile() or member.isdir(), 'SOURCE_LINK_OR_SPECIAL_FILE'
        assert source.extractfile('deploy/aws-ec2/runtime-profile.json').read() == (directory / 'runtime-profile.json').read_bytes()
    for key in ('api', 'web'):
        image = manifest['images'][key]
        with tarfile.open(directory / image['archive'], 'r:gz') as archive:
            index = archive.getmember('manifest.json')
            assert index.size <= 65536
            entries = json.load(archive.extractfile(index))
            assert len(entries) == 1 and entries[0]['RepoTags'] == [image['tag']]
            config_file = archive.getmember(entries[0]['Config'])
            assert config_file.isfile() and config_file.size <= 1024 * 1024
            content = archive.extractfile(config_file).read()
            assert 'sha256:' + hashlib.sha256(content).hexdigest() == image['id']
            config = json.loads(content)['config']
            assert config['Labels']['org.aegisai.runtime-profile'] == manifest['profile']
            assert config['Labels']['org.opencontainers.image.revision'] == manifest['sourceCommit']
            keys = {value.split('=', 1)[0] for value in config.get('Env', [])}
            assert not keys.intersection({'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'DATABASE_URL', 'SESSION_SECRET', 'CSRF_SECRET', 'GITHUB_CLIENT_SECRET', 'POSTGRES_PASSWORD'})
    if snapshot is not None:
        assert snapshot['readOnly'] and snapshot['instanceId'] == 'i-0d24d0502cfc5a9c5'
        observed = datetime.datetime.fromisoformat(snapshot['observedAt'])
        age = (datetime.datetime.now(datetime.timezone.utc) - observed).total_seconds()
        assert -5 <= age <= 900, 'TARGET_SNAPSHOT_EXPIRED'
        validate_history(profile, snapshot['migrations'])
        assert snapshot['scannerReady'] and not snapshot['scannerBusy']
        assert set(snapshot['workerSourceHashes']) == set(WORKERS), 'INCOMPLETE_HOST_WORKER_SNAPSHOT'
        with tarfile.open(directory / manifest['sourceArchive'], 'r:gz') as source:
            for name, expected in snapshot['workerSourceHashes'].items():
                assert pathlib.PurePosixPath(name).name == name
                assert hashlib.sha256(source.extractfile('apps/scanner/' + name).read()).hexdigest() == expected
        required = sum(image['uncompressedBytes'] for image in manifest['images'].values()) * 2 + 3 * 1024 ** 3
        assert snapshot['diskFreeBytes'] >= required, 'INSUFFICIENT_DEPLOYMENT_HEADROOM'
    if target:
        state = json.loads(pathlib.Path('/opt/aegisai/operator/data-plane-state.json').read_text())
        assert state['existingInstanceId'] == 'i-0d24d0502cfc5a9c5'
        catalog = json.loads(pathlib.Path('/opt/aegisai/scanner/catalog/current.json').read_text())
        assert catalog['ready'] and not catalog['busy'], 'SCANNER_NOT_IDLE_READY'
        sql = 'SELECT coalesce(json_agg(t),\'[]\'::json) FROM (SELECT migration_name,checksum,finished_at,rolled_back_at FROM "_prisma_migrations") t;'
        rows = json.loads(subprocess.check_output(['docker', 'exec', 'aegisai-ec2-demo-postgres-1',
            'psql', '-U', 'aegisai', '-d', 'aegisai', '-Atc', sql], text=True))
        validate_history(profile, rows)
        with tarfile.open(directory / manifest['sourceArchive'], 'r:gz') as source:
            for name in WORKERS:
                local = pathlib.Path('/opt/aegisai/scanner') / name
                member = source.extractfile('apps/scanner/' + name)
                assert local.is_file() and member, 'HOST_WORKER_MISSING'
                assert hashlib.sha256(member.read()).hexdigest() == digest(local), 'HOST_WORKER_DRIFT'
        size = sum(image['uncompressedBytes'] for image in manifest['images'].values())
        assert shutil.disk_usage('/opt/aegisai').free >= size * 2 + 3 * 1024 ** 3, 'INSUFFICIENT_DEPLOYMENT_HEADROOM'
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=pathlib.Path)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--target', action='store_true')
    parser.add_argument('--target-snapshot', type=pathlib.Path)
    options = parser.parse_args()
    assert not (options.target and options.target_snapshot)
    snapshot = json.loads(options.target_snapshot.read_text()) if options.target_snapshot else None
    result = check(options.directory, options.manifest_sha256, options.target, snapshot)
    print(json.dumps({'candidateVerified': True, 'profile': result['profile'], 'commit': result['sourceCommit'],
                      'targetChecked': options.target or snapshot is not None, 'deploymentPerformed': False}))
