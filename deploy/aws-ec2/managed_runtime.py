"""Root operator access to existing managed secrets. Never print returned values."""
import json
import os
import pathlib
import re
import resource
import shlex
import stat
import subprocess
import urllib.parse

ROOT = pathlib.Path('/opt/aegisai')
REGION = 'ap-northeast-2'
ARN = re.compile(r'^arn:aws:secretsmanager:ap-northeast-2:024139495514:secret:aegisai/private-runtime/(auth|scm)-[A-Za-z0-9]+$')
SECRET_KEYS = {'DATABASE_URL', 'REDIS_URL', 'SESSION_SECRET', 'CSRF_SECRET',
               'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITLAB_CLIENT_ID',
               'GITLAB_CLIENT_SECRET', 'TOKEN_ENCRYPTION_KEY', 'INTERNAL_API_SECRET',
               'GITHUB_APP_ID', 'GITHUB_APP_SLUG', 'ALLOWED_GITHUB_USER_IDS', 'GITHUB_LOGIN_KIND'}
PUBLIC_KEYS = {'NODE_ENV', 'PORT', 'APP_URL', 'FRONTEND_URL', 'COOKIE_SECURE',
               'ANALYSIS_CLIENT_MODE', 'USE_INTERNAL_AI', 'GITHUB_APP_PRIVATE_KEY_PATH'}
TARGETS = ('shared/runtime.env', 'shared/private-broker.env', 'shared/scm-keys/github-app-org.pem')


def read_protected(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
        assert not info.st_mode & 0o077 and info.st_size <= 65536
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            content = stream.read(65537)
        assert len(content) <= 65536
        return content, (info.st_dev, info.st_ino)
    finally:
        os.close(descriptor)


def read_secret(secret_id):
    assert os.geteuid() == 0 and ARN.fullmatch(secret_id)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'HOME': '/root', 'AWS_CONFIG_FILE': '/dev/null',
                   'AWS_SHARED_CREDENTIALS_FILE': '/dev/null', 'AWS_EC2_METADATA_V1_DISABLED': 'true',
                   'AWS_CLI_AUTO_PROMPT': 'off', 'AWS_PAGER': ''}
    result = subprocess.run(['/usr/local/lib/aegisai-aws-cli/aws', '--region', REGION,
                             'secretsmanager', 'get-secret-value', '--secret-id', secret_id,
                             '--query', 'SecretString', '--output', 'text'],
                            env=environment, capture_output=True, timeout=30)
    assert result.returncode == 0 and len(result.stdout) <= 65536, 'MANAGED_SECRET_UNAVAILABLE'
    data = json.loads(result.stdout)
    assert data['version'] == 1 and isinstance(data['values'], dict)
    assert all(isinstance(k, str) and isinstance(v, str) and '\0' not in v for k, v in data['values'].items())
    return data['values']


def load_bundles(root=ROOT, reader=read_secret):
    assert os.geteuid() == 0
    content, _ = read_protected(root / 'operator/data-plane-state.json')
    state = json.loads(content)
    ids = state['secretArns']
    assert ARN.fullmatch(ids['auth']) and '/auth-' in ids['auth']
    assert ARN.fullmatch(ids['scm']) and '/scm-' in ids['scm']
    bundles = {scope: reader(ids[scope]) for scope in ('auth', 'scm')}
    assert bundles['auth']['DATABASE_URL'] == bundles['scm']['DATABASE_URL']
    assert bundles['auth']['ALLOWED_GITHUB_USER_IDS'] == bundles['scm']['ALLOWED_GITHUB_USER_IDS'] == '161540124'
    assert bundles['auth']['GITHUB_LOGIN_KIND'] == 'github-app'
    assert 'PRIVATE KEY' in bundles['scm']['GITHUB_APP_PRIVATE_KEY_PEM']
    return state, bundles


def load_values(root=ROOT):
    _, bundles = load_bundles(root)
    return {**bundles['auth'], **bundles['scm']}


def parse_env(content):
    result = {}
    for line in content.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        assert separator and re.fullmatch(r'[A-Z][A-Z0-9_]*', key) and key not in result
        pieces = shlex.split(value)
        assert len(pieces) <= 1
        result[key] = pieces[0] if pieces else ''
    return result


def postgres_password(values):
    url = urllib.parse.urlparse(values['DATABASE_URL'])
    assert url.scheme in ('postgres', 'postgresql') and url.hostname == 'postgres'
    assert url.username == 'aegisai' and url.path == '/aegisai'
    return urllib.parse.unquote(url.password or '')


def plan_retirement(root, state, bundles):
    records, contents, identities = [], {}, {}
    for relative in TARGETS:
        path = root / relative
        assert path.resolve() == path and path.parent.stat().st_uid == 0
        assert not path.parent.stat().st_mode & 0o022
        content, identity = read_protected(path)
        contents[relative], identities[relative] = content, identity
        if relative.endswith('.pem'):
            assert content.decode().strip() == bundles['scm']['GITHUB_APP_PRIVATE_KEY_PEM'].strip(), 'SIGNING_KEY_MISMATCH'
            records.append({'path': relative, 'kind': 'pem', 'scope': 'scm', 'key': 'GITHUB_APP_PRIVATE_KEY_PEM'})
            continue
        fields = []
        for key, value in parse_env(content).items():
            if key in SECRET_KEYS:
                matches = [scope for scope in ('auth', 'scm') if bundles[scope].get(key) == value]
                assert matches, 'LEGACY_SECRET_MISMATCH:' + key
                fields.append({'key': key, 'scope': matches[0]})
            elif key == 'POSTGRES_PASSWORD':
                assert value == postgres_password(bundles['auth']), 'DATABASE_PASSWORD_MISMATCH'
                fields.append({'key': key, 'derive': 'auth.DATABASE_URL.password'})
            else:
                assert key in PUBLIC_KEYS, 'UNKNOWN_LEGACY_FIELD:' + key
                if key.endswith('_URL'):
                    url = urllib.parse.urlparse(value)
                    assert url.scheme == 'https' and url.netloc == 'aegisai-aws.tailaca7d2.ts.net'
                if key == 'GITHUB_APP_PRIVATE_KEY_PATH':
                    assert value == '/run/aegisai/scm/github-app-org.pem'
                fields.append({'key': key, 'publicValue': value})
        records.append({'path': relative, 'kind': 'env', 'fields': fields})
    return {'version': 1, 'secretArns': state['secretArns'], 'files': records}, contents, identities


def validate_running_configuration(root=ROOT):
    state = json.loads(read_protected(root / 'operator/data-plane-state.json')[0])
    forbidden = SECRET_KEYS - {'ALLOWED_GITHUB_USER_IDS', 'GITHUB_LOGIN_KIND', 'GITHUB_APP_ID', 'GITHUB_APP_SLUG'}
    for name in ('aegisai-ec2-demo-api-1', 'aegisai-private-broker'):
        item = json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]
        assert item['State']['Health']['Status'] == 'healthy'
        environment = dict(x.split('=', 1) for x in item['Config']['Env'])
        assert not forbidden.intersection(environment) and 'GITHUB_APP_PRIVATE_KEY_PATH' not in environment
        assert environment['AWS_SCM_SECRET_ARN'] == state['secretArns']['scm']
        if name.endswith('api-1'):
            assert environment['AWS_AUTH_SECRET_ARN'] == state['secretArns']['auth']
        for mount in item['Mounts']:
            assert not any(str(root / target).startswith(mount['Source'].rstrip('/') + '/')
                           or str(root / target) == mount['Source'] for target in TARGETS)
    active = [root / 'operator' / name for name in ('run-private-broker.sh', 'run-evidence-retention.sh',
              'materialize-database-secret.py', 'restore-after-root-replacement.sh')]
    active += list(pathlib.Path('/etc/systemd/system').glob('aegisai*.service'))
    for path in active:
        text = path.read_text()
        assert not any(target in text for target in TARGETS), 'ACTIVE_LEGACY_REFERENCE'


def retire(root=ROOT, reader=read_secret, validator=validate_running_configuration):
    state, bundles = load_bundles(root, reader)
    destination = root / 'operator/retired-local-credentials.json'
    if destination.exists():
        previous = json.loads(read_protected(destination)[0])
        assert previous['version'] == 1 and previous['secretArns'] == state['secretArns']
        assert {item['path'] for item in previous['files']} == set(TARGETS)
        assert not any((root / name).exists() or (root / name).is_symlink() for name in TARGETS)
        validator(root)
        return {'obsoleteLocalCopiesRetired': len(TARGETS), 'alreadyRetired': True}
    manifest, contents, identities = plan_retirement(root, state, bundles)
    validator(root)
    for relative, identity in identities.items():
        info = (root / relative).lstat()
        assert (info.st_dev, info.st_ino) == identity
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(manifest, output, indent=2)
    removed = []
    try:
        for relative in TARGETS:
            (root / relative).unlink()
            removed.append(relative)
    except BaseException:
        for relative in removed:
            descriptor = os.open(root / relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(contents[relative])
        destination.unlink()
        raise
    return {'obsoleteLocalCopiesRetired': len(removed), 'managedRecoveryReferencesSaved': True}


def recover_to_ram(root=ROOT, destination=pathlib.Path('/run/aegisai-legacy-recovery'), reader=read_secret):
    assert not destination.exists()
    assert subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(destination.parent)], text=True).strip() == 'tmpfs'
    state, bundles = load_bundles(root, reader)
    manifest = json.loads(read_protected(root / 'operator/retired-local-credentials.json')[0])
    assert manifest['version'] == 1 and manifest['secretArns'] == state['secretArns']
    assert {item['path'] for item in manifest['files']} == set(TARGETS)
    destination.mkdir(mode=0o700)
    for item in manifest['files']:
        path = destination / item['path']
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if item['kind'] == 'pem':
            content = bundles[item['scope']][item['key']]
        else:
            lines = []
            for field in item['fields']:
                key = field['key']
                value = field['publicValue'] if 'publicValue' in field else postgres_password(bundles['auth']) if 'derive' in field else bundles[field['scope']][key]
                lines.append(key + '=' + shlex.quote(value))
            content = '\n'.join(lines) + '\n'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write(content)
    return {'recoveryFilesCreatedInRam': len(manifest['files']), 'productionConfigurationModified': False}
