import gzip
import json
import pathlib
import subprocess
import time
import urllib.error
import urllib.request
import uuid

root = pathlib.Path('/opt/aegisai')
release = (root / 'shared/candidate-release').read_text().strip()
env = dict(line.split('=', 1) for line in (root / 'shared/runtime.env').read_text().splitlines() if '=' in line)

def request(path, expected, internal=False):
    headers = {'Content-Type': 'application/json'}
    if internal:
        headers['Authorization'] = 'Bearer ' + env['INTERNAL_API_SECRET']
    req = urllib.request.Request('http://127.0.0.1:8080' + path,
                                 data=b'{}' if internal else None, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read().decode()
        assert response.status == expected, (path, response.status)
        if internal:
            assert json.loads(body)['errorCode'] == 'PRODUCTION_RUNTIME_NOT_READY'
    print(json.dumps({'path': path, 'status': expected}))

request('/api/health', 200)
request('/api/integrations', 401)
request('/api/scan-plane/mock-runs', 503, True)
request('/api/token-broker/issue', 503, True)

backup = root / 'backups' / ('pre-' + release + '.sql.gz')
assert backup.is_file()
expected_count = int((root / 'backups' / ('pre-' + release + '.migrations')).read_text().strip())
assert expected_count > 0
database = 'restore_verify_' + uuid.uuid4().hex
prefix = ['docker', 'exec', '-i', 'aegisai-persistence-verify']
# Backup ownership is retained; recreate only the required NOLOGIN role in the
# disposable verification cluster, never in the application database.
subprocess.run(prefix + ['psql', '-U', 'verify', '-d', 'aegisai_verify',
    '-v', 'ON_ERROR_STOP=1', '-c',
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegisai') "
    "THEN CREATE ROLE aegisai NOLOGIN; END IF; END $$;"],
    stdout=subprocess.DEVNULL, check=True)
subprocess.run(prefix + ['createdb', '-U', 'verify', database], check=True)
started = time.monotonic()
try:
    with gzip.open(backup, 'rb') as stream:
        # Verification database belongs to this run; application data is never modified.
        subprocess.run(prefix + ['psql', '-U', 'verify', '-d', database, '-v', 'ON_ERROR_STOP=1'],
                       input=stream.read(), stdout=subprocess.DEVNULL, check=True)
    count = subprocess.check_output(prefix + ['psql', '-U', 'verify', '-d', database, '-Atc',
        'SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NOT NULL'], text=True).strip()
    assert int(count) == expected_count, count
    print(json.dumps({'backupRestore': 'passed', 'migrationCount': int(count),
                      'restoreSeconds': round(time.monotonic() - started, 3),
                      'dataScope': 'pre-release bootstrap database; no customer data'}))
finally:
    subprocess.run(prefix + ['dropdb', '-U', 'verify', database], check=True)
