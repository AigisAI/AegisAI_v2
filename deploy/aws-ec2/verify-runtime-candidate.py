import json
import pathlib
import urllib.error
import urllib.request

from managed_runtime import load_values, validate_running_configuration

root = pathlib.Path('/opt/aegisai')
release = (root / 'shared/candidate-release').read_text().strip()
env = load_values()
validate_running_configuration()

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
request('/api/runtime/scans', 401)
request('/api/scan-plane/mock-runs', 503, True)
request('/api/token-broker/issue', 503, True)

# Managed-runtime health checks are read-only. Backup/restore acceptance is
# explicitly separate: backup-current-data.py --verify-restore in an idle window.
print(json.dumps({'runtimeConfiguration': 'managed-secrets', 'backupRestoreRepeated': False}))
