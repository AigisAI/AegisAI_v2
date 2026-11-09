"""Activate verified org App metadata without exposing the external signing key."""
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import time

os.umask(0o077)
root = pathlib.Path('/opt/aegisai')
metadata = json.loads((root / 'operator/github-app-org-registration.json').read_text())
assert metadata['ownerId'] == 241095585
assert metadata['permissions'] == {'contents': 'read', 'metadata': 'read', 'members': 'read'}
live = json.loads((root / 'operator/github-live-installation.json').read_text())
assert live['appId'] == metadata['id'] and live['discoveryTokenRevoked'] is True
assert live['verifiedAdministratorId'] == 161540124
key = root / 'shared/scm-keys/github-app-org.pem'
assert key.stat().st_uid == 0 and key.stat().st_mode & 0o777 == 0o600
subprocess.run(['openssl', 'pkey', '-check', '-noout', '-in', str(key)],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
unused = root / 'shared/scm-keys/github-app.pem'
archive = root / 'operator/unused-personal-app.pem'
if unused.exists():
    assert not archive.exists()
    unused.rename(archive)
    archive.chmod(0o600)
updates = {'GITHUB_APP_ID': str(metadata['id']), 'GITHUB_APP_SLUG': metadata['slug'],
           'ALLOWED_GITHUB_USER_IDS': '161540124',
           'FRONTEND_URL': 'https://aegisai-aws.tailaca7d2.ts.net/auth-check',
           'GITHUB_APP_PRIVATE_KEY_PATH': '/run/aegisai/scm/github-app-org.pem'}
runtime = root / 'shared/runtime.env'
backup = root / 'shared' / ('runtime.env.before-github-app-' + str(time.time_ns()))
shutil.copyfile(runtime, backup)
backup.chmod(0o600)
lines = [line for line in runtime.read_text().splitlines() if line.split('=', 1)[0] not in updates]
lines.extend(name + '=' + shlex.quote(value) for name, value in updates.items())
temporary = root / 'shared' / ('runtime.env.app-' + str(time.time_ns()))
fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('\n'.join(lines) + '\n')
os.replace(temporary, runtime)
print('Verified organization App configured; signing key remains external and unreadable to scan sandboxes')
