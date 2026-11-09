"""Switch AWS to its separate identity client; never modifies Oracle or SCM keys."""
import json
import os
import pathlib
import shlex
import shutil
import time

os.umask(0o077)
root = pathlib.Path('/opt/aegisai')
pending = root / 'shared/login-client.pending.json'
assert pending.stat().st_uid == 0 and pending.stat().st_mode & 0o777 == 0o600
identity = json.loads((root / 'operator/github-login-registration.json').read_text())
assert identity['ownerId'] == 161540124
assert identity['permissions'].get('emails') == 'read'
assert set(identity['permissions']) <= {'emails', 'metadata'}
updates = json.loads(pending.read_text())
assert set(updates) == {'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'GITHUB_LOGIN_KIND'}
assert updates['GITHUB_LOGIN_KIND'] == 'github-app'
assert all(isinstance(value, str) and value and '\n' not in value and '\r' not in value for value in updates.values())
updates.update({'ALLOWED_GITHUB_USER_IDS': '161540124', 'APP_URL': 'https://aegisai-aws.tailaca7d2.ts.net',
                'FRONTEND_URL': 'https://aegisai-aws.tailaca7d2.ts.net/auth-check'})
runtime = root / 'shared/runtime.env'
backup = root / 'shared' / ('runtime.env.before-identity-' + str(time.time_ns()))
shutil.copyfile(runtime, backup)
backup.chmod(0o600)
lines = [line for line in runtime.read_text().splitlines() if line.split('=', 1)[0] not in updates]
lines.extend(name + '=' + shlex.quote(value) for name, value in updates.items())
temporary = root / 'shared' / ('runtime.env.identity-' + str(time.time_ns()))
fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('\n'.join(lines) + '\n')
os.replace(temporary, runtime)
print('Separate AWS identity client configured; original Oracle and SCM credentials unchanged')
