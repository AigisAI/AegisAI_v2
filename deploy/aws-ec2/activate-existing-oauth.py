"""Run as root on the target host; never outputs credential values."""
import json
import os
import pathlib
import shlex
import shutil
import time

root = pathlib.Path('/opt/aegisai/shared')
runtime = root / 'runtime.env'
pending = root / 'existing-oauth.pending.json'
values = json.loads(pending.read_text())
updates = {key: values[key] for key in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET')}
assert all(isinstance(value, str) and value and '\n' not in value and '\r' not in value
           for value in updates.values())
updates.update({
    'APP_URL': 'https://aegisai-aws.tailaca7d2.ts.net',
    'FRONTEND_URL': 'https://aegisai-aws.tailaca7d2.ts.net',
})
lines = runtime.read_text().splitlines()
backup = root / ('runtime.env.before-oauth-' + str(time.time_ns()))
shutil.copyfile(runtime, backup)
os.chmod(backup, 0o600)
result = []
for line in lines:
    key = line.split('=', 1)[0] if '=' in line else ''
    if key in updates:
        continue
    result.append(line)
result.extend(key + '=' + shlex.quote(value) for key, value in updates.items())
temporary = root / ('runtime.env.oauth-' + str(time.time_ns()))
fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('\n'.join(result) + '\n')
os.replace(temporary, runtime)
print('Existing GitHub OAuth configured for AWS origin; callback acceptance still unverified')
