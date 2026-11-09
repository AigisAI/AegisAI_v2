"""Boot prerequisite: materialize only the database password into root-only RAM.
Uses the instance role, never the operator login cache. No secret stdout/logging.
"""
import json
import os
import pathlib
import subprocess
import tempfile
import urllib.parse

assert os.geteuid()==0
os.umask(0o077)
state=json.loads(pathlib.Path('/opt/aegisai/operator/data-plane-state.json').read_text())
environment={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root',
    'AWS_CONFIG_FILE':'/dev/null','AWS_SHARED_CREDENTIALS_FILE':'/dev/null','AWS_EC2_METADATA_V1_DISABLED':'true',
    'AWS_CLI_AUTO_PROMPT':'off','AWS_PAGER':''}
result=subprocess.run(['/usr/local/lib/aegisai-aws-cli/aws','--region','ap-northeast-2','secretsmanager','get-secret-value',
    '--secret-id',state['secretArns']['auth'],'--query','SecretString','--output','text'],env=environment,
    capture_output=True,timeout=30)
assert result.returncode==0,'Managed database secret unavailable'
secret=json.loads(result.stdout)
assert secret['version']==1
url=urllib.parse.urlparse(secret['values']['DATABASE_URL'])
assert url.scheme in ('postgres','postgresql') and url.hostname=='postgres' and url.username=='aegisai' and url.path=='/aegisai'
password=urllib.parse.unquote(url.password or '')
assert len(password)>=16 and not any(char in password for char in '\r\n\0')
directory=pathlib.Path('/run/aegisai-runtime-secrets')
directory.mkdir(mode=0o700,exist_ok=True)
assert directory.resolve()==directory and directory.stat().st_uid==0 and not directory.stat().st_mode&0o077
descriptor,name=tempfile.mkstemp(prefix='postgres-',dir=directory)
temporary=pathlib.Path(name)
try:
    with os.fdopen(descriptor,'w') as output: output.write(password)
    temporary.chmod(0o600);temporary.replace(directory/'postgres-password')
finally:temporary.unlink(missing_ok=True)
print('MANAGED_DATABASE_SECRET_READY_IN_RAM')
