"""Release only the frontend after proving API/shared/dependency inputs unchanged.
Keeps database, API, broker and scanner processes running. Reverts failed web start.
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import time
import urllib.request

assert os.geteuid()==0
os.umask(0o077)
release,digest=sys.argv[1:]
assert re.fullmatch(r'ec2-runtime-\d{8}-\d{6}',release) and re.fullmatch(r'[a-f0-9]{64}',digest)
root=pathlib.Path('/opt/aegisai')
archive=pathlib.Path('/home/ubuntu')/(release+'.tar.gz')
assert hashlib.sha256(archive.read_bytes()).hexdigest()==digest
target=root/'releases'/release
assert not target.exists()
target.mkdir(mode=0o750)
with tarfile.open(archive,'r:gz') as stream:
    for member in stream.getmembers():
        path=pathlib.PurePosixPath(member.name)
        assert member.isfile() and not path.is_absolute() and '..' not in path.parts
        assert not any(part.startswith('.env') or part in ('node_modules','dist','__pycache__') for part in path.parts)
        assert member.size<=16*1024*1024 and path.suffix not in ('.pem','.key')
    stream.extractall(target,filter='data')
api_release=(root/'shared/candidate-release').read_text().strip()
assert re.fullmatch(r'ec2-runtime-\d{8}-\d{6}',api_release)
base=root/'releases'/api_release
def files(path):
    return {file.relative_to(path).as_posix():hashlib.sha256(file.read_bytes()).hexdigest()
        for file in path.rglob('*') if file.is_file() and 'dist' not in file.parts and 'node_modules' not in file.parts and '__pycache__' not in file.parts}
for directory in ('apps/api','packages'):
    assert files(base/directory)==files(target/directory),'Frontend-only deployment cannot change API/shared inputs'
for name in ('package.json','pnpm-lock.yaml','pnpm-workspace.yaml','.npmrc','tsconfig.base.json','deploy/aws-ec2/compose.yaml'):
    assert (base/name).read_bytes()==(target/name).read_bytes(),'Frontend-only dependency/configuration mismatch'
environment={**os.environ,'RELEASE_ID':release,'RUNTIME_ENV_FILE':str(root/'shared/runtime-public.env')}
subprocess.run(['docker','compose','-f',str(target/'deploy/aws-ec2/compose.yaml'),'build','web'],env=environment,check=True)
override=root/'shared/web-release.override.yaml'
old=override.read_text() if override.exists() else None
base_environment={**environment,'RELEASE_ID':api_release}
command=['docker','compose','-f',str(base/'deploy/aws-ec2/compose.yaml'),'-f',str(override),'up','-d','--no-deps','--wait','--wait-timeout','90','web']
def write(content):
    pending=override.with_suffix('.pending');pending.write_text(content);pending.replace(override)
previous=json.loads(subprocess.check_output(['docker','inspect','aegisai-ec2-demo-web-1']))[0]['Config']['Image']
write('services:\n  web:\n    image: aegisai-web:'+release+'\n')
try:
    subprocess.run(command,env=base_environment,check=True)
    for path in ('/','/dashboard','/repos','/scan'):
        with urllib.request.urlopen('http://127.0.0.1:8080'+path,timeout=10) as response:
            assert response.status==200 and b'<div id="root">' in response.read(1024*1024)
except Exception:
    write(old if old is not None else 'services:\n  web:\n    image: '+previous+'\n')
    subprocess.run(command,env=base_environment,check=True)
    if old is None:override.unlink()
    raise
report={'webRelease':release,'apiRelease':api_release,'sha256':digest,'apiSharedInputsUnchanged':True,
    'previousWebImage':previous,'frontendRoutesHealthy':True,'databaseMigrated':False,
    'releasedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
(root/'operator/web-release.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
