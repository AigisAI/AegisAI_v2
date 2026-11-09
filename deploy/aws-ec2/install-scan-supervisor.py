"""Install a hash-verified fixed host-code bundle; activate only an idle consumer.
Does not create scans, identities, integrations, ingress or AWS resources.
"""
import hashlib
import json
import os
import pathlib
import pwd
import re
import subprocess
import sys
import tarfile

assert os.geteuid()==0
os.umask(0o077)
archive=pathlib.Path(sys.argv[1]);expected=sys.argv[2]
assert re.fullmatch('[a-f0-9]{64}',expected)
assert archive.parent==pathlib.Path('/home/ubuntu') and archive.is_file() and not archive.is_symlink()
assert re.fullmatch(r'host-worker-[a-z0-9-]+\.tar\.gz',archive.name) and archive.stat().st_size<1024*1024
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
assert pwd.getpwuid(50001).pw_name=='aegisai-fetch'
state=subprocess.run(['systemctl','show','-p','ActiveState','--value','aegisai-scan-supervisor.service'],capture_output=True,text=True).stdout.strip()
assert state not in ('active','activating','deactivating','reloading'),'Stop and drain the existing supervisor before replacing host code'
listed=subprocess.check_output(['systemctl','list-units','--all','--no-legend','--plain','aegisai-fetch-*.service'],text=True)
for line in listed.splitlines():
    fields=line.split()
    if fields and re.fullmatch(r'aegisai-fetch-[a-f0-9]{32}\.service',fields[0]):
        assert fields[2] not in ('active','activating','deactivating'),'Existing gateway must be stopped before replacing code'
names={'runtime.py','runtime_catalog.py','supervisor.py','normalize.py','github_fetch.py','broker_client.py','source_gateway.py',
       'aegisai-scan-supervisor.service'}
files={}
with tarfile.open(archive,'r:gz') as stream:
    for entry in stream:
        assert entry.name in names and entry.name not in files and entry.isfile() and not entry.issym() and not entry.islnk() and 0<entry.size<131072
        files[entry.name]=stream.extractfile(entry).read()
assert set(files)==names
scanner=pathlib.Path('/opt/aegisai/scanner')
gateway=pathlib.Path('/usr/local/lib/aegisai-source-gateway')
gateway.mkdir(mode=0o755,exist_ok=True)
assert gateway.resolve()==gateway and gateway.stat().st_uid==0 and not gateway.stat().st_mode & 0o022
gateway.chmod(0o755)
for name,data in files.items():
    if name.endswith('.py'):
        target=scanner/name
        assert not target.is_symlink()
        target.write_bytes(data);target.chmod(0o600)
for name in ('runtime.py','github_fetch.py','broker_client.py','source_gateway.py'):
    target=gateway/name
    assert not target.is_symlink()
    target.chmod(0o600) if target.exists() else None
    target.write_bytes(files[name]);target.chmod(0o444)
unit=pathlib.Path('/etc/systemd/system/aegisai-scan-supervisor.service')
unit.write_bytes(files[unit.name]);unit.chmod(0o644)
catalog=scanner/'catalog';catalog.mkdir(mode=0o755,exist_ok=True);catalog.chmod(0o755)
jobs=pathlib.Path('/run/aegisai-scan-jobs');jobs.mkdir(mode=0o710,exist_ok=True)
assert not jobs.is_symlink() and jobs.stat().st_uid==0
os.chown(jobs,0,50001);jobs.chmod(0o710)
manifest={'archiveSha256':expected,'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},'scanCreated':False}
(scanner/'host-runtime-manifest.json').write_text(json.dumps(manifest,indent=2))
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','aegisai-scan-supervisor.service'],check=True)
if '--install-only' not in sys.argv:
    subprocess.run(['systemctl','start','aegisai-scan-supervisor.service'],check=True)
print('PRIVATE_SUPERVISOR_INSTALLED_NO_SCAN_CREATED')
