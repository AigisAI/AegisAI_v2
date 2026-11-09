"""Install checksummed vendor tools and an independent containerd sandbox daemon.

Does not modify/restart application Docker or start a repository/scanner workload.
"""
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import urllib.request


def download(url, limit=200 * 1024 * 1024):
    with urllib.request.urlopen(url, timeout=60) as response:
        content = response.read(limit + 1)
        if len(content) > limit:
            raise RuntimeError('Vendor download exceeds bound')
        return content


def write_once(path, content, mode=0o600):
    if path.exists():
        assert path.read_text() == content, 'Refuse to overwrite existing configuration: ' + str(path)
        return
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w') as stream:
        stream.write(content)


assert os.geteuid() == 0 and os.uname().machine == 'x86_64'
version = subprocess.check_output(['containerd', '--version'], text=True)
assert ' 2.' in version, 'This configuration targets containerd 2.x'
gvisor_url = 'https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/gvisor.tar.bz2'
gvisor_archive = download(gvisor_url)
gvisor_sha = hashlib.sha512(gvisor_archive).hexdigest()
assert download(gvisor_url + '.sha512', 4096).decode().split()[0] == gvisor_sha
gvisor = pathlib.Path('/usr/local/lib/aegisai-gvisor') / gvisor_sha[:16]
gvisor.mkdir(mode=0o755, parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(gvisor_archive), mode='r:bz2') as archive:
    archive.extractall(gvisor, filter='data')
runsc = gvisor / 'runsc'
shim = gvisor / 'containerd-shim-runsc-v1'
assert runsc.is_file() and shim.is_file()
runsc.chmod(0o755)
shim.chmod(0o755)

nerdctl_version = '2.4.2'
nerdctl_name = 'nerdctl-' + nerdctl_version + '-linux-amd64.tar.gz'
nerdctl_url = 'https://github.com/containerd/nerdctl/releases/download/v' + nerdctl_version + '/'
checksums = download(nerdctl_url + 'SHA256SUMS', 128 * 1024).decode().splitlines()
expected = next(line.split()[0] for line in checksums if line.split()[-1].lstrip('*') == nerdctl_name)
nerdctl_archive = download(nerdctl_url + nerdctl_name)
assert hashlib.sha256(nerdctl_archive).hexdigest() == expected
nerdctl_dir = pathlib.Path('/usr/local/lib/aegisai-nerdctl') / nerdctl_version
nerdctl_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(nerdctl_archive), mode='r:gz') as archive:
    member = next(member for member in archive.getmembers() if member.name.lstrip('./') == 'nerdctl')
    assert member.isfile()
    (nerdctl_dir / 'nerdctl').write_bytes(archive.extractfile(member).read())
(nerdctl_dir / 'nerdctl').chmod(0o755)

root = pathlib.Path('/opt/aegisai/scanner')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
config = '''version = 3
root = "/var/lib/aegisai-scan/containerd"
state = "/run/aegisai-scan/containerd"
disabled_plugins = ["io.containerd.cri.v1.runtime", "io.containerd.cri.v1.images"]
[grpc]
  address = "/run/aegisai-scan/containerd.sock"
  uid = 0
  gid = 0
[ttrpc]
  address = "/run/aegisai-scan/containerd-ttrpc.sock"
'''
write_once(root / 'containerd.toml', config)
unit = '''[Unit]
Description=AegisAI isolated scan containerd
After=network.target
[Service]
Type=notify
Environment=PATH=''' + str(gvisor) + ''':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/bin/containerd --config /opt/aegisai/scanner/containerd.toml
Restart=on-failure
RuntimeDirectory=aegisai-scan
RuntimeDirectoryMode=0700
Delegate=yes
MemoryMax=4G
CPUQuota=100%
TasksMax=1024
LimitNOFILE=65536
UMask=0022
[Install]
WantedBy=multi-user.target
'''
write_once(pathlib.Path('/etc/systemd/system/aegisai-scan-containerd.service'), unit, 0o644)
wrapper = '''#!/bin/sh
set -eu
export PATH=''' + str(gvisor) + ''':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec ''' + str(nerdctl_dir / 'nerdctl') + ''' --address /run/aegisai-scan/containerd.sock --namespace aegisai-scans "$@"
'''
write_once(root / 'nerdctl', wrapper, 0o700)
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemctl', 'enable', '--now', 'aegisai-scan-containerd'], check=True)
metadata = {'gvisorSource': gvisor_url, 'gvisorArchiveSha512': gvisor_sha,
            'runscVersion': subprocess.check_output([str(runsc), '--version'], text=True).strip(),
            'nerdctlVersion': nerdctl_version, 'nerdctlArchiveSha256': expected,
            'socket': '/run/aegisai-scan/containerd.sock', 'containerd': version.strip()}
(root / 'runtime-tools.json').write_text(json.dumps(metadata, indent=2))
print(json.dumps(metadata))
