"""Install only exact vendor-checksummed operator tools; no app credentials."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path('/opt/aegisai/platform/tools/supply-chain')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ci',action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0 and __debug__
    assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
    os.umask(0o022 if args.ci else 0o077)
    root = Path('/opt/aegisai-ci-supply-chain-tools') if args.ci else ROOT
    pins = json.loads(Path(__file__).with_name('toolchain.json').read_text())
    root.mkdir(mode=0o755 if args.ci else 0o700, parents=True, exist_ok=True)
    assert not root.is_symlink() and root.stat().st_uid == 0
    root.chmod(0o755 if args.ci else 0o700)
    for name in ('trivy','gh'):
        pin = pins[name]
        directory = root/name/pin['version']
        directory.mkdir(mode=0o755 if args.ci else 0o700, parents=True, exist_ok=True)
        directory.parent.chmod(0o755 if args.ci else 0o700)
        directory.chmod(0o755 if args.ci else 0o700)
        binary = directory/name
        proof = directory/'verified-install.json'
        if binary.exists():
            assert not binary.is_symlink() and proof.is_file()
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == json.loads(proof.read_text())['binarySha256']
            continue
        assert pin['url'].startswith('https://github.com/')
        with tempfile.TemporaryDirectory(dir=directory) as temporary:
            archive = Path(temporary)/'vendor.tar.gz'
            checksum = hashlib.sha256()
            with urllib.request.urlopen(pin['url'],timeout=60) as response, archive.open('wb') as target:
                total = 0
                while chunk := response.read(1024*1024):
                    total += len(chunk)
                    assert total <= 256*1024**2
                    checksum.update(chunk)
                    target.write(chunk)
            assert checksum.hexdigest() == pin['sha256'], 'VENDOR_ARCHIVE_DIGEST_MISMATCH'
            with tarfile.open(archive,'r:gz') as source:
                member = source.getmember(pin['member'])
                assert member.isfile() and 0 < member.size <= 512*1024**2
                stage = Path(temporary)/name
                with source.extractfile(member) as incoming, stage.open('wb') as target:
                    shutil.copyfileobj(incoming,target)
                stage.chmod(0o755)
                subprocess.run([str(stage),'--version'],check=True,timeout=10)
                os.replace(stage,binary)
            proof.write_text(json.dumps({'name':name,'version':pin['version'],
                'archiveSha256':pin['sha256'],'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2))
            os.chown(proof,0,0)
            proof.chmod(0o644 if args.ci else 0o600)
            assert proof.stat().st_uid == 0 and proof.stat().st_mode & 0o022 == 0
        print(json.dumps({'verifiedOperatorTool':name,'version':pin['version'],'applicationChanged':False}))


if __name__ == '__main__':
    main()
