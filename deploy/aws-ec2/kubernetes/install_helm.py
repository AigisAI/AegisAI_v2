"""Extract only the checksum-pinned vendor executable, never an install script."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.request
import zipfile


def install(destination):
    pins=json.loads(Path(__file__).with_name('toolchain.json').read_text())['helm']
    system='windows' if platform.system()=='Windows' else 'linux'
    if system=='linux':assert os.geteuid()==0
    selected=pins[system]
    assert not destination.is_symlink()
    destination.parent.mkdir(parents=True,exist_ok=True)
    with urllib.request.urlopen(selected['url'],timeout=30) as response:
        content=response.read(128*1024**2+1)
    assert len(content)<=128*1024**2 and hashlib.sha256(content).hexdigest()==selected['sha256']
    if system=='windows':
        with zipfile.ZipFile(io.BytesIO(content)) as archive:binary=archive.read(selected['member'])
    else:
        with tarfile.open(fileobj=io.BytesIO(content),mode='r:gz') as archive:
            member=archive.getmember(selected['member']);assert member.isfile() and member.size<256*1024**2
            binary=archive.extractfile(member).read()
    assert not destination.exists(), 'DO_NOT_OVERWRITE_EXISTING_TOOL'
    destination.write_bytes(binary);destination.chmod(0o755)
    proof={'version':pins['version'],'archiveSha256':selected['sha256'],
           'binarySha256':hashlib.sha256(binary).hexdigest()}
    destination.with_name('verified-install.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('destination',type=Path)
    install(parser.parse_args().destination)
