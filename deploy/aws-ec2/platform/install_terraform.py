"""Install vendor-checksummed tooling in the protected operator area only."""
import hashlib
import io
import json
import os
import pathlib
import subprocess
import urllib.request
import zipfile


def install():
    assert os.geteuid() == 0
    os.umask(0o077)
    config = json.loads(pathlib.Path(__file__).with_name('toolchain.json').read_text())
    base = pathlib.Path('/opt/aegisai/platform')
    assert not base.is_symlink()
    base.mkdir(mode=0o700, exist_ok=True)
    assert base.stat().st_uid == 0 and base.stat().st_mode & 0o077 == 0
    target = base / 'tools' / config['terraformVersion']
    binary = target / 'terraform'
    version = config['terraformVersion']
    if not binary.exists():
        assert __import__('shutil').disk_usage(base).free > 3 * 1024 ** 3 + 200 * 1024 ** 2
        url = f'https://releases.hashicorp.com/terraform/{version}/terraform_{version}_linux_amd64.zip'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(128 * 1024 ** 2 + 1)
        assert len(data) <= 128 * 1024 ** 2
        assert hashlib.sha256(data).hexdigest() == config['terraformArchiveSha256']
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert set(archive.namelist()) <= {'terraform', 'LICENSE.txt'}
            assert archive.getinfo('terraform').file_size <= 200 * 1024 ** 2
            content = archive.read('terraform')
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        with binary.open('xb') as output:
            output.write(content)
        binary.chmod(0o700)
        (target / 'verified-install.json').write_text(json.dumps({
            'version': version, 'archiveSha256': config['terraformArchiveSha256'],
            'binarySha256': hashlib.sha256(content).hexdigest()}))
    recorded = json.loads((target / 'verified-install.json').read_text())
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == recorded['binarySha256']
    result = json.loads(subprocess.check_output([str(binary), 'version', '-json'], text=True))
    assert result['terraform_version'] == version
    print(json.dumps({'terraformInstalled': version, 'vendorChecksumVerified': True,
                      'applicationModified': False, 'cloudResourcesModified': False}))


if __name__ == '__main__':
    install()
