"""Root-only bounded retention of admitted images, separate from traffic ownership."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from bootstrap import BINARY, ROOT, PIN, digest, now, snapshot

OPERATOR = Path('/opt/aegisai/operator')
SOCKET = 'unix:///run/k3s/containerd/containerd.sock'
OWNER = 'io.aegisai.approved-retention'


def ctr(*args):
    return subprocess.check_output([str(BINARY), 'ctr', '-n', 'k8s.io', *args], text=True, timeout=30)


def inventory():
    return json.loads(subprocess.check_output([str(BINARY), 'crictl', '--config', '/dev/null',
        '--runtime-endpoint', SOCKET, '--image-endpoint', SOCKET, 'images', '--output', 'json'],
        text=True, timeout=30))['images']


def require_pinned(images):
    rows = inventory()
    for kind, image in images.items():
        reference = image['reference']
        assert kind in ('api', 'web') and re.fullmatch(
            r'docker.io/library/aegisai-' + kind + r'@sha256:[a-f0-9]{64}', reference)
        matches = [row for row in rows if reference in row.get('repoDigests', [])]
        assert len(matches) == 1 and matches[0].get('pinned') is True, 'APPROVED_IMAGE_NOT_PRESENT_AND_PINNED'


def pin(canonical, reference):
    assert re.fullmatch(r'docker.io/library/aegisai-(api|web):ec2-runtime-[0-9]{8}-[0-9]{6}', canonical)
    assert reference.split('@')[0] == canonical.split(':')[0]
    for name in (canonical, reference):
        ctr('images', 'label', name, 'io.cri-containerd.pinned=pinned', OWNER + '=true')


def trim_owned_pins(releases):
    # Remove only our own retention labels. Never remove image content or vendor pins.
    keep = {image['reference'] for release in releases for image in release['images'].values()}
    rows = inventory()
    retained_ids = {row['id'] for row in rows if keep.intersection(row.get('repoDigests', []))}
    aliases = {name for row in rows if row['id'] in retained_ids
               for name in row.get('repoTags', []) + row.get('repoDigests', [])}
    owned = ctr('images', 'ls', '-q', 'labels."' + OWNER + '"==true').splitlines()
    for name in owned:
        assert re.fullmatch(r'docker.io/library/aegisai-(api|web)(:ec2-runtime-[0-9]{8}-[0-9]{6}|@sha256:[a-f0-9]{64})', name)
        if name not in aliases:
            ctr('images', 'label', name, 'io.cri-containerd.pinned=', OWNER + '=')


def candidate_directory(release):
    matches = []
    for directory in (OPERATOR / 'candidates').iterdir():
        manifest = directory / 'candidate.json'
        if re.fullmatch(r'ec2-runtime-[0-9]{8}-[0-9]{6}', directory.name) and manifest.is_file():
            if hashlib.sha256(manifest.read_bytes()).hexdigest() == release['manifestSha256']:
                matches.append(directory)
    assert len(matches) == 1, 'SIGNED_ARCHIVE_NOT_UNIQUE'
    return matches[0]


def ensure(release):
    directory = candidate_directory(release)
    manifest = json.loads((directory / 'candidate.json').read_text())
    missing = [kind for kind, image in release['images'].items() if not any(
        image['reference'] in row.get('repoDigests', []) for row in inventory())]
    if missing:
        trusted = OPERATOR / 'supply-chain/current/deploy/aws-ec2/supply-chain'
        assert trusted.resolve().is_relative_to(OPERATOR / 'supply-chain/releases')
        for name in ('verify_candidate.py', 'policy.py'):
            path = trusted / name
            assert path.stat().st_uid == 0 and not path.stat().st_mode & 0o022
        sys.path.insert(0, str(trusted))
        from verify_candidate import verify
        receipt = verify(directory, release['manifestSha256'], release['approvedSource'], target=True)
        assert receipt['signedCandidateVerification'] == 'passed'
    for kind, image in release['images'].items():
        archive = manifest['images'][kind]
        canonical = 'docker.io/library/' + archive['tag']
        if kind in missing:
            process = subprocess.Popen([str(BINARY), 'ctr', '-n', 'k8s.io', 'images', 'import',
                '--digests', '--no-unpack', '-'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL)
            try:
                with gzip.open(directory / archive['archive'], 'rb') as stream:
                    shutil.copyfileobj(stream, process.stdin)
                process.stdin.close()
                assert process.wait(timeout=90) == 0, 'IMAGE_RESTORE_FAILED'
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()
        rows = ctr('images', 'ls').splitlines()
        targets = [row.split()[2] for row in rows if row.split() and row.split()[0] == canonical]
        assert targets == [image['importedTargetDigest']], 'RESTORED_DIGEST_MISMATCH'
        assert image['reference'] == canonical.split(':')[0] + '@' + targets[0]
        ctr('images', 'tag', '--force', canonical, image['reference'])
        pin(canonical, image['reference'])
    for _ in range(20):
        try:
            require_pinned(release['images'])
            return missing
        except AssertionError:
            time.sleep(0.5)
    require_pinned(release['images'])


def main():
    import fcntl
    assert os.geteuid() == 0 and __debug__; os.umask(0o077)
    argparse.ArgumentParser(description=__doc__).parse_args()
    lock = (OPERATOR / 'signed-deployment.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert digest(BINARY) == PIN['binary']['sha256']
    path = ROOT / 'approved-app-images.json'
    assert not path.is_symlink() and path.stat().st_uid == 0 and not path.stat().st_mode & 0o077
    ledger = json.loads(path.read_text()); releases = ledger.get('approvedReleases', [ledger])
    assert 1 <= len(releases) <= 2
    before = snapshot(); traffic = (OPERATOR / 'application-traffic.json').read_bytes()
    results = []
    for release in releases:
        restored = ensure(release)
        results.append({'source': release['approvedSource'], 'restored': restored,
            'references': [image['reference'] for image in release['images'].values()], 'criPinned': True})
    trim_owned_pins(releases)
    assert snapshot() == before and (OPERATOR / 'application-traffic.json').read_bytes() == traffic
    result = {'approvedImageRetention': 'passed', 'releases': results,
        'trafficUnchanged': True, 'verifiedAt': now()}
    (ROOT / 'image-retention-result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
