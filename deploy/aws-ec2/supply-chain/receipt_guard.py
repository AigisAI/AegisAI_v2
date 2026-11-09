"""Reject direct legacy deploy invocation after signature policy activation."""
import datetime
import os
from pathlib import Path
import sys

from policy import digest, strict_json, timestamp

ROOT = Path('/opt/aegisai/operator')


def main():
    assert os.geteuid() == 0 and __debug__
    directory, expected = Path(sys.argv[1]).resolve(), sys.argv[2]
    raw = os.environ.get('AEGISAI_SIGNED_VERIFICATION_RECEIPT','')
    path = Path(raw)
    assert raw and not path.is_symlink() and path.resolve().parent == ROOT/'signed-verification-receipts'
    assert path.stat().st_uid == 0 and path.stat().st_mode & 0o077 == 0
    receipt = strict_json(path)
    manifest = strict_json(directory/'candidate.json')
    policy = strict_json(ROOT/'supply-chain-required.json')
    assert receipt['signedCandidateVerification'] == 'passed' and receipt['targetChecked'] is True
    assert receipt['candidateDirectory'] == str(directory)
    assert receipt['manifestSha256'] == expected == digest(directory/'candidate.json')
    assert receipt['sourceCommit'] == manifest['sourceCommit'] and manifest['sourceCommit'] in policy['approvedSources']
    age = (datetime.datetime.now(datetime.timezone.utc)-timestamp(receipt['verifiedAt'])).total_seconds()
    assert 0 <= age <= 300, 'SIGNED_VERIFICATION_RECEIPT_EXPIRED'
    for item in manifest['files']:
        assert Path(item['name']).name == item['name']
        assert digest(directory/item['name']) == item['sha256']


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('TRUSTED_SIGNED_DEPLOYMENT_ENTRYPOINT_REQUIRED')
        raise SystemExit(1)
