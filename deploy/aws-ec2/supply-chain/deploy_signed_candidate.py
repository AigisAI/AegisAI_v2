"""Only reviewed operator source can admit a signed candidate to deployment."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import subprocess

from verify_candidate import verify
from policy import strict_json

ROOT = Path('/opt/aegisai/operator')


def main():
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--approved-source',required=True)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    policy_path = ROOT/'supply-chain-required.json'
    if policy_path.exists():
        policy = strict_json(policy_path)
        if args.approved_source not in policy['approvedSources']:
            raise ValueError('SOURCE_NOT_OPERATOR_APPROVED')
    with (ROOT/'signed-deployment.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = verify(args.directory,args.manifest_sha256,args.approved_source,target=True)
        receipt['candidateDirectory'] = str(args.directory.resolve())
        receipts = ROOT/'signed-verification-receipts'
        receipts.mkdir(mode=0o700,exist_ok=True)
        path = receipts/(args.manifest_sha256+'.json')
        path.write_text(json.dumps(receipt,indent=2))
        if args.apply:
            trusted = Path(__file__).resolve().parents[3]/'tools/private-runtime/deploy-prepared.sh'
            subprocess.run(['sh',str(trusted),str(args.directory),args.manifest_sha256,'--apply'],
                env=dict(os.environ,AEGISAI_SIGNED_VERIFICATION_RECEIPT=str(path)),check=True,timeout=600)
        else:
            print(json.dumps(receipt))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('SIGNED_DEPLOYMENT_REJECTED: '+type(error).__name__)
        raise SystemExit(1)
