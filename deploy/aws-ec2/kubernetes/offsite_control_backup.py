"""Upload and restore one protected control snapshot through existing S3 storage."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import uuid

from bootstrap import ROOT, digest, now

ACCOUNT = '024139495514'
BUCKET = 'aegisai-private-024139495514-apne2'
OPERATOR = Path('/opt/aegisai/operator')
BACKUPS = ROOT / 'control-backups'
MEMBERS = ('state.db', 'token', 'encryption-config.json', 'application-traffic.json')
LIMIT = 64 * 1024**2


def aws(*args, runtime=False, denied=False):
    environment = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': '/root', 'AWS_PAGER': '', 'AWS_CONFIG_FILE': '/dev/null',
        'AWS_SHARED_CREDENTIALS_FILE': '/dev/null', 'AWS_EC2_METADATA_V1_DISABLED': 'true'}
    command = ['/usr/local/lib/aegisai-aws-cli/aws', '--region', 'ap-northeast-2']
    if not runtime:
        environment.update(AWS_CONFIG_FILE='/opt/aegisai/platform/operator-aws-config',
            AWS_PROFILE='aegisai-terraform', AWS_SDK_LOAD_CONFIG='1', AWS_EC2_METADATA_DISABLED='true')
    result = subprocess.run([*command, *args, '--output', 'json'], env=environment,
        capture_output=True, text=True, timeout=90)
    if denied:
        assert result.returncode and ('403' in result.stderr or 'AccessDenied' in result.stderr)
        return None
    if result.returncode:
        if 'session has expired' in result.stderr:
            raise RuntimeError('AWS_OPERATOR_SESSION_EXPIRED')
        raise RuntimeError('CONTROL_BACKUP_AWS_CALL_FAILED: '+args[0]+' '+args[1])
    return json.loads(result.stdout)


def check_bucket():
    identity = aws('sts', 'get-caller-identity')
    assert identity['Account'] == ACCOUNT and identity['Arn'] == f'arn:aws:iam::{ACCOUNT}:user/goodtu02'
    flags = aws('s3api', 'get-public-access-block', '--bucket', BUCKET)['PublicAccessBlockConfiguration']
    assert all(flags.get(key) is True for key in ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets'))
    ownership = aws('s3api','get-bucket-ownership-controls','--bucket',BUCKET)['OwnershipControls']['Rules']
    assert ownership == [{'ObjectOwnership':'BucketOwnerEnforced'}]
    policy = json.loads(aws('s3api','get-bucket-policy','--bucket',BUCKET)['Policy'])
    assert policy['Statement'] and all(statement['Effect'] == 'Deny' for statement in policy['Statement'])
    assert aws('s3api','get-bucket-policy-status','--bucket',BUCKET)['PolicyStatus']['IsPublic'] is False
    plane = json.loads((OPERATOR/'data-plane-state.json').read_text())
    assert plane['bucket'] == BUCKET and plane['existingInstanceId'] == 'i-0d24d0502cfc5a9c5'
    rules = aws('s3api','get-bucket-encryption','--bucket',BUCKET)['ServerSideEncryptionConfiguration']['Rules']
    assert len(rules) == 1
    settings = rules[0]['ApplyServerSideEncryptionByDefault']
    assert settings == {'SSEAlgorithm':'aws:kms'}
    role = aws('sts','get-caller-identity',runtime=True)
    assert role['Arn'].startswith(f'arn:aws:sts::{ACCOUNT}:assumed-role/aegisai-private-runtime/')
    prior = json.loads(Path('/opt/aegisai/platform/terraform-state-backup.json').read_text())['objectKey']
    assert prior.startswith('infrastructure-state/340/')
    aws('s3api','head-object','--bucket',BUCKET,'--key',prior,runtime=True,denied=True)
    return plane['kmsKeyArn']


def archive(backup, destination):
    assert backup.resolve() == backup and backup.parent == BACKUPS
    assert backup.stat().st_uid == 0 and not backup.stat().st_mode & 0o077
    with tarfile.open(destination, 'w:gz') as bundle:
        for name in MEMBERS:
            source = backup/name
            assert source.is_file() and not source.is_symlink()
            assert source.stat().st_uid == 0 and not source.stat().st_mode & 0o077
            assert 0 < source.stat().st_size < LIMIT
            bundle.add(source, arcname=name, recursive=False)


def extract(source, destination):
    with tarfile.open(source, 'r:gz') as bundle:
        members = bundle.getmembers()
        assert len(members) == len(MEMBERS) and {item.name for item in members} == set(MEMBERS)
        assert all(item.isfile() and 0 < item.size < LIMIT for item in members)
        bundle.extractall(destination, filter='data')
    for name in MEMBERS:
        (destination/name).chmod(0o600)


def round_trip(backup):
    kms_key = check_bucket()
    context = base64.b64encode(json.dumps({'purpose':'private-kubernetes-control-recovery'}).encode()).decode()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    key = f'infrastructure-state/340/control/{stamp}-{uuid.uuid4().hex}.tar.gz'
    with tempfile.TemporaryDirectory(prefix='offsite-transfer-', dir=BACKUPS) as temporary:
        directory = Path(temporary)
        outgoing, incoming = directory/'upload.tar.gz', directory/'download.tar.gz'
        archive(backup, outgoing)
        checksum = digest(outgoing)
        result = aws('s3api','put-object','--bucket',BUCKET,'--key',key,'--body',str(outgoing),
            '--server-side-encryption','aws:kms','--ssekms-key-id',kms_key,
            '--ssekms-encryption-context',context,'--if-none-match','*','--checksum-algorithm','SHA256')
        assert result['ServerSideEncryption'] == 'aws:kms' and result['SSEKMSKeyId'] == kms_key
        received = aws('s3api','get-object','--bucket',BUCKET,'--key',key,str(incoming))
        assert received['ServerSideEncryption'] == 'aws:kms' and received['SSEKMSKeyId'] == kms_key
        assert digest(incoming) == checksum
        aws('s3api','head-object','--bucket',BUCKET,'--key',key,runtime=True,denied=True)
        with tempfile.TemporaryDirectory(prefix='offsite-restore-', dir=BACKUPS) as target:
            extract(incoming, Path(target))
            subprocess.run(['python3','-B',str(Path(__file__).with_name('control_recovery.py')),
                'rehearse',target], check=True, timeout=155)
        report = {'offsiteControlRestore':'passed','objectKey':key,'compressedBytes':outgoing.stat().st_size,
            'sha256':checksum,'kmsEncryptionVerified':True,'runtimeObjectReadDenied':True,'verifiedAt':now()}
    (ROOT/'offsite-control-recovery-result.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    round_trip(parser.parse_args().backup)
