"""Create-only, encrypted operator state snapshot; never restore production state."""
import base64
import datetime
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import uuid

from manage_terraform import ROOT, WORK, execution_environment
from plan_guard import assert_no_secret_values, validate_no_changes


def backup():
    assert os.geteuid() == 0
    os.umask(0o077)
    import fcntl
    with (ROOT / 'terraform-operator.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source = WORK / 'state/terraform.tfstate'
        raw = source.read_bytes()
        assert_no_secret_values(json.loads(raw))
        data = gzip.compress(raw, mtime=0)
        data_plane = json.loads(pathlib.Path('/opt/aegisai/operator/data-plane-state.json').read_text())
        assert data_plane['existingInstanceId'] == 'i-0d24d0502cfc5a9c5'
        key = 'infrastructure-state/340/' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex + '.tfstate.json.gz'
        directory = pathlib.Path(tempfile.mkdtemp(prefix='aegisai-tf-backup340-', dir='/dev/shm'))
        try:
            archive = directory / 'state.json.gz'
            download = directory / 'download.json.gz'
            archive.write_bytes(data)
            environment = execution_environment()
            cli = '/usr/local/lib/aegisai-aws-cli/aws'

            def aws(*arguments):
                reply = subprocess.run([cli, '--region', 'ap-northeast-2', *arguments],
                    env=environment, capture_output=True, text=True, timeout=40)
                assert reply.returncode == 0, 'OPERATOR_STATE_BACKUP_OPERATION_FAILED'
                return json.loads(reply.stdout) if reply.stdout.strip() else {}

            identity = aws('sts', 'get-caller-identity')
            assert identity['Account'] == '024139495514' and ':user/' in identity['Arn']
            context = base64.b64encode(json.dumps({'purpose': 'terraform-state',
                'instanceId': data_plane['existingInstanceId']}).encode()).decode()
            uploaded = aws('s3api', 'put-object', '--bucket', data_plane['bucket'], '--key', key,
                '--body', str(archive), '--server-side-encryption', 'aws:kms',
                '--ssekms-key-id', data_plane['kmsKeyArn'], '--ssekms-encryption-context', context,
                '--if-none-match', '*', '--checksum-algorithm', 'SHA256')
            assert uploaded['ServerSideEncryption'] == 'aws:kms'
            assert uploaded['SSEKMSKeyId'] == data_plane['kmsKeyArn']
            received = aws('s3api', 'get-object', '--bucket', data_plane['bucket'], '--key', key, str(download))
            assert received['ServerSideEncryption'] == 'aws:kms'
            assert download.read_bytes() == data and gzip.decompress(download.read_bytes()) == raw
            runtime_environment = {'PATH': environment['PATH'], 'HOME': '/root',
                'AWS_CONFIG_FILE': '/dev/null', 'AWS_SHARED_CREDENTIALS_FILE': '/dev/null',
                'AWS_EC2_METADATA_V1_DISABLED': 'true', 'AWS_PAGER': ''}
            denied = subprocess.run([cli, '--region', 'ap-northeast-2', 's3api', 'head-object',
                '--bucket', data_plane['bucket'], '--key', key], env=runtime_environment,
                text=True, capture_output=True, timeout=30)
            assert denied.returncode != 0 and ('403' in denied.stderr or 'AccessDenied' in denied.stderr), 'RUNTIME_MUST_NOT_READ_TERRAFORM_STATE'
            probe = directory / 'restore-verification'
            probe.mkdir(mode=0o700)
            shutil.copyfile(WORK / 'main.tf.json', probe / 'main.tf.json')
            shutil.copyfile(WORK / '.terraform.lock.hcl', probe / '.terraform.lock.hcl')
            (probe / 'state').mkdir(mode=0o700)
            (probe / 'state/terraform.tfstate').write_bytes(gzip.decompress(download.read_bytes()))
            version = json.loads(pathlib.Path(__file__).with_name('toolchain.json').read_text())['terraformVersion']
            binary = ROOT / 'tools' / version / 'terraform'
            initialized = subprocess.run([str(binary), 'init', '-input=false', '-lockfile=readonly'],
                cwd=probe, env=environment, text=True, capture_output=True, timeout=180)
            assert initialized.returncode == 0, 'STATE_RESTORE_PROBE_INIT_FAILED'
            planned = subprocess.run([str(binary), 'plan', '-input=false', '-detailed-exitcode', '-out=restored.tfplan'],
                cwd=probe, env=environment, text=True, capture_output=True, timeout=180)
            assert planned.returncode == 0, 'RESTORED_STATE_NOT_NOOP'
            shown = subprocess.check_output([str(binary), 'show', '-json', 'restored.tfplan'],
                cwd=probe, env=environment, text=True, timeout=30)
            validate_no_changes(json.loads(shown))
        finally:
            assert directory.parent == pathlib.Path('/dev/shm') and directory.name.startswith('aegisai-tf-backup340-')
            shutil.rmtree(directory)
        assert source.read_bytes() == raw
        report = {'encryptedOperatorStateBackup': 'passed', 'objectKey': key,
            'compressedBytes': len(data), 'compressedSha256': hashlib.sha256(data).hexdigest(),
            'stateSha256': hashlib.sha256(raw).hexdigest(), 'transferHashMatched': True,
            'isolatedRestoredStatePlan': 'NO_CHANGES', 'productionStateUnchanged': True,
            'runtimeRoleObjectRead': 'denied', 'kmsKeyManager': 'AWS',
            'snapshotRetentionAutomation': 'not-yet-configured',
            'fullEnvironmentReconstructionVerified': False,
            'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        (ROOT / 'terraform-state-backup.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report))


if __name__ == '__main__':
    backup()
