"""Existing-resource import and no-op plan only. There is intentionally no apply."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

from plan_guard import assert_no_secret_values, validate_no_changes


ROOT = pathlib.Path('/opt/aegisai/platform')
WORK = ROOT / 'terraform'


def execution_environment():
    return {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': '/root', 'LANG': 'C.UTF-8', 'TF_INPUT': '0', 'TF_IN_AUTOMATION': '1',
        'CHECKPOINT_DISABLE': '1', 'TF_PLUGIN_CACHE_DIR': str(pathlib.Path('/dev/shm/aegisai-terraform-provider-cache')),
        'AWS_CONFIG_FILE': str(ROOT / 'operator-aws-config'), 'AWS_SHARED_CREDENTIALS_FILE': '/dev/null',
        'AWS_PROFILE': 'aegisai-terraform', 'AWS_SDK_LOAD_CONFIG': '1', 'AWS_EC2_METADATA_DISABLED': 'true'}


def run(action):
    assert os.geteuid() == 0
    os.umask(0o077)
    assert not ROOT.is_symlink() and not WORK.is_symlink()
    assert WORK.stat().st_uid == 0 and WORK.stat().st_mode & 0o077 == 0
    toolchain = json.loads(pathlib.Path(__file__).with_name('toolchain.json').read_text())
    binary = ROOT / 'tools' / toolchain['terraformVersion'] / 'terraform'
    installation = json.loads(binary.with_name('verified-install.json').read_text())
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == installation['binarySha256']
    cache = pathlib.Path('/dev/shm/aegisai-terraform-provider-cache')
    assert subprocess.check_output(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(cache.parent)], text=True).strip() == 'tmpfs'
    cache.mkdir(mode=0o700, exist_ok=True)
    assert not cache.is_symlink() and cache.stat().st_uid == 0 and cache.stat().st_mode & 0o077 == 0
    aws_config = ROOT / 'operator-aws-config'
    if not aws_config.exists():
        aws_config.write_text('[profile aegisai-terraform]\ncredential_process = /opt/aegisai/operator/aws-cli.sh configure export-credentials --format process\nregion = ap-northeast-2\n')
    assert aws_config.stat().st_uid == 0 and aws_config.stat().st_mode & 0o077 == 0
    environment = execution_environment()
    log = ROOT / 'terraform-operation.log'

    def terraform(*arguments, accepted=(0,)):
        result = subprocess.run([str(binary), *arguments], cwd=WORK, env=environment,
                                capture_output=True, text=True, timeout=300)
        with log.open('a') as stream:
            stream.write(result.stdout + result.stderr)
        if result.returncode not in accepted:
            raise RuntimeError('TERRAFORM_OPERATION_FAILED: ' + arguments[0])
        return result

    with (ROOT / 'terraform-operator.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('TERRAFORM_OPERATOR_LOCKED') from None
        terraform('init', '-input=false')
        terraform('fmt', '-check')
        terraform('validate', '-json')
        if action == 'import':
            existing = terraform('state', 'list', accepted=(0, 1)).stdout.splitlines()
            imports = json.loads((WORK / 'imports.json').read_text())
            for address, identity in imports.items():
                if address in existing:
                    continue
                if address == 'aws_instance.control':
                    userdata = subprocess.run(['/opt/aegisai/operator/aws-cli.sh', 'ec2',
                        'describe-instance-attribute', '--instance-id', identity, '--attribute', 'userData',
                        '--output', 'json'], capture_output=True, text=True, timeout=30)
                    assert userdata.returncode == 0
                    assert not json.loads(userdata.stdout).get('UserData', {}).get('Value'), 'NONEMPTY_USERDATA_NOT_ADOPTED'
                terraform('import', '-input=false', address, identity)
                state = json.loads((WORK / 'state/terraform.tfstate').read_text())
                assert_no_secret_values(state)
                print(json.dumps({'resourceImported': address, 'cloudResourceModified': False}), flush=True)
        if action == 'init':
            print(json.dumps({'terraformInitialized': True, 'applicationModified': False}))
            return
        plans = ROOT / 'plans'
        plans.mkdir(mode=0o700, exist_ok=True)
        path = plans / 'current.tfplan'
        planned = terraform('plan', '-input=false', '-detailed-exitcode', '-out=' + str(path), accepted=(0, 2))
        plan = json.loads(terraform('show', '-json', str(path)).stdout)
        assert_no_secret_values(plan.get('planned_values', {}))
        validate_no_changes(plan)
        assert planned.returncode == 0
        state_path = WORK / 'state/terraform.tfstate'
        state = json.loads(state_path.read_text())
        assert_no_secret_values(state)
        assert state_path.stat().st_mode & 0o077 == 0
        receipt = {'terraformPlan': 'NO_CHANGES', 'cloudResourcesModified': False,
            'applicationModified': False, 'newComputeCreated': False,
            'resourceCount': len(terraform('state', 'list').stdout.splitlines()),
            'sourceConfigSha256': hashlib.sha256((WORK / 'main.tf.json').read_bytes()).hexdigest(),
            'stateSha256': hashlib.sha256(state_path.read_bytes()).hexdigest(),
            'protectedState': True, 'stateBackend': 'local-encrypted-existing-root',
            'operatorCredentialProcess': True, 'runtimeRoleExpanded': False,
            'fullEnvironmentReconstructionVerified': False,
            'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        (ROOT / 'terraform-readiness.json').write_text(json.dumps(receipt, indent=2))
        print(json.dumps(receipt))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'import', 'plan'])
    args = parser.parse_args()
    try:
        run(args.action)
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
