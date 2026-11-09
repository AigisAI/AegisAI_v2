"""Bounded lock, simulated-state drift and destruction-plan safety proofs."""
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from manage_terraform import ROOT, WORK, execution_environment
from plan_guard import assert_no_secret_values


def prove():
    assert os.geteuid() == 0
    os.umask(0o077)
    toolchain = json.loads(pathlib.Path(__file__).with_name('toolchain.json').read_text())
    binary = ROOT / 'tools' / toolchain['terraformVersion'] / 'terraform'
    state_path = WORK / 'state/terraform.tfstate'
    before = hashlib.sha256(state_path.read_bytes()).hexdigest()
    with (ROOT / 'terraform-operator.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        collision = subprocess.run(['python3', '-E', '-s', '-B',
            str(pathlib.Path(__file__).with_name('manage_terraform.py')), 'plan'],
            text=True, capture_output=True, timeout=15)
        assert collision.returncode == 1 and 'TERRAFORM_OPERATOR_LOCKED' in collision.stderr
        directory = pathlib.Path(tempfile.mkdtemp(prefix='aegisai-tf-drift340-', dir='/dev/shm'))
        try:
            shutil.copyfile(WORK / 'main.tf.json', directory / 'main.tf.json')
            shutil.copyfile(WORK / '.terraform.lock.hcl', directory / '.terraform.lock.hcl')
            target = directory / 'state'
            target.mkdir(mode=0o700)
            state = json.loads(state_path.read_text())
            assert_no_secret_values(state)
            for resource in state['resources']:
                if resource['type'] == 'aws_s3_bucket' and resource['name'] == 'private':
                    attributes = resource['instances'][0]['attributes']
                    attributes['tags']['ManagedBy'] = 'state-only-drift-proof'
                    attributes['tags_all']['ManagedBy'] = 'state-only-drift-proof'
                    break
            else:
                raise RuntimeError('DRIFT_PROOF_RESOURCE_MISSING')
            (target / 'terraform.tfstate').write_text(json.dumps(state))

            def terraform(*arguments):
                return subprocess.run([str(binary), *arguments], cwd=directory,
                    env=execution_environment(), text=True, capture_output=True, timeout=180)

            initialized = terraform('init', '-input=false', '-lockfile=readonly')
            assert initialized.returncode == 0, 'DRIFT_PROOF_INIT_FAILED'
            planned = terraform('plan', '-refresh-only', '-input=false',
                                 '-detailed-exitcode', '-out=drift.tfplan')
            assert planned.returncode == 2, 'SIMULATED_STATE_DRIFT_NOT_DETECTED'
            shown = terraform('show', '-json', 'drift.tfplan')
            assert shown.returncode == 0
            result = json.loads(shown.stdout)
            drift = [item for item in result.get('resource_drift', [])
                     if item['address'] == 'aws_s3_bucket.private']
            assert drift and drift[0]['change']['actions'] == ['update']
            rejected = terraform('plan', '-destroy', '-refresh=false', '-input=false')
            assert rejected.returncode == 1 and 'prevent_destroy' in rejected.stderr
        finally:
            assert directory.parent == pathlib.Path('/dev/shm') and directory.name.startswith('aegisai-tf-drift340-')
            shutil.rmtree(directory)
    assert hashlib.sha256(state_path.read_bytes()).hexdigest() == before
    report = {'operatorConcurrencyLock': 'passed', 'simulatedStateDriftAgainstLiveAws': 'detected',
        'destructionPlan': 'rejected', 'productionStateUnchanged': True,
        'cloudConfigurationModified': False, 'applicationModified': False,
        'fullEnvironmentReconstructionVerified': False,
        'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    (ROOT / 'terraform-safety-proof.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    prove()
