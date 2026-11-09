"""Explicit 2026-11-09 owner approval: existing root volume 30 -> 50 GiB only."""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

from plan_guard import assert_no_secret_values, validate_no_changes


def validate_expansion(plan):
    assert not plan.get('errored') and plan.get('complete') is not False
    changes = [item for item in plan.get('resource_changes', []) if item['change']['actions'] != ['no-op']]
    assert len(changes) == 1
    item = changes[0]
    assert item['address'] == 'aws_instance.control' and item['change']['actions'] == ['update']
    before, after = copy.deepcopy(item['change']['before']), copy.deepcopy(item['change']['after'])
    assert before['id'] == after['id'] == 'i-0d24d0502cfc5a9c5'
    assert len(before['root_block_device']) == len(after['root_block_device']) == 1
    old, new = before['root_block_device'][0], after['root_block_device'][0]
    assert old['volume_id'] == new['volume_id'] == 'vol-06b3fb819818cd306'
    assert old['volume_size'] == 30 and new['volume_size'] == 50
    old['volume_size'] = new['volume_size']
    # Imported provider state has null; an update materializes its false default.
    if before.get('user_data_replace_on_change') is None and after.get('user_data_replace_on_change') is False:
        before['user_data_replace_on_change'] = False
    assert before == after, 'Unrelated resource attributes changed'
    assert_no_secret_values(plan.get('planned_values', {}))


def main():
    import fcntl
    from manage_terraform import ROOT, WORK, execution_environment
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    toolchain = json.loads(Path(__file__).with_name('toolchain.json').read_text())
    binary = ROOT / 'tools' / toolchain['terraformVersion'] / 'terraform'
    verified = json.loads(binary.with_name('verified-install.json').read_text())
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == verified['binarySha256']
    environment = execution_environment()
    log = ROOT / 'storage-expansion.log'

    def terraform(*arguments):
        result = subprocess.run([str(binary), *arguments], cwd=WORK, env=environment,
                                text=True, capture_output=True, timeout=600)
        with log.open('a') as stream:
            stream.write(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('Scoped storage operation failed: ' + arguments[0])
        return result.stdout

    with (ROOT / 'terraform-operator.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        config_path = WORK / 'main.tf.json'
        config = json.loads(config_path.read_text())
        block = config['resource']['aws_instance']['control']['root_block_device']
        assert block['volume_size'] in (30, 50) and block['encrypted'] is True
        block['volume_size'] = 50
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        plan_path = ROOT / 'plans/storage-50g.tfplan'
        terraform('plan', '-input=false', '-out=' + str(plan_path))
        plan = json.loads(terraform('show', '-json', str(plan_path)))
        validate_expansion(plan)
        terraform('apply', '-input=false', str(plan_path))
        confirmation = ROOT / 'plans/storage-50g-confirm.tfplan'
        terraform('plan', '-input=false', '-out=' + str(confirmation))
        validate_no_changes(json.loads(terraform('show', '-json', str(confirmation))))
        receipt = {'approvedRootVolumeGiB':50, 'volumeId':'vol-06b3fb819818cd306',
                   'terraformScope':'single-root-volume-size-only', 'terraformPlanAfter':'NO_CHANGES',
                   'newComputeCreated':False, 'filesystemExpanded':False,
                   'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}
        (ROOT / 'storage-expansion.json').write_text(json.dumps(receipt, indent=2))
        print(json.dumps(receipt))


if __name__ == '__main__':
    main()
