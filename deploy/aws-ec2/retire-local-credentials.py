"""Retire only managed-secret-equivalent active legacy copies; never history/EBS."""
import json
import os
import sys

from managed_runtime import ROOT, load_bundles, plan_retirement, recover_to_ram, retire, validate_running_configuration

assert os.geteuid() == 0
os.umask(0o077)
try:
    mode = sys.argv[1] if len(sys.argv) == 2 else '--plan'
    assert mode in ('--plan', '--apply', '--recover-to-ram')
    if mode == '--apply':
        report = retire()
    elif mode == '--recover-to-ram':
        report = recover_to_ram()
    else:
        state, bundles = load_bundles()
        validate_running_configuration()
        if (ROOT / 'operator/retired-local-credentials.json').exists():
            report = {**retire(), 'changesApplied': False}
        else:
            manifest, _, _ = plan_retirement(ROOT, state, bundles)
            report = {'retirementReady': True, 'files': [item['path'] for item in manifest['files']], 'changesApplied': False}
    print(json.dumps(report))
except Exception:
    print('LOCAL_CREDENTIAL_MAINTENANCE_BLOCKED', file=sys.stderr)
    raise SystemExit(1) from None
