"""Native temporary-storage permissions, with synthetic input and UID probes only."""
import json
import os
import pathlib
import subprocess
import sys
import uuid

from runtime import JOBS, JobStorage, RuntimeFailure, job_key, mounts

assert os.geteuid() == 0
assert JOBS.stat().st_gid == 50001 and JOBS.stat().st_mode & 0o777 == 0o710


def gateway_probe(root, write):
    # Trusted fixture code, not customer code. Dropping all supplementary groups
    # also proves that no inherited operator group supplies filesystem access.
    program = '''import os,pathlib,sys
os.setgroups([]);os.setgid(50001);os.setuid(50001)
root=pathlib.Path(sys.argv[1])
try:
    (root/'source/Fixture.java').write_text('class Fixture {}')
    (root/'control/targets.json').write_text('[]')
except PermissionError:
    sys.exit(13)
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(root)],
                            capture_output=True, timeout=10)
    assert result.returncode == (0 if write else 13), 'Gateway filesystem permission mismatch'


results = {}
for scenario in ('sealed', 'symlink', 'hardlink'):
    storage = JobStorage(job_key('synthetic-storage', uuid.uuid4().hex))
    root = storage.prepare()
    try:
        gateway_probe(root, False)
        storage.grant_gateway_writer()
        gateway_probe(root, True)
        if scenario == 'symlink':
            (root/'source/link').symlink_to('/etc/passwd')
        elif scenario == 'hardlink':
            os.link(root/'source/Fixture.java', root/'source/other.java')
        if scenario == 'sealed':
            storage.seal()
            assert root.stat().st_uid == 0 and root.stat().st_mode & 0o777 == 0o700
            for directory in ('source', 'control'):
                assert (root/directory).stat().st_uid == 0
                assert (root/directory).stat().st_mode & 0o777 == 0o555
                for file in (root/directory).iterdir():
                    assert file.stat().st_uid == 0 and file.stat().st_mode & 0o777 == 0o444
            gateway_probe(root, False)
        else:
            try:
                storage.seal()
                raise AssertionError('Unsafe storage was accepted')
            except RuntimeFailure as error:
                assert str(error) == 'INVALID_SOURCE_STORAGE'
        results[scenario] = 'passed'
    finally:
        storage.cleanup()
    assert not root.exists() and str(root) not in mounts()
report = {'nativeStoragePermissions': results, 'gatewayUid': 50001,
          'sourceProcessed': 'synthetic-only', 'tmpfsCleanupVerified': True}
pathlib.Path('/opt/aegisai/scanner/storage-verification.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report))
