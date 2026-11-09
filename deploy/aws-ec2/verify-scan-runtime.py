"""Trusted fixture only; no repository input or SCM credentials are used."""
import json
import pathlib
import subprocess
import uuid

CLI = '/opt/aegisai/scanner/nerdctl'
name = 'aegisai-isolation-verify-' + uuid.uuid4().hex
image = 'docker.io/library/alpine:3.22'
metadata = json.loads(subprocess.check_output([CLI, 'image', 'inspect', image], text=True))[0]
digest = metadata['RepoDigests'][0]
assert '@sha256:' in digest
checks = '''set -eu
test "$(id -u)" = "65532"
test ! -e /var/run/docker.sock
test ! -e /run/aegisai-scan/containerd.sock
test ! -e /opt/aegisai/operator
if touch /write-must-fail 2>/dev/null; then exit 91; fi
if wget -qO- -T 2 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1; then exit 92; fi
if wget -qO- -T 2 http://172.31.55.151:8080/ >/dev/null 2>&1; then exit 93; fi
echo isolation-fixture-passed
uname -r
'''
try:
    result = subprocess.run([
        CLI, '--cgroup-manager', 'cgroupfs', 'run', '--name', name, '--log-driver', 'none', '--runtime', 'io.containerd.runsc.v1',
        '--annotation', 'io.kubernetes.cri.container-type=sandbox',
        '--network', 'none', '--user', '65532:65532', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--pids-limit', '64', '--cpus', '0.5', '--memory', '256m', '--memory-swap', '256m',
        digest, '/bin/sh', '-c', checks
    ], text=True, capture_output=True, timeout=45)
    if result.returncode:
        raise RuntimeError('Fixture failed: ' + result.stderr[-3000:])
    assert 'isolation-fixture-passed' in result.stdout
    compatible = json.loads(subprocess.check_output([CLI, 'inspect', name], text=True))[0]
    # nerdctl 2.4's Docker-compatible view represents disabled logging as empty
    # driver/address fields; the explicit run flag and absent LogPath prove no
    # json-file or remote log sink is configured.
    log_config = compatible['HostConfig']['LogConfig']
    assert log_config.get('driver',log_config.get('Type')) in ('','none')
    assert not log_config.get('address')
    assert not compatible.get('LogPath')
    native = json.loads(subprocess.check_output([CLI, 'inspect', '--mode=native', name], text=True))[0]
    assert native['Runtime']['Name'] == 'io.containerd.runsc.v1'
    spec = native['Spec']
    assert spec['root']['readonly'] is True
    assert spec['process']['noNewPrivileges'] is True
    assert spec['process']['user']['uid'] == 65532
    assert not spec['process']['capabilities'].get('bounding')
    resources = spec['linux']['resources']
    assert resources['memory']['limit'] == 256 * 1024 * 1024
    assert resources['pids']['limit'] == 64
    assert resources['cpu']['quota'] == 50000
    report = {'runtime': native['Runtime']['Name'], 'image': digest,
              'fixture': 'passed', 'network': 'none', 'rootfs': 'read-only',
              'uid': 65532, 'memoryMiB': 256, 'pids': 64, 'cpu': 0.5,
              'hostMetadataReachable': False, 'hostControlReachable': False,
              'customerRepositoryProcessed': False, 'kernel': result.stdout.strip().splitlines()[-1]}
    report['rawOutputLogDriver'] = 'none'
    pathlib.Path('/opt/aegisai/scanner/isolation-verification.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
finally:
    subprocess.run([CLI, 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
