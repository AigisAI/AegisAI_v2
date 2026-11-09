#!/usr/bin/env python3
"""Prepare pinned vendor images and validate config; no application replacement."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path('/opt/aegisai/observability')
SOURCE = Path(__file__).resolve().parent


def run(*args):
    subprocess.run(args, check=True, timeout=600)


def capacity():
    if shutil.disk_usage('/').free < 3584 * 1024 ** 2:
        raise SystemExit('Preserved disk reserve reached; no pruning or volume expansion authorized')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'start'])
    args = parser.parse_args()
    assert os.geteuid() == 0
    capacity()
    images = json.loads((SOURCE / 'vendor-images.json').read_text())
    if args.action == 'prepare':
        for name, value in images.items():
            capacity()
            print('Preparing pinned image:', name, flush=True)
            run('docker', 'pull', value['image'])
            capacity()
        common = ['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop=ALL',
                  '--security-opt=no-new-privileges', '--memory=384m', '--pids-limit=128',
                  '--tmpfs', '/tmp:rw,nosuid,size=32m', '-v', str(SOURCE) + ':/config:ro']
        run(*common, '--entrypoint', '/bin/promtool', images['prometheus']['image'], 'check', 'config', '/config/prometheus.yaml')
        run(*common, images['loki']['image'], '-config.file=/config/loki.yaml', '-verify-config=true')
        run(*common, images['alloy']['image'], 'validate', '/config/config.alloy')
        return
    # Network conflict checks cover existing Docker bridges and host routes before creation.
    import ipaddress
    wanted = ipaddress.ip_network('172.29.240.0/24')
    ids = subprocess.check_output(['docker', 'network', 'ls', '-q']).decode().split()
    existing = json.loads(subprocess.check_output(['docker', 'network', 'inspect', *ids]))
    match = next((n for n in existing if n['Name'] == 'aegisai-observability'), None)
    for network in existing:
        for config in network.get('IPAM', {}).get('Config') or []:
            subnet = config.get('Subnet')
            if subnet and ':' not in subnet and wanted.overlaps(ipaddress.ip_network(subnet)):
                assert network['Name'] == 'aegisai-observability' and network['Internal'], 'Conflicting bridge'
    for route in json.loads(subprocess.check_output(['ip', '-j', '-4', 'route'])):
        dest = route.get('dst', 'default')
        if dest != 'default' and wanted.overlaps(ipaddress.ip_network(dest, strict=False)):
            assert match and route.get('dev') == 'br-' + match['Id'][:12], 'Conflicting host route'
    if match is None:
        run('docker', 'network', 'create', '--internal', '--subnet=172.29.240.0/24',
            '--gateway=172.29.240.1', '--ip-range=172.29.240.128/25',
            '--label=aegisai.owner=342', 'aegisai-observability')
    else:
        assert match['Labels'].get('aegisai.owner') == '342'
        assert match['IPAM']['Config'][0]['Subnet'] == '172.29.240.0/24'
    ROOT.mkdir(mode=0o755, parents=True, exist_ok=True)
    config_dir = ROOT / 'config'
    config_dir.mkdir(mode=0o755, exist_ok=True)
    for source in SOURCE.iterdir():
        if source.is_file() and source.suffix in ('.yaml', '.ini', '.alloy', '.json'):
            shutil.copyfile(source, config_dir / source.name)
            (config_dir / source.name).chmod(0o644)
    for name, uid in {'grafana':472, 'loki':10001, 'prometheus':65534, 'alloy':473, 'tempo':10001}.items():
        path = ROOT / 'data' / name
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(path, uid, uid)
    secret = ROOT / 'grafana-secret'
    if not secret.exists():
        import secrets
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, 'w') as stream:
            stream.write(secrets.token_hex(64))
        os.chown(secret, 0, 472)
        secret.chmod(0o440)
    assert not secret.is_symlink()
    os.chown(secret, 0, 472)
    secret.chmod(0o440)
    logs = ROOT / 'logs'
    logs.mkdir(mode=0o755, exist_ok=True)
    (logs / 'status.jsonl').touch(mode=0o644, exist_ok=True)
    shutil.copyfile(SOURCE / 'host_exporter.py', ROOT / 'host_exporter.py')
    run('docker', 'compose', '-f', str(config_dir / 'compose.json'), 'config', '--quiet')
    run('docker', 'compose', '-f', str(config_dir / 'compose.json'), 'up', '-d')
    shutil.copyfile(SOURCE / 'aegisai-host-metrics.service', '/etc/systemd/system/aegisai-host-metrics.service')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'enable', 'aegisai-host-metrics.service')
    run('systemctl', 'restart', 'aegisai-host-metrics.service')
    print('Hidden backends started. Application and public ingress unchanged.')


if __name__ == '__main__':
    main()
