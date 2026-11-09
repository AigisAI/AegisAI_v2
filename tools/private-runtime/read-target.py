"""Read-only existing-host snapshot; key contents and application data never returned."""
import argparse
import json
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--identity-file', required=True, type=pathlib.Path)
parser.add_argument('--output', required=True, type=pathlib.Path)
options = parser.parse_args()
script = r'''
import datetime,hashlib,json,pathlib,shutil,subprocess
root=pathlib.Path('/opt/aegisai')
sql='SELECT coalesce(json_agg(t),\'[]\'::json) FROM (SELECT migration_name,checksum,finished_at,rolled_back_at FROM "_prisma_migrations") t;'
rows=json.loads(subprocess.check_output(['docker','exec','aegisai-ec2-demo-postgres-1','psql','-U','aegisai','-d','aegisai','-Atc',sql],text=True))
state=json.loads((root/'operator/data-plane-state.json').read_text())
names=('runtime.py','supervisor.py','broker_client.py','github_fetch.py','source_gateway.py','normalize.py','runtime_catalog.py')
workers={name:hashlib.sha256((root/'scanner'/name).read_bytes()).hexdigest() for name in names}
catalog=json.loads((root/'scanner/catalog/current.json').read_text())
print(json.dumps({'readOnly':True,'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'instanceId':state['existingInstanceId'],'migrations':rows,'workerSourceHashes':workers,
 'diskFreeBytes':shutil.disk_usage(root).free,'scannerReady':catalog['ready'],'scannerBusy':catalog['busy']}))
'''
reply = subprocess.run(['ssh', '-i', str(options.identity_file), '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=8', 'ubuntu@100.64.144.15',
    'sudo python3 -'], input=script, capture_output=True, text=True, timeout=30)
assert reply.returncode == 0, 'TARGET_READ_FAILED'
snapshot = json.loads(reply.stdout)
assert snapshot['readOnly'] and snapshot['instanceId'] == 'i-0d24d0502cfc5a9c5'
options.output.write_text(json.dumps(snapshot, indent=2) + '\n')
print(json.dumps({'targetReadOnlySnapshot': 'saved', 'migrations': len(snapshot['migrations']), 'productionChanged': False}))
