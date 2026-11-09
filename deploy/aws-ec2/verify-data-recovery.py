"""Restore a fresh live DB backup into a unique disposable verification database.
Never restores into or modifies the application database; never prints row contents.
"""
import gzip
import json
import os
import pathlib
import subprocess
import time
import uuid

os.umask(0o077)
verify = 'aegisai-persistence-verify'
db = 'restore_verify_' + uuid.uuid4().hex
root = pathlib.Path('/opt/aegisai/backups')
root.mkdir(exist_ok=True, mode=0o700)
backup = root / ('pending-live-' + time.strftime('%Y%m%d-%H%M%S', time.gmtime()) + '.sql.gz')
prod = ['docker', 'exec', 'aegisai-ec2-demo-postgres-1']
test = ['docker', 'exec', '-i', verify]
query = '''SELECT json_build_object(
 'migrations',(SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NOT NULL),
 'users',(SELECT count(*) FROM "UserOAuthIdentity"),
 'integrations',(SELECT count(*) FROM "ScmIntegration"),
 'repositories',(SELECT count(*) FROM "RepositoryBinding"),
 'scans',(SELECT count(*) FROM "ScanRequest")
);'''
expected = json.loads(subprocess.check_output(prod + ['psql','-U','aegisai','-d','aegisai','-Atc',query],text=True))
release = pathlib.Path('/opt/aegisai/shared/candidate-release').read_text().strip()
assert release.startswith('ec2-runtime-') and '/' not in release and '..' not in release
migration_root = pathlib.Path('/opt/aegisai/releases') / release / 'apps/api/prisma/migrations'
assert expected['migrations'] == len(list(migration_root.glob('*/migration.sql'))) and expected['users'] >= 1
process = subprocess.Popen(prod + ['pg_dump','-U','aegisai','--no-owner','--no-privileges','aegisai'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
size = 0
with gzip.open(backup, 'wb') as output:
    while chunk := process.stdout.read(65536):
        size += len(chunk)
        if size > 512 * 1024 * 1024:
            process.kill()
            raise RuntimeError('Backup exceeds bounded verification size')
        output.write(chunk)
assert process.wait(timeout=30) == 0, 'Live backup failed'
subprocess.run(['docker','start',verify],check=True,stdout=subprocess.DEVNULL)
for _ in range(30):
    ready = subprocess.run(test+['pg_isready','-U','verify'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if ready.returncode == 0: break
    time.sleep(1)
else: raise RuntimeError('Verification PostgreSQL not ready')
started = time.monotonic()
created = False
try:
    subprocess.run(test + ['createdb','-U','verify',db],check=True)
    created = True
    with gzip.open(backup, 'rb') as stream:
        restore = subprocess.Popen(test+['psql','-U','verify','-d',db,'-v','ON_ERROR_STOP=1'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        while chunk := stream.read(65536):
            restore.stdin.write(chunk)
        restore.stdin.close()
        assert restore.wait(timeout=60) == 0, 'Disposable backup restore failed'
    actual = json.loads(subprocess.check_output(test+['psql','-U','verify','-d',db,'-Atc',query],text=True))
    assert actual == expected, 'Restored migration and durable entity counts differ'
    verified_backup = backup.with_name(backup.name.replace('pending-live-','verified-live-',1))
    backup.rename(verified_backup)
    report = {'backupRestore':'passed','rowsMatched':actual,'backupBytesUncompressed':size,
        'restoreSeconds':round(time.monotonic()-started,3),'productionDatabaseModified':False,
        'verifiedBackup':verified_backup.name,
        'scope':'current small private deployment; not an RTO or scale claim'}
    pathlib.Path('/opt/aegisai/operator/data-recovery-verification.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
finally:
    if created:
        subprocess.run(test+['dropdb','-U','verify',db],check=True)
    subprocess.run(['docker','stop',verify],check=True,stdout=subprocess.DEVNULL)
