"""Encrypted off-host DB backup, using only the existing instance role.
No raw source is in the application DB. No operator credentials are used.
"""
import base64
import gzip
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import uuid

assert os.geteuid()==0
os.umask(0o077)
root=pathlib.Path('/opt/aegisai')
state=json.loads((root/'operator/data-plane-state.json').read_text())
environment={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root',
    'AWS_CONFIG_FILE':'/dev/null','AWS_SHARED_CREDENTIALS_FILE':'/dev/null','AWS_EC2_METADATA_V1_DISABLED':'true',
    'AWS_PAGER':'','AWS_CLI_AUTO_PROMPT':'off'}
def aws(arguments):
    result=subprocess.run(['/usr/local/lib/aegisai-aws-cli/aws','--region','ap-northeast-2',*arguments],
        env=environment,capture_output=True,timeout=120)
    if result.returncode: raise RuntimeError('ENCRYPTED_BACKUP_AWS_OPERATION_FAILED')
    return json.loads(result.stdout) if result.stdout.strip() else {}

directory=root/'backups';directory.mkdir(mode=0o700,exist_ok=True)
suffix=time.strftime('%Y%m%d-%H%M%S',time.gmtime())+'-'+uuid.uuid4().hex[:8]
backup=directory/('offsite-'+suffix+'.sql.gz')
download=directory/('offsite-restore-'+suffix+'.sql.gz')
key='backups/'+suffix+'.sql.gz'
dump=subprocess.Popen(['docker','exec','aegisai-ec2-demo-postgres-1','pg_dump','-U','aegisai','--no-owner','--no-privileges','aegisai'],
    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
size=0
with gzip.open(backup,'wb') as output:
    while chunk:=dump.stdout.read(65536):
        size+=len(chunk)
        if size>512*1024*1024: dump.kill();raise RuntimeError('BACKUP_CAPACITY_EXCEEDED')
        output.write(chunk)
assert dump.wait(timeout=30)==0 and size>0,'Database backup failed'
digest=hashlib.sha256(backup.read_bytes()).hexdigest()
context=base64.b64encode(json.dumps({'purpose':'database-backup','instanceId':state['existingInstanceId']}).encode()).decode()
uploaded=aws(['s3api','put-object','--bucket',state['bucket'],'--key',key,'--body',str(backup),'--server-side-encryption','aws:kms',
    '--ssekms-key-id',state['kmsKeyArn'],'--ssekms-encryption-context',context,'--if-none-match','*','--checksum-algorithm','SHA256'])
assert uploaded['ServerSideEncryption']=='aws:kms' and uploaded['SSEKMSKeyId']==state['kmsKeyArn']
received=aws(['s3api','get-object','--bucket',state['bucket'],'--key',key,str(download)])
assert received['ServerSideEncryption']=='aws:kms' and hashlib.sha256(download.read_bytes()).hexdigest()==digest
report={'offsiteEncryptedBackup':'passed','transferHashMatched':True,'kmsKeyManager':'AWS','uncompressedBytes':size,
    'backupObjectKey':key,'createdAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'restoreVerified':False}
if '--verify-restore' in sys.argv:
    database='restore_offsite_'+uuid.uuid4().hex
    test=['docker','exec','-i','aegisai-persistence-verify']
    subprocess.run(['docker','start','aegisai-persistence-verify'],check=True,stdout=subprocess.DEVNULL)
    for _ in range(30):
        if subprocess.run(test+['pg_isready','-U','verify'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
        time.sleep(1)
    else:raise RuntimeError('Verification database unavailable')
    query='''SELECT json_build_object('migrations',(SELECT count(*) FROM "_prisma_migrations" WHERE finished_at IS NOT NULL),
    'identities',(SELECT count(*) FROM "UserOAuthIdentity"),'integrations',(SELECT count(*) FROM "ScmIntegration"),
    'repositories',(SELECT count(*) FROM "RepositoryBinding"),'scans',(SELECT count(*) FROM "ScanRequest"),
    'findings',(SELECT count(*) FROM "NormalizedFinding"),'scannerRuns',(SELECT count(*) FROM "ScannerRun"),
    'evidencePacks',(SELECT count(*) FROM "EvidencePack"));'''
    try:
        subprocess.run(test+['createdb','-U','verify',database],check=True)
        with gzip.open(download,'rb') as stream:
            subprocess.run(test+['psql','-U','verify','-d',database,'-v','ON_ERROR_STOP=1'],input=stream.read(),check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        counts=json.loads(subprocess.check_output(test+['psql','-U','verify','-d',database,'-Atc',query],text=True))
        current=json.loads(subprocess.check_output(['docker','exec','aegisai-ec2-demo-postgres-1','psql','-U','aegisai','-d','aegisai','-Atc',query],text=True))
        assert counts==current,'Run acceptance restore while scans are idle'
        report.update(restoreVerified=True,restoredCounts=counts)
    finally:
        subprocess.run(test+['dropdb','-U','verify','--if-exists',database],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','stop','aegisai-persistence-verify'],check=True,stdout=subprocess.DEVNULL)
download.unlink()
destination=root/'operator/offsite-backup-status.json'
pending=destination.with_suffix('.pending.json');pending.write_text(json.dumps(report));pending.replace(destination)
print(json.dumps(report))
