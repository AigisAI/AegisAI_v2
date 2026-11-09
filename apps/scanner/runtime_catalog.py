"""Root-authored non-secret status; the API may mount only this directory read-only."""
import datetime
import json
import os
import pathlib
import subprocess
import tempfile

from runtime import IMAGE, RuntimeFailure, current_database

CATALOG = pathlib.Path('/opt/aegisai/scanner/catalog')
POLICY_VERSION = 'private-java-v1'


def local_runtime():
    _, digest = current_database()
    image = IMAGE.split('@sha256:')[1]
    return {'scannerSetVersion':'java-v1:'+image[:16]+':'+digest.split(':')[1],
            'policyVersion':POLICY_VERSION,'vulnerabilityDatabaseDigest':digest,
            'imageDigest':'sha256:'+image,'ai':'DISABLED'}


def check_fetch_egress():
    info = json.loads(pathlib.Path('/opt/aegisai/operator/fetch-egress/current.json').read_text())
    age = datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(info['updatedAt'])
    if info.get('uid')!=50001 or not datetime.timedelta(minutes=-5)<=age<=datetime.timedelta(hours=24):
        raise RuntimeFailure('FETCH_EGRESS_NOT_READY')
    subprocess.run(['nft','list','table','inet','aegisai_fetch'],capture_output=True,check=True,timeout=5)


def write_catalog(ready, *, busy=False):
    if os.geteuid()!=0: raise RuntimeFailure('PRIVILEGED_SUPERVISOR_REQUIRED')
    CATALOG.mkdir(mode=0o755,parents=True,exist_ok=True)
    info = CATALOG.lstat()
    if info.st_uid!=0 or info.st_mode & 0o022 or CATALOG.resolve()!=CATALOG:
        raise RuntimeFailure('INVALID_RUNTIME_CATALOG')
    status = {'ready':False,'busy':busy,'ai':'DISABLED','updatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if ready:
        check_fetch_egress()
        retention=json.loads(pathlib.Path('/run/aegisai-retention/status.json').read_text())
        age=datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(retention['checkedAt'].replace('Z','+00:00'))
        if retention.get('healthy') is not True or not datetime.timedelta(minutes=-5)<=age<=datetime.timedelta(minutes=30) or retention.get('oldestExpiredSeconds',86401)>86400:
            raise RuntimeFailure('EVIDENCE_RETENTION_NOT_READY')
        status.update(local_runtime(),ready=True)
    handle,name = tempfile.mkstemp(prefix='current-',suffix='.json',dir=CATALOG)
    temporary = pathlib.Path(name)
    try:
        with os.fdopen(handle,'w') as output: json.dump(status,output)
        temporary.chmod(0o644)
        temporary.replace(CATALOG/'current.json')
    finally:
        temporary.unlink(missing_ok=True)
    return status
