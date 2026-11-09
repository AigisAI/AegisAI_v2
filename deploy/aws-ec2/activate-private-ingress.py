"""Promote or pause the reviewed one-owner runtime; preserve mounted config inode.
Run after managed boot, real scan, encrypted offsite restore and validation pass.
"""
import datetime
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

assert os.geteuid()==0
os.umask(0o077)
root=pathlib.Path('/opt/aegisai')
mode=sys.argv[1] if len(sys.argv)==2 else ''
assert mode in ('promote','pause')
source=pathlib.Path(__file__).resolve().parent/'ingress-production.conf'
destination=root/'shared/ingress-pending.conf'
paused=root/'shared/ingress.private-paused.conf'

def request(path):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8081'+path,timeout=10) as response:
            return response.status,response.read(1024*1024)
    except urllib.error.HTTPError as error:return error.code,error.read(4096)

def reload(content):
    destination.write_text(content)
    subprocess.run(['docker','exec','aegisai-ingress','nginx','-t'],check=True)
    subprocess.run(['docker','exec','aegisai-ingress','nginx','-s','reload'],check=True)
    time.sleep(1)

old=destination.read_text()
if mode=='promote':
    accepted=json.loads((root/'operator/acceptance/live-scan-result.json').read_text())
    restart=json.loads((root/'operator/acceptance/restart-result.json').read_text())
    backup=json.loads((root/'operator/offsite-backup-status.json').read_text())
    validation=json.loads((root/'operator/acceptance/workspace-validation.json').read_text())
    assert accepted['operatorLiveScanAcceptance']=='passed' and accepted['ai']=='DISABLED'
    assert restart['managedBootRecovery']=='passed' and restart['completedJobNotReplayed']
    assert backup['restoreVerified'] and backup['offsiteEncryptedBackup']=='passed'
    assert validation['requiredSixChecks']=='passed'
    catalog=json.loads((root/'scanner/catalog/current.json').read_text())
    age=datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(catalog['updatedAt'])
    assert catalog['ready'] and not catalog['busy'] and age.total_seconds()<60
    for service in ('aegisai-scan-supervisor','aegisai-private-broker','aegisai-runtime-secrets'):
        subprocess.run(['systemctl','is-active','--quiet',service],check=True)
    release=(root/'shared/candidate-release').read_text().strip()
    assert release==validation['candidateRelease']
    for component in ('api','web','postgres','redis'):
        container=json.loads(subprocess.check_output(['docker','inspect','aegisai-ec2-demo-'+component+'-1']))[0]
        assert container['State']['Health']['Status']=='healthy'
        if component in ('api','web'):
            component_release=release
            web_state=root/'operator/web-release.json'
            if component=='web' and web_state.is_file():
                frontend=json.loads(web_state.read_text())
                assert frontend['apiRelease']==release
                component_release=frontend['webRelease']
            assert container['Config']['Image']=='aegisai-'+component+':'+component_release
    # Serve only; public security-group and Funnel are never modified here.
    serve=json.loads(subprocess.check_output(['tailscale','serve','status','--json']))
    assert not any(serve.get('AllowFunnel',{}).values()),'Public Funnel must remain disabled'
    if not paused.exists():
        assert request('/')[0]==503,'Capture only a known closed ingress configuration'
        paused.write_text(old)
    content=source.read_text()
else:
    assert paused.is_file()
    content=paused.read_text()

try:
    reload(content)
    if mode=='promote':
        assert request('/')[0]==200
        assert request('/api/runtime/scans')[0]==401
        assert request('/api/scan-requests')[0]==404
        assert request('/ops/aws-login/expired')[0]==404
        status,body=request('/api/auth/me')
        assert status==200 and json.loads(body)['authenticated'] is False
    else:assert request('/')[0]==503
except Exception:
    reload(old)
    raise
report={'privateIngress':mode,'scope':'single-owner-java','ai':'DISABLED','publicExposureChanged':False,
    'changedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}
(root/'operator/private-ingress-status.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
