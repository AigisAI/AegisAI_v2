"""Reversible private ingress migration; preserves the original Docker release."""
import argparse
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time

from bootstrap import ROOT, now, snapshot
from foundation import kube

OPERATOR=Path('/opt/aegisai/operator')
STATE=OPERATOR/'application-traffic.json'
INGRESS=Path('/opt/aegisai/shared/ingress-pending.conf')
OLD='set $application http://aegisai-ec2-demo-web-1:80;'
NEW='set $application http://10.45.0.40:80;'
PINS={'deploy-candidate.sh':'0d78f4f19b1ccc0c9e52668ee909a4ad9647b7f70aa6b2444126fd18422bfd4b',
      'deploy-web.py':'13c8d4e6ba5d7df57a88f02f13cb7330b83ab76c2e101100907675bc1a915675',
      'activate-private-ingress.py':'81d2aeaebc1a56ba6f8c34ee543e4e18c1bc3a62537dd8c4cbdd4f1cb0038a70'}


def request(port,path='/'):
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=12)
    try:
        connection.request('GET',path,headers={'Host':'aegisai-aws.tailaca7d2.ts.net'})
        response=connection.getresponse();return response.status,response.read(2*1024**2)
    finally:connection.close()


def reload(content):
    INGRESS.write_text(content)  # preserve Docker bind-mounted inode
    subprocess.run(['docker','exec','aegisai-ingress','nginx','-t'],check=True,capture_output=True,timeout=10)
    subprocess.run(['docker','exec','aegisai-ingress','nginx','-s','reload'],check=True,capture_output=True,timeout=10)
    time.sleep(1)


def checks(expected_html):
    assert request(8081)[0]==200 and hashlib.sha256(request(8081)[1]).hexdigest()==expected_html
    assert request(8081,'/api/health')[0]==200
    assert request(8081,'/api/runtime/scans')[0]==401
    assert request(8081,'/api/scan-requests')[0]==404
    assert request(8081,'/api/runtime/observability-auth')[0]==404
    assert request(8081,'/ops/grafana/d/aegisai-private')[0]==302


def install_guards(directory):
    guard=OPERATOR/'ensure-compose-traffic.py'
    guard.write_text("import json,pathlib,sys\np=pathlib.Path('/opt/aegisai/operator/application-traffic.json')\nif p.exists() and json.loads(p.read_text())['backend']!='compose':\n print('COMPOSE_DEPLOYMENT_BLOCKED_WHILE_KUBERNETES_OWNS_TRAFFIC',file=sys.stderr);sys.exit(1)\n")
    guard.chmod(0o600)
    for name,pin in PINS.items():
        path=OPERATOR/name;text=path.read_text()
        if '/opt/aegisai/operator/ensure-compose-traffic.py' in text:continue
        assert hashlib.sha256(path.read_bytes()).hexdigest()==pin and path.stat().st_uid==0
        assert '__future__' not in text
        shutil.copyfile(path,directory/name)
        if name.endswith('.sh'):
            first,rest=text.split('\n',1)
            text=first+'\npython3 /opt/aegisai/operator/ensure-compose-traffic.py || exit 1\n'+rest
        else:
            text="import subprocess\nsubprocess.run(['python3','/opt/aegisai/operator/ensure-compose-traffic.py'],check=True)\n"+text
            compile(text,str(path),'exec')
        path.write_text(text)


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['activate','rollback']);parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    with (OPERATOR/'signed-deployment.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        before=snapshot();old=INGRESS.read_text()
        serve=json.loads(subprocess.check_output(['tailscale','serve','status','--json']))
        assert not any(serve.get('AllowFunnel',{}).values())
        if args.mode=='activate':
            assert OLD in old and NEW not in old
            ledger=json.loads((ROOT/'approved-app-images.json').read_text())
            assert ledger['verification']['signedCandidateVerification']=='passed'
            verified=datetime.datetime.fromisoformat(ledger['verification']['verifiedAt'])
            assert datetime.datetime.now(datetime.timezone.utc)-verified<datetime.timedelta(hours=24)
            assert json.loads((ROOT/'standby-result.json').read_text())['revision']==ledger['approvedSource']
            assert json.loads((ROOT/'catalog-projection-result.json').read_text())['nativeProjectedCatalog']=='passed'
            assert json.loads(Path('/opt/aegisai/observability/standby-metrics-result.json').read_text())['actualScrapeVerified']
            pods=json.loads(kube('get','pods','-n','aegisai-private','-o','json'))['items']
            assert len(pods)==2
            for pod in pods:
                kind=pod['metadata']['labels']['app.kubernetes.io/component']
                assert pod['spec']['containers'][0]['image']==ledger['images'][kind]['reference']
                assert any(c['type']=='Ready' and c['status']=='True' for c in pod['status']['conditions'])
            html=hashlib.sha256(request(8081)[1]).hexdigest()
            proposed=old.replace(OLD,NEW)
            state={'backend':'kubernetes','approvedSource':ledger['approvedSource'],'images':ledger['images'],
                   'dockerFallbackRelease':before['release'],'originalHtmlSha256':html,'changedAt':now()}
        else:
            state=json.loads(STATE.read_text());assert state['backend']=='kubernetes'
            assert NEW in old and OLD not in old
            proposed=(Path(state['backup'])/'ingress.conf').read_text()
            html=state['originalHtmlSha256'];state={**state,'backend':'compose','changedAt':now()}
        if not args.apply:
            print(json.dumps({'trafficPlan':'ready','mode':args.mode,'currentApplicationUnchanged':True}));return
        previous=STATE.read_bytes() if STATE.exists() else None
        if args.mode=='activate':
            directory=ROOT/'control-backups'/str(int(time.time()));directory.mkdir(mode=0o700,parents=True)
            (directory/'ingress.conf').write_text(old)
            source=sqlite3.connect('file:'+str(ROOT/'data/server/db/state.db')+'?mode=ro',uri=True)
            target=sqlite3.connect(directory/'state.db')
            try:
                source.backup(target);assert target.execute('PRAGMA quick_check').fetchone()[0]=='ok'
            finally:source.close();target.close()
            shutil.copyfile(ROOT/'data/server/token',directory/'token')
            shutil.copyfile(ROOT/'config.yaml',directory/'config.yaml')
            shutil.copyfile(ROOT/'data/server/cred/encryption-config.json',directory/'encryption-config.json')
            state['backup']=str(directory);install_guards(directory)
        try:
            STATE.write_text(json.dumps(state,indent=2));reload(proposed);checks(html)
            assert snapshot()==before
            if args.mode=='activate':
                rejected=subprocess.run(['python3',str(OPERATOR/'ensure-compose-traffic.py')],capture_output=True)
                assert rejected.returncode==1
        except Exception:
            reload(old)
            if previous is None:STATE.unlink(missing_ok=True)
            else:STATE.write_bytes(previous)
            raise
        report={'privateTrafficMigration':args.mode,'backend':state['backend'],'originalHtmlUnchanged':True,
                'authAndRouteGuardsPassed':True,'dockerFallbackUnchanged':True,'newScanExecuted':False,
                'newMigrationsApplied':False,'publicExposureChanged':False,'verifiedAt':now()}
        (ROOT/('traffic-'+args.mode+'-result.json')).write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
