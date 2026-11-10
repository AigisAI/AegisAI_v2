"""Four real owner-session reads across two signed API replicas; no fake session."""
import base64
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import quote, unquote, urlparse

from bootstrap import BINARY, ROOT, now
from foundation import kube


def read_reply(stream):
    line=stream.readline(65537);assert len(line)<=65536 and line.endswith(b'\r\n')
    kind=line[:1];value=line[1:-2]
    if kind==b'+':return value
    if kind==b':':return int(value)
    if kind==b'$':
        size=int(value)
        if size==-1:return None
        assert 0<=size<=65536
        data=stream.read(size);assert len(data)==size and stream.read(2)==b'\r\n';return data
    if kind==b'*':
        count=int(value);assert 0<=count<=2048;return [read_reply(stream) for _ in range(count)]
    raise RuntimeError('PRIVATE_SESSION_STORE_UNAVAILABLE')


def owner_cookie():
    root=Path('/opt/aegisai/operator')
    trusted=root/'supply-chain/current/deploy/aws-ec2'
    assert trusted.resolve().is_relative_to(root/'supply-chain/releases')
    sys.path.insert(0,str(trusted));import managed_runtime
    public=json.loads(managed_runtime.read_protected(root/'data-plane-state.json')[0])
    auth=managed_runtime.read_secret(public['secretArns']['auth'])
    assert auth['ALLOWED_GITHUB_USER_IDS']=='161540124'
    url=urlparse(auth['REDIS_URL']);assert url.hostname=='redis' and (url.port or 6379)==6379
    redis=json.loads(subprocess.check_output(['docker','inspect','aegisai-ec2-demo-redis-1']))[0]
    address=redis['NetworkSettings']['Networks']['aegisai-ec2-demo_default']['IPAddress']
    assert ipaddress.ip_address(address) in ipaddress.ip_network('172.18.0.0/16')
    session_id=None
    with socket.create_connection((address,6379),timeout=5) as connection, connection.makefile('rb') as stream:
        def command(*args):
            values=[str(value).encode() for value in args]
            connection.sendall(b'*'+str(len(values)).encode()+b'\r\n'+b''.join(b'$'+str(len(v)).encode()+b'\r\n'+v+b'\r\n' for v in values))
            return read_reply(stream)
        if url.password:
            assert command('AUTH',*(([unquote(url.username)] if url.username else [])+[unquote(url.password)]))==b'OK'
        assert command('SELECT',int(url.path.strip('/') or '0'))==b'OK'
        cursor='0'
        for _ in range(30):
            raw_cursor,keys=command('SCAN',cursor,'MATCH','aegisai:session:*','COUNT',50);cursor=raw_cursor.decode()
            for key in keys:
                raw=command('GET',key.decode())
                if not raw:continue
                value=json.loads(raw)
                expiry=value.get('cookie',{}).get('expires')
                if (value.get('auth',{}).get('providerUserId')=='161540124' and expiry
                    and datetime.datetime.fromisoformat(expiry.replace('Z','+00:00'))>datetime.datetime.now(datetime.timezone.utc)):
                    session_id=key.decode()[len('aegisai:session:'):];break
            if session_id or cursor=='0':break
    assert session_id,'UNEXPIRED_OWNER_SESSION_NOT_AVAILABLE'
    signature=base64.b64encode(hmac.new(auth['SESSION_SECRET'].encode(),session_id.encode(),hashlib.sha256).digest()).decode().rstrip('=')
    cookie=auth.get('SESSION_COOKIE_NAME','connect.sid')+'='+quote('s:'+session_id+'.'+signature,safe='')
    return cookie


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    root=Path('/opt/aegisai/operator');lock=(root/'signed-deployment.lock').open('a')
    import fcntl
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    cookie=owner_cookie()
    original=json.loads(kube('get','hpa','api','-n','aegisai-private','-o','json'))['spec']['minReplicas'];assert original==1
    ledger=json.loads((ROOT/'approved-app-images.json').read_text());rows=[]
    restore='aegisai-hpa-min-restore-'+str(int(time.time()))
    subprocess.run(['systemd-run','--quiet','--unit='+restore,'--on-active=240s',str(BINARY),'kubectl',
        '--kubeconfig',str(ROOT/'kubeconfig.yaml'),'patch','hpa','api','-n','aegisai-private','--type=merge',
        '-p',json.dumps({'spec':{'minReplicas':original}})],check=True,capture_output=True,timeout=10)
    try:
        kube('patch','hpa','api','-n','aegisai-private','--type=merge','-p',json.dumps({'spec':{'minReplicas':2}}))
        for _ in range(60):
            pods=json.loads(kube('get','pods','-n','aegisai-private','-l','app.kubernetes.io/component=api','-o','json'))['items']
            ready=[p for p in pods if not p['metadata'].get('deletionTimestamp') and any(c['type']=='Ready' and c['status']=='True' for c in p['status'].get('conditions',[]))]
            if len(ready)==2:break
            time.sleep(3)
        else:raise RuntimeError('TWO_SIGNED_API_REPLICAS_NOT_READY')
        for pod in ready:assert pod['spec']['containers'][0]['image']==ledger['images']['api']['reference']
        for index in range(4):
            pod=ready[index%2];address=pod['status']['podIP']
            assert ipaddress.ip_address(address) in ipaddress.ip_network('10.44.0.0/16')
            connection=http.client.HTTPConnection(address,3000,timeout=5,source_address=('172.31.55.151',0))
            try:
                connection.request('GET','/api/auth/me',headers={'Cookie':cookie,'X-Forwarded-Proto':'https'})
                response=connection.getresponse();body=json.loads(response.read(65536))
                assert response.status==200 and body['authenticated'] is True
                rows.append({'pod':pod['metadata']['name'],'status':response.status,'remaining':int(response.getheader('X-RateLimit-Remaining'))})
            finally:connection.close()
        assert all(rows[index]['remaining']==rows[index-1]['remaining']-1 for index in range(1,4))
        report={'actualSharedReplicaThrottle':'passed','actualOwnerSessionOnBothReplicas':True,
            'noSyntheticSessionCreated':True,'readOnlyRequests':rows,'hpaTemporarilyMinimum2':'verification-only-not-cpu-scaling-proof',
            'newScanExecuted':False,'newMigrationsApplied':False,'verifiedAt':now()}
        (ROOT/'resource-metrics/shared-throttle-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
    finally:
        kube('patch','hpa','api','-n','aegisai-private','--type=merge','-p',json.dumps({'spec':{'minReplicas':original}}))
        subprocess.run(['systemctl','stop',restore+'.timer'],capture_output=True,timeout=10)


if __name__=='__main__':main()
