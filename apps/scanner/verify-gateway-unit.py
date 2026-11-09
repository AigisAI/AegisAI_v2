"""One native sandboxed gateway process smoke, with trusted RAM fixture only."""
import json
import subprocess
import sys
import uuid

from runtime import JobStorage, job_key, mounts
from supervisor import gateway_command, stop_gateway

probe=r'''import os,pathlib,resource,socket,sys,urllib.request
sys.path.insert(0,'/usr/local/lib/aegisai-source-gateway')
import source_gateway
from broker_client import BrokerClient
from runtime import RuntimeFailure,require_tmpfs
assert os.geteuid()==50001 and os.getegid()==50001 and set(os.getgroups())<={50001}
assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)
status=pathlib.Path('/proc/self/status').read_text()
assert 'NoNewPrivs:\t1' in status.replace('\\t','\t')
caps=[line.split(':',1)[1].strip() for line in status.splitlines() if line.startswith('CapEff:')][0]
assert int(caps,16)==0
root=pathlib.Path(sys.argv[1]);require_tmpfs(root)
(root/'source/Fixture.java').write_text('class Fixture {}')
for path in ['/opt/aegisai/shared/scm-keys/github-app-org.pem','/run/aegisai-scan/containerd.sock','/run/docker.sock']:
 try:
  pathlib.Path(path).open('rb')
 except (PermissionError,FileNotFoundError): pass
 else: raise AssertionError('Privileged host resource accessible')
try:
 BrokerClient('gateway').request('/worker/claim',{'workerId':'unit-permission-probe'})
except RuntimeFailure: pass
else: raise AssertionError('Gateway could claim work')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(urllib.request.Request('https://api.github.com/rate_limit',headers={'User-Agent':'AegisAI-Unit-Smoke'}),timeout=10) as response:
 assert response.status==200;response.read(4096)
for host,port in [('169.254.169.254',80),('127.0.0.1',8081)]:
 try: connection=socket.create_connection((host,port),timeout=3)
 except OSError: pass
 else: connection.close();raise AssertionError('Forbidden host endpoint reachable')
print('GATEWAY_UNIT_PERMISSIONS_PASSED')
'''
storage=JobStorage(job_key('synthetic-gateway-unit',uuid.uuid4().hex))
root=storage.prepare()
try:
    storage.grant_gateway_writer()
    command=gateway_command(storage.key)
    command[-1:]=['-c',probe,str(root)]
    result=subprocess.run(command,capture_output=True,text=True,timeout=40)
    assert result.returncode==0 and result.stdout.strip()=='GATEWAY_UNIT_PERMISSIONS_PASSED','Gateway native unit smoke failed: '+result.stderr[-2000:]
    stop_gateway(storage.key)
    storage.seal()
    assert (root/'source/Fixture.java').stat().st_uid==0
finally:
    stop_gateway(storage.key)
    storage.cleanup()
assert not root.exists() and str(root) not in mounts()
print(json.dumps({'nativeGatewayUnit':'passed','dedicatedUid':50001,'capabilities':'none','hostSecrets':'inaccessible',
    'network':'GitHub-API-only','sourceTmpfsSealedAndRemoved':True,'scmCredentialUsed':False}))
