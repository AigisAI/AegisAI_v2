"""Read-only deployed process and native role smoke check; no SCM token issued."""
import json
import os
import pathlib
import stat
import subprocess
import http.client
import socket

assert os.geteuid()==0
info=json.loads(subprocess.check_output(['docker','inspect','aegisai-private-broker'],text=True))[0]
assert info['State']['Running']
host=info['HostConfig']
assert host['ReadonlyRootfs'] and host['CapDrop']==['ALL'] and 'no-new-privileges' in host['SecurityOpt']
assert host['Memory']==512*1024*1024 and host['PidsLimit']==128 and host['NanoCpus']==500000000
assert host['NetworkMode']=='aegisai-ec2-demo_default' and not host['PortBindings']
names={value.split('=',1)[0] for value in info['Config']['Env']}
assert names <= {'PATH','NODE_VERSION','YARN_VERSION','NODE_ENV','PORT','AWS_REGION','AWS_EC2_METADATA_V1_DISABLED',
    'AWS_SCM_SECRET_ARN','EVIDENCE_BUCKET','EVIDENCE_KMS_KEY_ARN'}
mounts={item['Destination']:item for item in info['Mounts']}
assert set(mounts)=={'/run/broker'}
assert set(host['Tmpfs'])=={'/tmp'} and 'noexec' in host['Tmpfs']['/tmp']
assert mounts['/run/broker']['Source']=='/run/aegisai-source-broker' and mounts['/run/broker']['RW']
directory=pathlib.Path('/run/aegisai-source-broker')
assert directory.stat().st_uid==0 and directory.stat().st_gid==50001 and stat.S_IMODE(directory.stat().st_mode)==0o2750
for name,mode in [('control.sock',0o600),('gateway.sock',0o660)]:
    entry=(directory/name).lstat()
    assert stat.S_ISSOCK(entry.st_mode) and stat.S_IMODE(entry.st_mode)==mode and entry.st_uid==0 and entry.st_gid==50001

class Unix(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect('/run/aegisai-source-broker/control.sock')
connection=Unix('localhost',timeout=5)
connection.request('GET','/health')
response=connection.getresponse()
assert response.status==200 and json.loads(response.read())=={'ok':True}
connection.close()
probe='''import socket,http.client,json
denied=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
 denied.connect('/run/aegisai-source-broker/control.sock')
 raise AssertionError('Control socket accessible')
except PermissionError: pass
finally: denied.close()
class Unix(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5)
  self.sock.connect('/run/aegisai-source-broker/gateway.sock')
c=Unix('localhost',timeout=5)
c.request('POST','/worker/claim',body=json.dumps({'workerId':'permission-probe'}),headers={'Content-Type':'application/json'})
r=c.getresponse();assert r.status==403;r.read();c.close()
'''
subprocess.run(['setpriv','--reuid=50001','--regid=50001','--clear-groups','python3','-c',probe],check=True,capture_output=True,timeout=10)
print(json.dumps({'privateBrokerHealth':'passed','gatewayUidControlAccess':'denied','gatewayWorkerOperation':'denied',
    'minimalCredentialsOnly':True,'readOnlyContainer':True,'runtimeImage':info['Config']['Image'],
    'publicListener':False,'upstreamTokenIssued':False,'consumerActivated':False}))
