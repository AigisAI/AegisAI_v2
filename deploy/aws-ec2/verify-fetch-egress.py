"""One deployed public-API/blocked-destination smoke check; no SCM credential."""
import json
import subprocess

probe='''import json,socket,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(urllib.request.Request('https://api.github.com/rate_limit',headers={'User-Agent':'AegisAI-Egress-Smoke'}),timeout=10) as response:
 assert response.status==200
 response.read(4096)
blocked=[]
for host,port in [('169.254.169.254',80),('127.0.0.1',8081),('8.8.8.8',443)]:
 try:
  connection=socket.create_connection((host,port),timeout=3)
 except OSError:
  blocked.append(host)
 else:
  connection.close();raise AssertionError('Forbidden destination reachable')
assert len(blocked)==3
print(json.dumps({'githubApiReachable':True,'awsMetadataBlocked':True,'hostIngressBlocked':True,'unapprovedInternetBlocked':True,'scmCredentialUsed':False}))
'''
result=subprocess.run(['setpriv','--reuid=50001','--regid=50001','--clear-groups','python3','-c',probe],
    check=True,capture_output=True,text=True,timeout=25)
report=json.loads(result.stdout)
print(json.dumps(report))
