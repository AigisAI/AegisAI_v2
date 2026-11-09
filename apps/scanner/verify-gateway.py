"""Synthetic provider plus actual private Unix HTTP stream and bounded tmpfs.
No production broker, SCM credential or repository is used.
"""
import base64
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import socketserver
import tempfile
import threading
import uuid

from broker_client import BrokerClient
from github_fetch import FetchFailure
from runtime import JobStorage, RuntimeFailure, job_key
from source_gateway import fetch_assignment

TOKEN = 'synthetic-upstream-only-never-in-receipt'
DATA = b'class Fixture {}\n'
BLOB = hashlib.sha1(b'blob '+str(len(DATA)).encode()+b'\0'+DATA,usedforsecurity=False).hexdigest()
COMMIT, TREE = 'a'*40, 'b'*40


class Provider:
    def __init__(self): self.calls = 0; self.revocations = 0
    def request(self,path,token,deadline,*,method='GET',limit=None):
        assert token == TOKEN
        if method == 'DELETE': self.revocations += 1; return None
        self.calls += 1
        prefix = '/repos/AigisAI/fixture'
        if path == prefix: return {'id':123,'full_name':'AigisAI/fixture','owner':{'id':241095585}}
        if path == prefix+'/git/commits/'+COMMIT: return {'sha':COMMIT,'tree':{'sha':TREE}}
        if path == prefix+'/git/trees/'+TREE+'?recursive=1':
            return {'sha':TREE,'truncated':False,'tree':[{'path':'Fixture.java','type':'blob','mode':'100644','size':len(DATA),'sha':BLOB}]}
        assert path == prefix+'/git/blobs/'+BLOB
        return {'sha':BLOB,'size':len(DATA),'encoding':'base64','content':base64.b64encode(DATA).decode()}


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


results = {}
for scenario in ('success','revoked-before-blob','denied-handoff'):
    provider = Provider()
    done = threading.Event()
    scan_id = uuid.uuid4().hex
    lease = {'tenantId':'synthetic-gateway','scanRequestId':scan_id,'jobId':'synthetic-job'}
    expires = (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=2)).isoformat().replace('+00:00','Z')
    scope = {'tenantId':lease['tenantId'],'scanRequestId':scan_id,'dispatchJobId':lease['jobId'],
        'credentialId':'synthetic-capability','claimToken':'synthetic-claim','expiresAt':expires,
        'repositoryBindingId':'synthetic-binding','providerRepoId':'123','providerUserId':'1',
        'fullName':'AigisAI/fixture','installationId':'99','commitSha':COMMIT}
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*args): pass
        def do_POST(self):
            value = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if self.path == '/gateway/open':
                assert value == {'lease':lease,'capability':'synthetic-one-use'}
                self.send_response(200); self.send_header('Content-Type','application/x-ndjson'); self.end_headers()
                self.wfile.write((json.dumps({'kind':'fetch-scope','claim':scope})+'\n').encode())
                self.wfile.write((json.dumps({'upstreamToken':TOKEN,'expiresAt':expires})+'\n').encode()); self.wfile.flush()
                done.wait(10)
                self.close_connection = True
                return
            assert all(value[name]==scope[name] for name in ('tenantId','credentialId','claimToken'))
            if self.path == '/gateway/check':
                data = {'authorized':not(scenario=='revoked-before-blob' and provider.calls>=3)}
            else:
                assert self.path == '/gateway/finish' and type(value['success']) is bool
                assert provider.revocations == 1, 'Finish cannot precede provider revocation'
                data = {'handoffAllowed':value['success'] and scenario=='success','integrationSuspended':False}
                done.set()
            encoded = json.dumps({'ok':True,'data':data}).encode()
            self.send_response(200); self.send_header('Content-Length',str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
    with tempfile.TemporaryDirectory(prefix='aegisai-gateway-fixture-') as directory:
        path = pathlib.Path(directory)
        os.chown(path,0,50001); path.chmod(0o2750)
        server = Server(str(path/'gateway.sock'),Handler)
        os.chown(path/'gateway.sock',0,50001); (path/'gateway.sock').chmod(0o660)
        thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.05},daemon=True); thread.start()
        storage = JobStorage(job_key(lease['tenantId'],scan_id))
        root = storage.prepare()
        try:
            try:
                receipt = fetch_assignment({'lease':lease,'capability':'synthetic-one-use'},
                    broker=BrokerClient('gateway',directory=directory),transport=provider)
                assert scenario == 'success'
                assert receipt['commitSha'] == COMMIT and receipt['sourceBytes'] == len(DATA)
                assert TOKEN not in json.dumps(receipt) and 'claimToken' not in receipt
            except (RuntimeFailure,FetchFailure) as error:
                assert scenario != 'success'
                assert str(error) == ('FETCH_AUTHORITY_LOST' if scenario=='revoked-before-blob' else 'GATEWAY_HANDOFF_DENIED')
            assert provider.revocations == 1
            assert provider.calls == (3 if scenario=='revoked-before-blob' else 4)
            results[scenario] = 'passed'
        finally:
            done.set(); server.shutdown(); server.server_close(); thread.join(timeout=2)
            storage.cleanup()
report = {'nativeGatewayTransport':results,'transport':'actual-private-Unix-HTTP','provider':'synthetic',
    'liveRepositoryFetched':False,'tmpfsCleanupVerified':True}
pathlib.Path('/opt/aegisai/scanner/gateway-verification.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
