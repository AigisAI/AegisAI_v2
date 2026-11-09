"""Synthetic provider transport against actual bounded no-exec RAM storage.
No GitHub credentials, network requests or customer repository input are used.
"""
import base64
import copy
import hashlib
import json
import pathlib
import stat
import time
import uuid

from github_fetch import GitHubObjectsFetcher, FetchFailure, safe_path
from runtime import JobStorage, RuntimeFailure, job_key

COMMIT = 'a'*40
TREE = 'b'*40
DATA = b'class Fixture { void ok() {} }\n'
BLOB = hashlib.sha1(b'blob '+str(len(DATA)).encode()+b'\0'+DATA,usedforsecurity=False).hexdigest()


class ProviderFixture:
    def __init__(self, *, entry=None, entries=None, owner=241095585, repo_id=123, commit=COMMIT, tamper=False, truncated=False, revoke_fails=False):
        self.entry = entry or {'path':'src/Fixture.java','type':'blob','mode':'100755','size':len(DATA),'sha':BLOB}
        self.owner = owner
        self.repo_id = repo_id
        self.commit = commit
        self.entries = entries
        self.tamper = tamper
        self.truncated = truncated
        self.revoke_fails = revoke_fails
        self.revocations = 0
        self.calls = []

    def request(self, path, token, deadline, *, method='GET', limit=None):
        assert token == 'synthetic-upstream-only'
        self.calls.append((method,path))
        if method == 'DELETE':
            assert path == '/installation/token'
            self.revocations += 1
            if self.revoke_fails: raise FetchFailure('PROVIDER_UNAVAILABLE')
            return None
        assert time.monotonic() < deadline
        prefix = '/repos/AigisAI/fixture'
        if path == prefix:
            return {'id':self.repo_id,'full_name':'AigisAI/fixture','owner':{'id':self.owner}}
        if path == prefix+'/git/commits/'+COMMIT:
            return {'sha':self.commit,'tree':{'sha':TREE}}
        if path == prefix+'/git/trees/'+TREE+'?recursive=1':
            return {'sha':TREE,'truncated':self.truncated,'tree':copy.deepcopy(self.entries) if self.entries is not None else [copy.deepcopy(self.entry)]}
        if path == prefix+'/git/blobs/'+BLOB:
            return {'sha':BLOB,'size':len(DATA),'encoding':'base64',
                'content':base64.b64encode(DATA.replace(b'Fixture',b'Changed') if self.tamper else DATA).decode()}
        raise AssertionError('Unexpected provider route')


def fetcher(provider, scan_id):
    return GitHubObjectsFetcher(tenant_id='synthetic-fetch-acceptance',scan_id=scan_id,
        repository_id=123,full_name='AigisAI/fixture',commit_sha=COMMIT,
        token='synthetic-upstream-only',capability_expires_at=time.time()+120,check_authority=lambda:True,transport=provider)


cases = [
    ('success',{},None),
    ('path_traversal',{'entry':{'path':'../Fixture.java','type':'blob','mode':'100644','sha':BLOB,'size':len(DATA)}},'UNSAFE_REPOSITORY_PATH'),
    ('symlink',{'entry':{'path':'Fixture.java','type':'blob','mode':'120000','sha':BLOB,'size':len(DATA)}},'UNSUPPORTED_REPOSITORY_ENTRY'),
    ('submodule',{'entry':{'path':'Fixture.java','type':'commit','mode':'160000','sha':BLOB}},'UNSUPPORTED_REPOSITORY_ENTRY'),
    ('wrong_organization',{'owner':2},'ORGANIZATION_NOT_ADMITTED'),
    ('wrong_repository',{'repo_id':124},'REPOSITORY_SCOPE_MISMATCH'),
    ('wrong_commit',{'commit':'c'*40},'COMMIT_SCOPE_MISMATCH'),
    ('truncated_tree',{'truncated':True},'INCOMPLETE_REPOSITORY_TREE'),
    ('oversized_blob',{'entry':{'path':'Fixture.java','type':'blob','mode':'100644','sha':BLOB,'size':1024*1024+1}},'SOURCE_BLOB_LIMIT'),
    ('hash_mismatch',{'tamper':True},'SOURCE_HASH_MISMATCH'),
    ('revocation_failure',{'revoke_fails':True},'UPSTREAM_REVOCATION_UNCONFIRMED')
]
duplicate={'path':'Fixture.java','type':'blob','mode':'100644','sha':BLOB,'size':len(DATA)}
cases.extend([
    ('duplicate_path',{'entries':[duplicate,duplicate]},'DUPLICATE_REPOSITORY_PATH'),
    ('file_count_limit',{'entries':[{'path':f'Fixture{i}.java','type':'blob','mode':'100644','sha':BLOB,'size':0} for i in range(1001)]},'SOURCE_SNAPSHOT_LIMIT'),
    ('total_source_limit',{'entries':[{'path':f'Fixture{i}.java','type':'blob','mode':'100644','sha':BLOB,'size':1024*1024} for i in range(21)]},'SOURCE_SNAPSHOT_LIMIT')
])
results = {}
for name, options, expected in cases:
    scan_id = uuid.uuid4().hex
    key = job_key('synthetic-fetch-acceptance',scan_id)
    storage = JobStorage(key)
    root = storage.prepare()
    provider = ProviderFixture(**options)
    gateway = fetcher(provider,scan_id)
    try:
        if expected:
            try:
                gateway.fetch(key)
                raise AssertionError('Expected fixed rejection')
            except FetchFailure as error:
                assert str(error) == expected
                assert 'synthetic-upstream-only' not in str(error)
        else:
            result = gateway.fetch(key)
            assert result['commitSha']==COMMIT and result['sourceBytes']==len(DATA) and result['javaFiles']==1
            target = root/'source/src/Fixture.java'
            assert target.read_bytes()==DATA and stat.S_IMODE(target.stat().st_mode)==0o444
            assert json.loads((root/'control/targets.json').read_text())[0][1]['path']=='/input/src/Fixture.java'
            assert gateway.revocation_confirmed
            try:
                gateway.fetch(key)
                raise AssertionError('Expected single-use capability')
            except FetchFailure as error: assert str(error)=='FETCH_CAPABILITY_CONSUMED'
        assert gateway._token is None
        assert provider.revocations == (3 if options.get('revoke_fails') else 1)
    finally:
        storage.cleanup()
    assert not root.exists()
    results[name]='passed'

for bad in ['/absolute','a/../x','a//x','a\\x','a\nx','.git/config','a/.GIT/config','a:stream','x'*513]:
    try:
        safe_path(bad)
        raise AssertionError('Unsafe path accepted')
    except FetchFailure as error: assert str(error)=='UNSAFE_REPOSITORY_PATH'
results['unsafe_path_matrix']='passed'
try:
    GitHubObjectsFetcher(tenant_id='synthetic-fetch-acceptance',scan_id='expired',
        repository_id=123,full_name='AigisAI/fixture',commit_sha=COMMIT,
        token='synthetic-upstream-only',capability_expires_at=time.time()-1,check_authority=lambda:True)
    raise AssertionError('Expired capability accepted')
except FetchFailure as error: assert str(error)=='FETCH_CAPABILITY_EXPIRED'
results['expired_capability']='passed'

# Invalid storage must still revoke a token that was already handed to the gateway.
provider = ProviderFixture()
gateway = fetcher(provider,'invalid-storage')
try:
    gateway.fetch('../invalid')
    raise AssertionError('Invalid job key accepted')
except RuntimeFailure: pass
assert provider.revocations==1 and gateway._token is None
results['invalid_storage_revocation']='passed'

provider=ProviderFixture()
scan_id=uuid.uuid4().hex
gateway=fetcher(provider,scan_id)
gateway._deadline=time.monotonic()-1
storage=JobStorage(job_key('synthetic-fetch-acceptance',scan_id))
root=storage.prepare()
try:
    try:
        gateway.fetch(storage.key)
        raise AssertionError('Expired in-flight capability accepted')
    except FetchFailure as error: assert str(error)=='FETCH_TIMEOUT'
    assert provider.revocations==1 and gateway._token is None
finally:storage.cleanup()
results['expired_inflight_revocation']='passed'
provider=ProviderFixture()
scan_id=uuid.uuid4().hex
gateway=fetcher(provider,scan_id)
gateway._authority=lambda:len(provider.calls)<3
storage=JobStorage(job_key('synthetic-fetch-acceptance',scan_id))
root=storage.prepare()
try:
    try:
        gateway.fetch(storage.key)
        raise AssertionError('Revoked authority accepted')
    except FetchFailure as error: assert str(error)=='FETCH_AUTHORITY_LOST'
    assert not any('/git/blobs/' in path for _,path in provider.calls)
    assert provider.revocations==1 and gateway._token is None
finally:storage.cleanup()
results['midfetch_authority_revoked']='passed'

provider=ProviderFixture()
gateway=fetcher(provider,'scope-one')
storage=JobStorage(job_key('synthetic-fetch-acceptance','scope-two'))
root=storage.prepare()
try:
    try:
        gateway.fetch(storage.key)
        raise AssertionError('Different scan storage accepted')
    except FetchFailure as error: assert str(error)=='JOB_SCOPE_MISMATCH'
    assert provider.calls==[('DELETE','/installation/token')]
    assert provider.revocations==1 and gateway._token is None
    assert not any((root/'source').iterdir())
finally:storage.cleanup()
results['different_scan_storage_revoked']='passed'
report={'sourceGatewayFixture':results,'providerTransport':'synthetic','storage':'actual-no-exec-tmpfs',
    'liveRepositoryFetched':False,'customerCodeExecuted':False,'applicationIngressPromoted':False}
pathlib.Path('/opt/aegisai/scanner/fetch-verification.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
