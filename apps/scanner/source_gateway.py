"""Dedicated fetch UID entrypoint. Receives upstream credentials only in RAM.
Not started by importing this module; no public listener or background consumer.
"""
import datetime
import json
import os
import sys

from broker_client import BrokerClient
from github_fetch import GitHubObjectsFetcher, FetchFailure
from runtime import RuntimeFailure, job_key


def frame(response):
    raw = response.readline(16385)
    if not raw.endswith(b'\n') or len(raw)>16384:
        raise RuntimeFailure('INVALID_GATEWAY_FRAME')
    value = json.loads(raw)
    if not isinstance(value,dict):
        raise RuntimeFailure('INVALID_GATEWAY_FRAME')
    return value


def fetch_assignment(assignment, *, broker=None, transport=None):
    if not isinstance(assignment,dict) or set(assignment)!= {'lease','capability'} or not isinstance(assignment['lease'],dict):
        raise RuntimeFailure('INVALID_GATEWAY_ASSIGNMENT')
    broker = broker or BrokerClient('gateway')
    connection,response = broker.open('/gateway/open',assignment)
    scope = None
    completed = False
    try:
        if response.getheader('Content-Type','').split(';')[0]!='application/x-ndjson':
            raise RuntimeFailure('INVALID_GATEWAY_FRAME')
        first = frame(response)
        if set(first)!= {'kind','claim'} or first['kind']!='fetch-scope' or not isinstance(first['claim'],dict):
            raise RuntimeFailure('INVALID_GATEWAY_FRAME')
        scope = first['claim']
        lease = assignment['lease']
        if scope.get('tenantId')!=lease.get('tenantId') or scope.get('scanRequestId')!=lease.get('scanRequestId') or scope.get('dispatchJobId')!=lease.get('jobId'):
            raise RuntimeFailure('INVALID_GATEWAY_SCOPE')
        authority = {name:scope[name] for name in ('tenantId','credentialId','claimToken')}
        secret = frame(response)
        if set(secret)!= {'upstreamToken','expiresAt'} or secret['expiresAt']!=scope['expiresAt']:
            raise RuntimeFailure('INVALID_GATEWAY_FRAME')
        deadline = datetime.datetime.fromisoformat(scope['expiresAt'].replace('Z','+00:00')).timestamp()
        gateway = GitHubObjectsFetcher(tenant_id=scope['tenantId'],scan_id=scope['scanRequestId'],
            repository_id=int(scope['providerRepoId']),full_name=scope['fullName'],commit_sha=scope['commitSha'],
            token=secret.pop('upstreamToken'),capability_expires_at=deadline,
            check_authority=lambda:broker.request('/gateway/check',authority)=={'authorized':True},transport=transport)
        metadata = gateway.fetch(job_key(scope['tenantId'],scope['scanRequestId']))
        finish = broker.request('/gateway/finish',{**authority,'success':True})
        completed = True
        if not gateway.revocation_confirmed or not isinstance(finish,dict) or finish.get('handoffAllowed') is not True or finish.get('integrationSuspended') is not False:
            raise RuntimeFailure('GATEWAY_HANDOFF_DENIED')
        # This receipt is metadata only, never a token, source blob or arbitrary
        # provider body. The supervisor independently asks the broker to start.
        return {'credentialId':scope['credentialId'],'tenantId':scope['tenantId'],
                'scanRequestId':scope['scanRequestId'],'commitSha':scope['commitSha'],
                'sourceBytes':metadata['sourceBytes'],'javaFiles':metadata['javaFiles']}
    finally:
        if not completed and scope is not None:
            try:
                broker.request('/gateway/finish',{**{name:scope[name] for name in ('tenantId','credentialId','claimToken')},'success':False})
            except Exception:
                pass  # Closing the held stream independently triggers revocation.
        response.close()
        connection.close()


if __name__=='__main__':
    try:
        if os.geteuid()!=50001 or os.getegid()!=50001 or not set(os.getgroups())<={50001}:
            raise RuntimeFailure('DEDICATED_GATEWAY_UID_REQUIRED')
        raw = sys.stdin.buffer.read(16385)
        if len(raw)>16384:
            raise RuntimeFailure('INVALID_GATEWAY_ASSIGNMENT')
        receipt = fetch_assignment(json.loads(raw))
        sys.stdout.write(json.dumps({'ok':True,'data':receipt})+'\n')
    except Exception as error:
        code = str(error) if isinstance(error,FetchFailure) and str(error) in {
            'UNSUPPORTED_SCAN_PROFILE','SOURCE_BLOB_LIMIT','SOURCE_SNAPSHOT_LIMIT','UNSUPPORTED_REPOSITORY_ENTRY',
            'UNSAFE_REPOSITORY_PATH','DUPLICATE_REPOSITORY_PATH','INCOMPLETE_REPOSITORY_TREE'} else 'SOURCE_FETCH_FAILED'
        sys.stdout.write(json.dumps({'ok':False,'errorCode':code})+'\n')
        sys.exit(1)
