"""Fresh signed import -> immutable Git desired values -> observed rollout/recovery."""
import argparse
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request

from bootstrap import ROOT, SOURCE, now
from delivery_gate import require_aws_delivery_gate
from foundation import kube
from image_retention import require_pinned

OPERATOR=Path('/opt/aegisai/operator')
REPO='https://github.com/AigisAI/AegisAI_v2.git'
VALUE_FILE='deploy/aws-ec2/kubernetes/environments/private-release.json'


def app():return json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))


def http_health():
    connection=http.client.HTTPConnection('127.0.0.1',8081,timeout=5)
    try:
        connection.request('GET','/api/health');response=connection.getresponse();response.read(65536);return response.status
    finally:connection.close()


def pod_state():
    return [{'name':p['metadata']['name'],'uid':p['metadata']['uid'],
             'component':p['metadata']['labels']['app.kubernetes.io/component'],
             'image':p['spec']['containers'][0]['image'],
             'ready':any(c['type']=='Ready' and c['status']=='True' for c in p['status'].get('conditions',[])),
             'terminating':bool(p['metadata'].get('deletionTimestamp'))}
            for p in json.loads(kube('get','pods','-n','aegisai-private','-o','json'))['items']]


def wait_ready(revision,images,timeout,samples):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        state=app();pods=pod_state();status=http_health()
        samples.append({'at':now(),'httpHealth':status,'pods':pods})
        assert status==200,'PRIVATE_HEALTH_FAILED_'+str(status)
        assert sum(p['component']=='api' for p in pods)<=3 and sum(p['component']=='web' for p in pods)<=2
        active=[p for p in pods if not p['terminating']]
        if (state.get('status',{}).get('sync',{}).get('revision')==revision
            and state['status']['sync'].get('status')=='Synced'
            and state['status'].get('health',{}).get('status')=='Healthy'
            and all(p['ready'] and p['image']==images[p['component']] for p in active)
            and any(p['component']=='api' for p in active) and any(p['component']=='web' for p in active)
            and not any(p['terminating'] for p in pods)):
            return True
        time.sleep(3)
    return False


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('git_revision');parser.add_argument('--apply',action='store_true')
    parser.add_argument('--expect-rejection',action='store_true');args=parser.parse_args()
    assert re.fullmatch('[a-f0-9]{40}',args.git_revision)
    delivery_run = require_aws_delivery_gate(args.git_revision)
    lock=(OPERATOR/'signed-deployment.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    url='https://raw.githubusercontent.com/AigisAI/AegisAI_v2/'+args.git_revision+'/'+VALUE_FILE
    with urllib.request.urlopen(url,timeout=20) as response:raw=response.read(65537)
    assert len(raw)<=65536;values=json.loads(raw)
    assert set(values)<= {'images','revision','apiReplicas','frontendIngressCidrs','apiReadinessPath'}
    assert values['apiReplicas']==1 and values['frontendIngressCidrs']==['172.18.0.3/32','172.29.240.2/32']
    assert values.get('apiReadinessPath','/api/health')==('/api/health-unavailable' if args.expect_rejection else '/api/health')
    ledger=json.loads((ROOT/'approved-app-images.json').read_text())
    matching=[record for record in ledger.get('approvedReleases',[ledger]) if record['approvedSource']==values['revision']]
    assert len(matching)==1;release=matching[0]
    expected={kind:item['reference'] for kind,item in release['images'].items()}
    assert values['images']==expected and set(expected)=={'api','web'}
    trusted=Path('/opt/aegisai/operator/supply-chain/current/deploy/aws-ec2/supply-chain')
    assert trusted.resolve().is_relative_to(OPERATOR/'supply-chain/releases')
    sys.path.insert(0,str(trusted));from verify_candidate import verify
    directories=[]
    for candidate in (OPERATOR/'candidates').iterdir():
        manifest=candidate/'candidate.json'
        if not re.fullmatch(r'ec2-runtime-[0-9]{8}-[0-9]{6}',candidate.name) or not manifest.is_file():continue
        if hashlib.sha256(manifest.read_bytes()).hexdigest()==release['manifestSha256']:directories.append(candidate)
    assert len(directories)==1
    receipt=verify(directories[0],release['manifestSha256'],release['approvedSource'],target=True)
    assert receipt['signedCandidateVerification']=='passed'
    # Refuse before changing Git if the offline rollback/promotion cache is absent.
    require_pinned(release['images'])
    current=app();previous_source=current['spec']['source']
    assert previous_source['repoURL']==REPO and previous_source['path']=='deploy/aws-ec2/kubernetes/chart'
    assert 'RespectIgnoreDifferences=true' in current['spec']['syncPolicy']['syncOptions']
    assert any(v.get('name')=='api' and '/spec/replicas' in v.get('jsonPointers',[]) for v in current['spec']['ignoreDifferences'])
    traffic_path=OPERATOR/'application-traffic.json';traffic=json.loads(traffic_path.read_text())
    assert traffic['backend']=='kubernetes' and http_health()==200
    if not args.apply:print(json.dumps({'gitPromotionPlan':'ready','source':values['revision'],'gitRevision':args.git_revision,'awsDeliveryGateRun':delivery_run,'freshSignatureVerification':'passed'}));return
    target={**previous_source,'targetRevision':args.git_revision,
            'helm':{'releaseName':'aegisai-private','valueFiles':['../environments/private-release.json']}}
    before=pod_state();samples=[];started=time.monotonic()
    kube('patch','application','aegisai-private','-n','argocd','--type=json','-p',json.dumps([{'op':'replace','path':'/spec/source','value':target}]))
    accepted=False;failure=None
    try:
        accepted=wait_ready(args.git_revision,expected,50 if args.expect_rejection else 180,samples)
        if args.expect_rejection:
            assert not accepted,'EXPECTED_BAD_CANDIDATE_WAS_ACCEPTED'
            old_ready={p['uid'] for p in before if p['component']=='api' and p['ready']}
            assert any(p['component']=='api' and not p['ready'] and not p['terminating'] and p['uid'] not in old_ready
                       for sample in samples for p in sample['pods']),'NON_READY_CANDIDATE_POD_NOT_OBSERVED'
            assert all(any(p['uid'] in old_ready and p['ready'] for p in sample['pods']) for sample in samples),'OLD_READY_REPLICA_NOT_PRESERVED'
        else:assert accepted,'NEW_RELEASE_NOT_READY'
    except BaseException as error:
        failure=type(error).__name__+': '+str(error)[:300]
        raise
    finally:
        if not accepted or args.expect_rejection:
            kube('patch','application','aegisai-private','-n','argocd','--type=json','-p',json.dumps([{'op':'replace','path':'/spec/source','value':previous_source}]))
            previous_images={kind:item['reference'] for kind,item in traffic['images'].items()}
            assert wait_ready(previous_source['targetRevision'],previous_images,180,samples),'AUTOMATIC_GIT_RECOVERY_FAILED'
        if failure:
            (ROOT/'gitops'/('failed-promotion-'+args.git_revision[:12]+'.json')).write_text(json.dumps({
                'failure':failure,'gitRevision':args.git_revision,'actualSamples':samples,
                'restoredGitRevision':previous_source['targetRevision'],'verifiedAt':now()},indent=2))
    if accepted and not args.expect_rejection:
        traffic.update(approvedSource=release['approvedSource'],images=release['images'],gitRevision=args.git_revision,
            manifestSha256=release['manifestSha256'],gitValueFile=VALUE_FILE,changedAt=now())
        traffic_path.write_text(json.dumps(traffic,indent=2))
    report={'gitReleasePromotion':'rejected-and-recovered' if args.expect_rejection else 'passed',
            'gitRevision':args.git_revision,'applicationSource':values['revision'],'awsDeliveryGateRun':delivery_run,'beforePods':before,
            'actualSamples':samples,'allHealthSamples200':all(v['httpHealth']==200 for v in samples),
            'freshSignatureVerification':'passed','hpaOwnershipPreserved':True,'newScanExecuted':False,
            'newMigrationsApplied':False,'seconds':round(time.monotonic()-started,3),'verifiedAt':now()}
    path=ROOT/'gitops'/('promotion-'+args.git_revision[:12]+'.json');path.write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if k not in ('actualSamples','beforePods')}))


if __name__=='__main__':main()
