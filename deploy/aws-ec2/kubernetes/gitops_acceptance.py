"""One harmless drift, actual immutable Git forward/back, no new scan or image."""
import copy
import hashlib
import json
import os
import time
import urllib.request

from bootstrap import ROOT, now
from foundation import kube
from gitops_adopt import boundaries, pod_ids, REVISION

NORMALIZED='e1dd6fe8808521793600f70d68f814d3c258d804'


def healthy():
    assert urllib.request.urlopen('http://127.0.0.1:8081/api/health',timeout=10).status==200
    app=json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))
    return app


def deployment(name):
    return json.loads(kube('get','deployment',name,'-n','aegisai-private','-o','json'))


def wait_revision(revision,history,ids):
    for _ in range(60):
        app=healthy();status=app.get('status',{})
        if (status.get('sync',{}).get('revision')==revision and status['sync'].get('status')=='Synced'
            and status.get('health',{}).get('status')=='Healthy'
            and all(deployment(name)['spec']['revisionHistoryLimit']==history for name in ('api','web'))):
            assert pod_ids()==ids
            return
        time.sleep(3)
    raise RuntimeError('GIT_REVISION_NOT_RECONCILED')


def adoption_evidence():
    before=json.loads((ROOT/'gitops/pre-adoption-pods.json').read_text());current=pod_ids()
    assert len(before)==len(current)==2
    for name,uid in before.items():
        if name.startswith('api-'):assert current.get(name)==uid
    web_changed=before!=current
    if web_changed:
        sets=json.loads(kube('get','replicasets','-n','aegisai-private','-l','app.kubernetes.io/component=web','-o','json'))['items']
        sets.sort(key=lambda v:v['metadata']['creationTimestamp']);assert len(sets)==2
        old,new=[copy.deepcopy(v['spec']['template']) for v in sets]
        text=json.loads(kube('get','configmap','web-nginx','-n','aegisai-private','-o','json'))['data']['nginx.conf'].replace('\r\n','\n')
        assert old['metadata']['annotations'].pop('checksum/web-config')==hashlib.sha256(text.replace('\n','\r\n').encode()).hexdigest()
        assert new['metadata']['annotations'].pop('checksum/web-config')==hashlib.sha256(text.encode()).hexdigest()
        for value in (old,new):value['metadata']['labels'].pop('pod-template-hash',None)
        assert old==new,'UNEXPLAINED_WEB_TEMPLATE_CHANGE'
    return current,web_changed


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    native=boundaries();ids,web_changed=adoption_evidence()
    ledger=json.loads((ROOT/'approved-app-images.json').read_text())
    for name in ('api','web'):
        assert deployment(name)['spec']['template']['spec']['containers'][0]['image']==ledger['images'][name]['reference']
    original=deployment('api')['spec']['revisionHistoryLimit'];assert original==2
    start=time.monotonic()
    kube('patch','deployment','api','-n','aegisai-private','--type=merge','-p',json.dumps({'spec':{'revisionHistoryLimit':1}}))
    assert deployment('api')['spec']['revisionHistoryLimit']==1
    for _ in range(45):
        if deployment('api')['spec']['revisionHistoryLimit']==original:break
        time.sleep(3)
    else:raise RuntimeError('ACTUAL_DRIFT_NOT_CORRECTED')
    assert pod_ids()==ids;healthy()
    drift_seconds=round(time.monotonic()-start,3)
    steps=[]
    for revision,history in ((NORMALIZED,3),(REVISION,2),(NORMALIZED,3)):
        kube('patch','application','aegisai-private','-n','argocd','--type=merge','-p',json.dumps({'spec':{'source':{'targetRevision':revision}}}))
        wait_revision(revision,history,ids)
        steps.append({'chartRevision':revision,'actualRevisionHistoryLimit':history,'existingPodsUnchanged':True})
    report={'actualGitOpsAcceptance':'passed','nativeNamespaceBoundaries':native,
            'adoptionApiPodUnchanged':True,'adoptionWebRolledOnceForLineEndings':web_changed,
            'actualHarmlessDriftCorrected':True,'driftSeconds':drift_seconds,'actualGitForwardBack':steps,
            'applicationSource':ledger['approvedSource'],'activeGitRevision':NORMALIZED,
            'sameSignedImagesPreserved':True,'newScanExecuted':False,'newMigrationsApplied':False,
            'generalQualification':'NOT_QUALIFIED','verifiedAt':now()}
    (ROOT/'gitops/acceptance-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
