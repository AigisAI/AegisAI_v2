"""One bounded real HTTP load; actual1->2->1 and missing metrics observation."""
import collections
import concurrent.futures
import http.client
import json
import os
import threading
import time

from bootstrap import BINARY, ROOT, now
from foundation import kube
import subprocess


def deployment():return json.loads(kube('get','deployment','api','-n','aegisai-private','-o','json'))
def hpa():return json.loads(kube('get','hpa','api','-n','aegisai-private','-o','json'))


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    initial=deployment();assert initial['spec']['replicas']==1 and initial['status']['readyReplicas']==1
    ceiling=hpa()['spec'];assert ceiling['minReplicas']==1 and ceiling['maxReplicas']==2
    stop=threading.Event();counts=collections.Counter();lock=threading.Lock();samples=[]
    start=time.monotonic();deadline=start+60
    # Four persistent clients,45RPS each, at most60s/10800 requests. The endpoint
    # is read-only. Normal200 and real throttling429 are both recorded, not hidden.
    def load():
        connection=http.client.HTTPConnection('127.0.0.1',8081,timeout=3)
        target=time.monotonic()
        try:
            while not stop.is_set() and time.monotonic()<deadline:
                target=time.monotonic()+1/45
                try:
                    connection.request('GET','/api/health',headers={'Host':'aegisai-aws.tailaca7d2.ts.net'})
                    response=connection.getresponse();response.read(65536);code=str(response.status)
                except Exception:
                    code='transport-error';connection.close();connection=http.client.HTTPConnection('127.0.0.1',8081,timeout=3)
                with lock:counts[code]+=1
                stop.wait(max(0,target-time.monotonic()))
        finally:connection.close()
    restore_timer=None;scaled=False;missing=False
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs=[pool.submit(load) for _ in range(4)]
            while time.monotonic()<start+100:
                d=deployment();state=hpa()['status'];replicas=d['spec']['replicas']
                assert 1<=replicas<=2
                samples.append({'seconds':round(time.monotonic()-start,2),'desired':replicas,
                    'ready':d['status'].get('readyReplicas',0),'metrics':state.get('currentMetrics',[])})
                if replicas==2 and d['status'].get('readyReplicas')==2:scaled=True;break
                if time.monotonic()>deadline:break
                time.sleep(3)
            stop.set()
            for job in jobs:job.result(timeout=5)
        load_seconds=round(time.monotonic()-start,3)
        assert scaled,'BOUNDED_REAL_LOAD_DID_NOT_CAUSE_SCALE_UP'
        print(json.dumps({'actualScaleUp':'1-to-2','requests':sum(counts.values()),'statuses':dict(counts),'seconds':load_seconds}),flush=True)
        # Independently scheduled restoration survives an interrupted verifier.
        restore_timer='aegisai-metrics-restore-'+str(int(time.time()))
        binary=[str(BINARY),'kubectl','--kubeconfig',str(ROOT/'kubeconfig.yaml')]
        subprocess.run(['systemd-run','--quiet','--unit='+restore_timer,'--on-active=80s',
            *binary,'scale','deployment/metrics-server','-n','aegisai-system','--replicas=1'],check=True,capture_output=True,timeout=10)
        kube('scale','deployment/metrics-server','-n','aegisai-system','--replicas=0')
        missing_start=time.monotonic();retained=[]
        while time.monotonic()-missing_start<45:
            state=hpa()['status'];d=deployment();retained.append(d['spec']['replicas'])
            assert d['spec']['replicas']==2
            if any(c['type']=='ScalingActive' and c['status']=='False' and c.get('reason')=='FailedGetResourceMetric' for c in state.get('conditions',[])):
                missing=True;break
            time.sleep(3)
        assert missing,'MISSING_METRIC_STATE_NOT_OBSERVED'
        kube('scale','deployment/metrics-server','-n','aegisai-system','--replicas=1')
        for _ in range(75):
            d=deployment()
            if d['spec']['replicas']==1 and d['status'].get('readyReplicas')==1 and d['status'].get('replicas')==1:break
            time.sleep(3)
        else:raise RuntimeError('ACTUAL_SCALE_DOWN_NOT_OBSERVED')
        metrics=json.loads(kube('get','--raw','/apis/metrics.k8s.io/v1beta1/namespaces/aegisai-private/pods'))
        assert any(p['metadata']['name'].startswith('api-') for p in metrics['items'])
        app=json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))
        assert app['status']['sync']['status']=='Synced'
        report={'actualApiHpa':'passed','replicas':[1,2,1],'realCpuMetricSamples':samples,
            'boundedLoad':{'maximumRps':180,'maximumConcurrency':4,'maximumSeconds':60,'actualRequests':sum(counts.values()),
                'statuses':dict(counts),'actualSeconds':load_seconds,'successfulTrafficBenchmarkClaimed':False},
            'actualMissingMetricsObserved':True,'replicasWhileMetricsMissing':retained,
            'collectorRestored':True,'gitOpsRespectedHpaReplicas':True,'extraComputeCreated':False,
            'newScanExecuted':False,'newMigrationsApplied':False,'verifiedAt':now()}
        (ROOT/'resource-metrics/hpa-acceptance-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
    finally:
        stop.set()
        kube('scale','deployment/metrics-server','-n','aegisai-system','--replicas=1')
        if restore_timer:subprocess.run(['systemctl','stop',restore_timer+'.timer'],capture_output=True,timeout=10)


if __name__=='__main__':main()
