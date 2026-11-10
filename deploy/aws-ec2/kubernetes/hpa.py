"""Explicit replica ownership before the real API-only bounded HPA starts."""
import argparse
import json
import os
from pathlib import Path

from bootstrap import ROOT, now
from foundation import kube
from metrics import obj


def main():
    assert os.geteuid()==0 and __debug__;os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    metrics=json.loads(kube('get','--raw','/apis/metrics.k8s.io/v1beta1/namespaces/aegisai-private/pods'))
    assert any(p['metadata']['name'].startswith('api-') for p in metrics['items'])
    app=json.loads(kube('get','application','aegisai-private','-n','argocd','-o','json'))
    assert app['status']['sync']['status']=='Synced' and app['status']['health']['status']=='Healthy'
    assert 'RespectIgnoreDifferences=true' in app['spec']['syncPolicy']['syncOptions']
    hpa=obj('HorizontalPodAutoscaler','api',api='autoscaling/v2',namespace='aegisai-private',spec={
        'scaleTargetRef':{'apiVersion':'apps/v1','kind':'Deployment','name':'api'},'minReplicas':1,'maxReplicas':2,
        'metrics':[{'type':'Resource','resource':{'name':'cpu','target':{'type':'Utilization','averageUtilization':25}}}],
        'behavior':{'scaleUp':{'stabilizationWindowSeconds':0,'policies':[{'type':'Pods','value':1,'periodSeconds':30}]},
                    'scaleDown':{'stabilizationWindowSeconds':30,'policies':[{'type':'Pods','value':1,'periodSeconds':30}]}}})
    if not args.apply:print(json.dumps({'apiHpaPlan':'ready','minimum':1,'maximum':2,'metric':'actual-cpu'}));return
    ignore={'group':'apps','kind':'Deployment','name':'api','namespace':'aegisai-private','jsonPointers':['/spec/replicas']}
    previous=app['spec'].get('ignoreDifferences',[])
    assert not any(v.get('kind')=='Deployment' and v.get('name')=='api' for v in previous)
    kube('patch','application','aegisai-private','-n','argocd','--type=merge','-p',json.dumps({'spec':{'ignoreDifferences':previous+[ignore]}}))
    kube('apply','--server-side','--field-manager=aegisai-api-scaling','-f','-',value=hpa)
    report={'apiHpa':'installed','minimum':1,'maximum':2,'replicaOwner':'HPA','gitOpsRespectsReplicas':True,
            'metric':'actual-cpu','cpuTargetPercentOf150mRequest':25,'actualScalingVerified':False,'installedAt':now()}
    (ROOT/'resource-metrics/hpa-installation-result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


if __name__=='__main__':main()
