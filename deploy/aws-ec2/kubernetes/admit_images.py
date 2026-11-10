"""Verify a separately approved signed candidate before importing into K3s."""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from bootstrap import BINARY, ROOT, PIN, digest, now, snapshot
from foundation import kube


def image_policy(images, previous=None):
    for release in (images,previous or {}):
        if not release:continue
        assert set(release)=={'api','web'}
        for kind,value in release.items():
            assert re.fullmatch(r'docker.io/library/aegisai-'+kind+r'@sha256:[a-f0-9]{64}',value['reference'])
    allowed = sorted({value['reference'] for release in (images, previous or {}) for value in release.values()})
    assert 2 <= len(allowed) <= 4 and all(re.fullmatch(
        r'docker.io/library/aegisai-(api|web)@sha256:[a-f0-9]{64}', value) for value in allowed)
    expression = 'c.image in ' + json.dumps(allowed)
    return {'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicy',
        'metadata':{'name':'aegisai-approved-private-images'},'spec':{'failurePolicy':'Fail',
            'matchConstraints':{'resourceRules':[{'apiGroups':[''],'apiVersions':['v1'],
                'operations':['CREATE','UPDATE'],'resources':['pods','pods/ephemeralcontainers']}]},
            'validations':[
                {'expression':'object.spec.containers.all(c, '+expression+')',
                 'message':'Only operator-approved signed API/web image digests are admitted'},
                {'expression':'!has(object.spec.initContainers) || object.spec.initContainers.all(c, '+expression+')',
                 'message':'Unsigned init containers are forbidden'},
                {'expression':'!has(object.spec.ephemeralContainers) || size(object.spec.ephemeralContainers) == 0',
                 'message':'Ephemeral debug containers are not admitted in the private application namespace'},
                {'expression':'has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false',
                 'message':'Application Pods cannot mount Kubernetes API credentials'}]}}


def retained_release(previous, active_source):
    records=previous.get('approvedReleases',[previous])
    assert 1<=len(records)<=2
    selected=[value for value in records if value['approvedSource']==active_source]
    assert len(selected)==1,'ACTIVE_RELEASE_NOT_PREVIOUSLY_ADMITTED'
    value=selected[0]
    assert value['verification']['signedCandidateVerification']=='passed'
    assert value['verification']['sourceCommit']==active_source
    assert value['verification']['manifestSha256']==value['manifestSha256']
    assert set(value['images'])=={'api','web'}
    image_policy(value['images'])
    return {key:value[key] for key in ('approvedSource','manifestSha256','verification','images')}


def main():
    import fcntl
    assert os.geteuid() == 0 and __debug__
    os.umask(0o077)
    lock=Path('/opt/aegisai/operator/signed-deployment.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--approved-source',required=True)
    args=parser.parse_args()
    assert digest(BINARY) == PIN['binary']['sha256']
    trusted=Path('/opt/aegisai/operator/supply-chain/current/deploy/aws-ec2/supply-chain')
    assert trusted.resolve().is_relative_to(Path('/opt/aegisai/operator/supply-chain/releases'))
    for path in (trusted/'verify_candidate.py',trusted/'policy.py'):
        assert path.stat().st_uid == 0 and not path.stat().st_mode & 0o022
    sys.path.insert(0,str(trusted))
    from verify_candidate import verify
    from policy import strict_json
    approval=Path('/opt/aegisai/operator/supply-chain-required.json')
    assert approval.stat().st_uid == 0 and not approval.stat().st_mode & 0o077
    assert args.approved_source in strict_json(approval)['approvedSources'], 'SOURCE_NOT_OPERATOR_APPROVED'
    before=snapshot()
    previous=None;ledger_path=ROOT/'approved-app-images.json'
    if ledger_path.exists():
        assert not ledger_path.is_symlink() and ledger_path.stat().st_uid==0 and not ledger_path.stat().st_mode&0o077
        existing=strict_json(ledger_path,65536)
        traffic=Path('/opt/aegisai/operator/application-traffic.json')
        source=strict_json(traffic)['approvedSource'] if traffic.exists() else existing['approvedSource']
        previous=retained_release(existing,source)
        assert source in strict_json(approval)['approvedSources']
    # No candidate code is executed. Same trusted H3 crypto/source/scan checks
    # run before any containerd image import or Kubernetes admission mutation.
    verification=verify(args.directory,args.manifest_sha256,args.approved_source,target=True)
    manifest=strict_json(args.directory/'candidate.json')
    images={}
    for kind in ('api','web'):
        image=manifest['images'][kind]
        command=[str(BINARY),'ctr','-n','k8s.io','images','import','--digests','--no-unpack','-']
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.DEVNULL)
        try:
            with gzip.open(args.directory/image['archive'],'rb') as source:
                shutil.copyfileobj(source,process.stdin)
            process.stdin.close()
            assert process.wait(timeout=90) == 0, 'IMAGE_IMPORT_FAILED'
        finally:
            if process.poll() is None:
                process.kill();process.wait()
        canonical='docker.io/library/'+image['tag']
        rows=subprocess.check_output([str(BINARY),'ctr','-n','k8s.io','images','ls'],text=True).splitlines()
        matches=[row.split()[2] for row in rows if row.split() and row.split()[0] == canonical]
        assert len(matches) == 1 and re.fullmatch('sha256:[a-f0-9]{64}',matches[0])
        reference=canonical.split(':')[0]+'@'+matches[0]
        subprocess.run([str(BINARY),'ctr','-n','k8s.io','images','tag','--force',canonical,reference],
                       check=True,timeout=15,stdout=subprocess.DEVNULL)
        images[kind]={'reference':reference,'candidateImageId':image['id'],'importedTargetDigest':matches[0]}
    policy=image_policy(images,previous['images'] if previous else None)
    kube('apply','--server-side','--field-manager=aegisai-operator-admission','-f','-',value=policy)
    binding={'apiVersion':'admissionregistration.k8s.io/v1','kind':'ValidatingAdmissionPolicyBinding',
        'metadata':{'name':'aegisai-approved-private-images'},'spec':{
            'policyName':'aegisai-approved-private-images','validationActions':['Deny','Audit'],
            'matchResources':{'namespaceSelector':{'matchLabels':{'aegisai.io/signed-app':'required'}}}}}
    kube('apply','--server-side','--field-manager=aegisai-operator-admission','-f','-',value=binding)
    kube('label','namespace','aegisai-private','aegisai.io/signed-app=required','--overwrite')
    # Keep restricted PodSecurity and default-deny. Permit DNS only; API-specific
    # metadata/SCM/data paths are a later reviewed migration step.
    kube('apply','-f','-',value={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy',
        'metadata':{'name':'allow-dns','namespace':'aegisai-private'},'spec':{
            'podSelector':{},'policyTypes':['Egress'],'egress':[{
                'to':[{'namespaceSelector':{'matchLabels':{'kubernetes.io/metadata.name':'kube-system'}},
                       'podSelector':{'matchLabels':{'k8s-app':'kube-dns'}}}],
                'ports':[{'protocol':'UDP','port':53},{'protocol':'TCP','port':53}]}]}})
    assert snapshot() == before
    ledger={'signedK3sImageAdmission':'enforced','approvedSource':args.approved_source,
        'manifestSha256':args.manifest_sha256,'verification':verification,'images':images,
        'privateNamespaceRestricted':True,'applicationUnchanged':True,'trafficMoved':False,
        'verifiedAt':now()}
    current={key:ledger[key] for key in ('approvedSource','manifestSha256','verification','images')}
    ledger['approvedReleases']=[current]+([previous] if previous and previous['approvedSource']!=args.approved_source else [])
    (ROOT/'approved-app-images.json').write_text(json.dumps(ledger,indent=2))
    print(json.dumps(ledger))


if __name__ == '__main__':
    main()
