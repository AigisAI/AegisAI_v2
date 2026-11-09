#!/bin/sh
# Default is read-only validation. --apply requires a later user deployment request.
set -eu
umask 077
directory=${1:?candidate directory required}
manifest_sha=${2:?trusted candidate.json SHA-256 required}
mode=${3:---check}
case "$mode" in --check|--apply) ;; *) exit 2 ;; esac
if [ -f /opt/aegisai/operator/supply-chain-required.json ]; then
  python3 /opt/aegisai/operator/supply-chain/current/deploy/aws-ec2/supply-chain/receipt_guard.py "$directory" "$manifest_sha"
fi
python3 "$directory/check-candidate.py" "$directory" --manifest-sha256 "$manifest_sha" --target
if [ "$mode" = --check ]; then exit 0; fi

python3 - "$directory" <<'PY'
import gzip,json,pathlib,shutil,subprocess,sys
directory=pathlib.Path(sys.argv[1]);manifest=json.loads((directory/'candidate.json').read_text())
root=pathlib.Path('/opt/aegisai')
state={'previousRelease':(root/'shared/candidate-release').read_text().strip(),
       'previousWebOverride':(root/'shared/web-release.override.yaml').read_text() if (root/'shared/web-release.override.yaml').exists() else None,
       'candidateRelease':manifest['releaseId'],'sourceCommit':manifest['sourceCommit']}
recovery=root/'operator'/('before-'+manifest['releaseId']+'.json')
assert not recovery.exists(),'Do not overwrite an existing recovery record'
recovery.write_text(json.dumps(state,indent=2))
subprocess.run(['python3',str(root/'operator/activate-private-ingress.py'),'pause'],check=True)
for kind in ('api','web'):
    image=manifest['images'][kind]
    process=subprocess.Popen(['docker','load'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL)
    try:
        with gzip.open(directory/image['archive'],'rb') as stream:shutil.copyfileobj(stream,process.stdin)
        process.stdin.close();assert process.wait(timeout=120)==0
    finally:
        if process.poll() is None:process.kill();process.wait()
    loaded=json.loads(subprocess.check_output(['docker','image','inspect',image['tag']]))[0]
    assert loaded['Id']==image['id']
archive=pathlib.Path('/home/ubuntu')/manifest['sourceArchive']
assert not archive.exists(),'Do not overwrite an existing source artifact'
shutil.copyfile(directory/manifest['sourceArchive'],archive);archive.chmod(0o600)
with __import__('tarfile').open(archive,'r:gz') as source:
    member=source.extractfile('deploy/aws-ec2/deploy-candidate.sh')
    script=directory/'verified-deploy-candidate.sh';script.write_bytes(member.read());script.chmod(0o700)
source_sha=next(item['sha256'] for item in manifest['files'] if item['name']==manifest['sourceArchive'])
subprocess.run(['sh',str(script),manifest['releaseId'],source_sha,'prebuilt',str(directory/'candidate.json')],check=True)
print('CANDIDATE_INSTALLED_INGRESS_REMAINS_CLOSED_FOR_POST_DEPLOYMENT_ACCEPTANCE')
PY
