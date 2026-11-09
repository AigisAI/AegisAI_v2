"""Package CI-built private images and tracked source. Never contacts production."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

import importlib.util

spec = importlib.util.spec_from_file_location('candidate_checker', pathlib.Path(__file__).with_name('check-candidate.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
parser = argparse.ArgumentParser()
parser.add_argument('output', type=pathlib.Path)
options = parser.parse_args()
assert os.environ.get('GITHUB_ACTIONS') == 'true', 'CANDIDATE_REQUIRES_HOSTED_CI'
assert not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert commit == os.environ['GITHUB_SHA']
epoch = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], text=True).strip())
release = 'ec2-runtime-' + datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
output = options.output
output.mkdir(parents=True, exist_ok=False)
source = output / (release + '.tar.gz')
subprocess.run(['git', 'archive', '--format=tar.gz', '--output', str(source), commit], check=True)
images = {}
for kind in ('api', 'web'):
    tag = 'aegisai-' + kind + ':' + release
    subprocess.run(['docker', 'tag', 'aegisai-private-' + kind + ':ci', tag], check=True)
    info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
    archive = output / (kind + '-image.tar.gz')
    process = subprocess.Popen(['docker', 'save', tag], stdout=subprocess.PIPE)
    with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
        shutil.copyfileobj(process.stdout, compressed, 1024 * 1024)
    assert process.wait(timeout=120) == 0
    images[kind] = {'tag': tag, 'id': info['Id'], 'archive': archive.name, 'uncompressedBytes': info['Size']}
shutil.copyfile('deploy/aws-ec2/runtime-profile.json', output / 'runtime-profile.json')
shutil.copyfile(pathlib.Path(__file__).with_name('check-candidate.py'), output / 'check-candidate.py')
shutil.copyfile(pathlib.Path(__file__).with_name('deploy-prepared.sh'), output / 'deploy-prepared.sh')
manifest = {'version': 1, 'profile': 'private-single-host-v1', 'generalQualification': 'NOT_QUALIFIED',
    'sourceCommit': commit, 'releaseId': release, 'sourceArchive': source.name, 'images': images,
    'ciRunId': os.environ['GITHUB_RUN_ID'], 'deploymentPerformed': False,
    'files': [{'name': path.name, 'sha256': checker.digest(path)} for path in sorted(output.iterdir())]}
path = output / 'candidate.json'
path.write_text(json.dumps(manifest, indent=2) + '\n')
sha = checker.digest(path)
checker.check(output, sha)
(output / 'candidate.sha256').write_text(sha + '  candidate.json\n')
print(json.dumps({'preparedCandidate': release, 'sourceCommit': commit, 'manifestSha256': sha,
                  'deploymentPerformed': False}))
