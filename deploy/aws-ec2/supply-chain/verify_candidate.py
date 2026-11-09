"""Trusted host/CI verifier. Verification never loads images or changes services."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

from policy import digest, strict_json, validate_security, REPOSITORY, WORKFLOW


def gh_binary():
    pins = strict_json(Path(__file__).with_name('toolchain.json'))
    root = Path('/opt/aegisai-ci-supply-chain-tools') if os.environ.get('GITHUB_ACTIONS') == 'true' else Path('/opt/aegisai/platform/tools/supply-chain')
    binary = root/'gh'/pins['gh']['version']/'gh'
    proof = binary.with_name('verified-install.json')
    if binary.is_symlink() or binary.stat().st_uid != 0 or binary.stat().st_mode & 0o022:
        raise ValueError('UNTRUSTED_SIGNATURE_VERIFIER')
    if proof.stat().st_uid != 0 or proof.stat().st_mode & 0o022:
        raise ValueError('UNTRUSTED_VERIFIER_INSTALLATION')
    if digest(binary) != strict_json(proof)['binarySha256']:
        raise ValueError('SIGNATURE_VERIFIER_CHANGED')
    return binary


def cryptographic_verify(path, bundle, approved_source, predicate='https://slsa.dev/provenance/v1'):
    strict_json(bundle,8*1024**2)
    if not re.fullmatch('[a-f0-9]{40}',approved_source):
        raise ValueError('APPROVED_SOURCE_REQUIRED')
    cache = Path(os.environ.get('RUNNER_TEMP','/opt/aegisai/operator/supply-chain-348'))/'verification-cache'
    cache.mkdir(mode=0o700,exist_ok=True)
    environment = {'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(cache),'GH_CONFIG_DIR':str(cache/'gh'),
                   'GH_HOST':'github.com','GH_NO_UPDATE_NOTIFIER':'1','GH_PROMPT_DISABLED':'1'}
    result = subprocess.run([str(gh_binary()),'attestation','verify',str(path),'--bundle',str(bundle),
        '--repo',REPOSITORY,'--signer-workflow',WORKFLOW,'--source-digest',approved_source,
        '--signer-digest',approved_source,'--deny-self-hosted-runners',
        '--cert-oidc-issuer','https://token.actions.githubusercontent.com','--predicate-type',predicate,
        '--format','json'],capture_output=True,text=True,env=environment,timeout=90)
    if result.returncode:
        (cache/'last-verification-error.txt').write_text(result.stderr[:16000])
        raise ValueError('CRYPTOGRAPHIC_ATTESTATION_REJECTED')
    values = json.loads(result.stdout)
    if not values:
        raise ValueError('NO_VERIFIED_ATTESTATIONS')
    return values


def verify(directory, manifest_sha, approved_source, target=False):
    directory = Path(directory)
    manifest_path = directory/'candidate.json'
    if digest(manifest_path) != manifest_sha:
        raise ValueError('CANDIDATE_MANIFEST_CHANGED')
    manifest = strict_json(manifest_path,1024**2)
    if manifest.get('version') != 2 or manifest['sourceCommit'] != approved_source:
        raise ValueError('SIGNED_APPROVED_CANDIDATE_REQUIRED')
    provenance = directory/'provenance.sigstore.json'
    cryptographic_verify(manifest_path,provenance,approved_source)
    # This checker belongs to the reviewed operator source tree, never the candidate.
    trusted = Path(__file__).resolve().parents[3]/'tools/private-runtime/check-candidate.py'
    spec = importlib.util.spec_from_file_location('trusted_candidate_checker',trusted)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    checker.check(directory,manifest_sha,target=target)
    validate_security(directory,manifest)
    for kind in ('api','web'):
        image = directory/manifest['images'][kind]['archive']
        cryptographic_verify(image,provenance,approved_source)
        cryptographic_verify(image,directory/(kind+'-sbom.sigstore.json'),approved_source,
                             'https://cyclonedx.org/bom')
    return {'signedCandidateVerification':'passed','sourceCommit':approved_source,
            'manifestSha256':manifest_sha,'repository':REPOSITORY,'signerWorkflow':WORKFLOW,
            'githubHostedRunnerRequired':True,'unsignedFallback':False,'targetChecked':target,
            'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--manifest-sha256',required=True)
    parser.add_argument('--approved-source',required=True)
    parser.add_argument('--target',action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.directory,args.manifest_sha256,args.approved_source,args.target)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError,KeyError,AssertionError,OSError,subprocess.SubprocessError) as error:
        print('SIGNED_CANDIDATE_REJECTED: '+type(error).__name__)
        raise SystemExit(1)
