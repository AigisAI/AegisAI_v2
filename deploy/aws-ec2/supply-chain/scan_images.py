"""Generate actual digest-bound image vulnerability/SBOM evidence in hosted CI."""
import datetime
import json
import os
from pathlib import Path
import subprocess

from policy import digest, POLICY_ID, strict_json, validate_database, validate_report, validate_sbom, validate_image_binding

ROOT = Path('/opt/aegisai-ci-supply-chain-tools')


def scan(directory, images, source, run_id):
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    pins = json.loads(Path(__file__).with_name('toolchain.json').read_text())
    binary = ROOT/'trivy'/pins['trivy']['version']/'trivy'
    installed = json.loads(binary.with_name('verified-install.json').read_text())
    assert digest(binary) == installed['binarySha256']
    cache = Path(os.environ['RUNNER_TEMP'])/'aegisai-image-vulnerability-cache'
    cache.mkdir(mode=0o700,exist_ok=True)
    config = cache/'scan-config.yaml'
    config.write_text('{}\n')
    environment = dict(os.environ,TRIVY_CACHE_DIR=str(cache),AWS_EC2_METADATA_DISABLED='true')
    # Prevent ambient scanner options/ignore policy from changing the approved scan.
    for key in tuple(environment):
        if key.startswith('TRIVY_') and key != 'TRIVY_CACHE_DIR':
            del environment[key]
    evidence = {'policyId':POLICY_ID,'sourceCommit':source,'ciRunId':run_id,'waivers':[],
                'generatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'trivyVersion':pins['trivy']['version'],'images':{}}
    for kind in ('api','web'):
        image = images[kind]
        report_path = directory/(kind+'-vuln.json')
        sbom_path = directory/(kind+'-sbom.cdx.json')
        subprocess.run([str(binary),'image','--input',str(directory/image['archive']),
            '--config',str(config),
            '--scanners','vuln','--format','json','--list-all-pkgs','--output',str(report_path),
            '--timeout','10m','--parallel','1','--ignorefile','/dev/null','--no-progress','--exit-code','0'],
            check=True,env=environment,timeout=660,cwd=os.environ['RUNNER_TEMP'])
        report = strict_json(report_path)
        subprocess.run([str(binary),'convert','--format','cyclonedx','--output',str(sbom_path),str(report_path)],
                       check=True,env=environment,timeout=60,cwd=os.environ['RUNNER_TEMP'])
        validate_sbom(strict_json(sbom_path,16*1024**2),kind)
        validate_report(report,image,source,kind)
        validate_image_binding(report,directory/image['archive'])
        evidence['images'][kind] = {'imageId':image['id'],'archiveSha256':digest(directory/image['archive']),
            'reportSha256':digest(report_path),'sbomSha256':digest(sbom_path)}
    evidence['database'] = strict_json(cache/'db/metadata.json')
    evidence['databaseSha256'] = digest(cache/'db/trivy.db')
    validate_database(evidence['database'],datetime.datetime.now(datetime.timezone.utc))
    (directory/'security.json').write_text(json.dumps(evidence,indent=2)+'\n')
