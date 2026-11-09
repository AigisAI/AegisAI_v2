"""Fail-closed policy for trusted deployment images, not customer findings."""
import datetime
import hashlib
import json
from pathlib import Path
import tarfile

POLICY_ID = 'aegisai-private-image-v1'
REPOSITORY = 'AigisAI/AegisAI_v2'
WORKFLOW = REPOSITORY + '/.github/workflows/ci.yml'
BLOCKED = {'HIGH','CRITICAL','UNKNOWN'}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024*1024):
            result.update(chunk)
    return result.hexdigest()


def strict_json(path, maximum=32*1024**2):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('INVALID_OR_MISSING_SECURITY_FILE')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('DUPLICATE_SECURITY_FIELD')
            result[key] = value
        return result
    return json.loads(path.read_text(),object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('NONFINITE_SECURITY_VALUE')))


def timestamp(value):
    result = datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.tzinfo is None:
        raise ValueError('TIMEZONE_REQUIRED')
    return result


def validate_database(database, now):
    updated, downloaded = timestamp(database['UpdatedAt']), timestamp(database['DownloadedAt'])
    for value in (updated, downloaded):
        age = (now-value).total_seconds()
        if not -300 <= age <= 48*3600:
            raise ValueError('VULNERABILITY_DATABASE_STALE')
    if database['Version'] != 2:
        raise ValueError('UNSUPPORTED_VULNERABILITY_DATABASE')


def validate_report(report, image, source, kind):
    if report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'container_image':
        raise ValueError('UNSUPPORTED_IMAGE_REPORT')
    metadata = report['Metadata']
    if metadata['OS'].get('EOSL') or metadata['OS'].get('Family') != 'alpine':
        raise ValueError('UNSUPPORTED_OR_END_OF_LIFE_OS')
    if image['tag'] not in metadata.get('RepoTags',[]):
        raise ValueError('SCANNED_IMAGE_TAG_MISMATCH')
    labels = metadata['ImageConfig']['config']['Labels']
    if labels.get('org.opencontainers.image.revision') != source:
        raise ValueError('SCANNED_IMAGE_SOURCE_MISMATCH')
    results = report.get('Results',[])
    packages = sum(len(item.get('Packages',[])) for item in results)
    if not packages or not any(item.get('Class') == 'os-pkgs' for item in results):
        raise ValueError('IMAGE_PACKAGE_COVERAGE_MISSING')
    if kind == 'api' and not any(item.get('Type') == 'node-pkg' and item.get('Packages') for item in results):
        raise ValueError('API_LANGUAGE_PACKAGE_COVERAGE_MISSING')
    blocked = []
    for item in results:
        for vulnerability in item.get('Vulnerabilities',[]):
            severity = vulnerability['Severity']
            if severity not in {'LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN'}:
                raise ValueError('UNSUPPORTED_SEVERITY')
            if severity in BLOCKED:
                blocked.append(vulnerability['VulnerabilityID'])
    if blocked:
        raise ValueError('IMAGE_VULNERABILITY_POLICY_REJECTED: '+str(len(blocked)))
    return packages


def validate_sbom(sbom,kind=None):
    if sbom.get('bomFormat') != 'CycloneDX' or not sbom.get('components'):
        raise ValueError('MISSING_OR_EMPTY_CYCLONEDX_SBOM')
    if len(sbom['components']) > 50000:
        raise ValueError('SBOM_COMPONENT_LIMIT')
    if kind == 'api' and not any(item.get('purl','').startswith('pkg:npm/') for item in sbom['components']):
        raise ValueError('API_SBOM_LANGUAGE_COMPONENTS_MISSING')


def validate_image_binding(report, archive):
    if Path(archive).stat().st_size > 1024**3:
        raise ValueError('IMAGE_ARCHIVE_LIMIT')
    with tarfile.open(archive,'r:gz') as source:
        member = source.getmember('manifest.json')
        if not member.isfile() or member.size > 65536:
            raise ValueError('INVALID_IMAGE_MANIFEST')
        entries = json.load(source.extractfile(member))
        if len(entries) != 1:
            raise ValueError('IMAGE_COUNT_MISMATCH')
        config = source.getmember(entries[0]['Config'])
        if not config.isfile() or config.size > 1024**2:
            raise ValueError('INVALID_IMAGE_CONFIG')
        expected = 'sha256:' + hashlib.sha256(source.extractfile(config).read()).hexdigest()
        if report['Metadata']['ImageID'] != expected:
            raise ValueError('VULNERABILITY_REPORT_IMAGE_CONFIG_MISMATCH')


def validate_security(directory, manifest, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    security = strict_json(Path(directory)/'security.json')
    if manifest.get('version') != 2 or security['policyId'] != POLICY_ID or security['waivers'] != []:
        raise ValueError('SIGNED_IMAGE_POLICY_REQUIRED')
    if security['trivyVersion'] != strict_json(Path(__file__).with_name('toolchain.json'))['trivy']['version']:
        raise ValueError('UNAPPROVED_IMAGE_SCANNER')
    if security['sourceCommit'] != manifest['sourceCommit'] or security['ciRunId'] != manifest['ciRunId']:
        raise ValueError('SECURITY_SOURCE_OR_RUN_MISMATCH')
    if not -300 <= (now-timestamp(security['generatedAt'])).total_seconds() <= 24*3600:
        raise ValueError('IMAGE_SCAN_EXPIRED')
    validate_database(security['database'],now)
    for kind in ('api','web'):
        image = manifest['images'][kind]
        proof = security['images'][kind]
        if proof['imageId'] != image['id'] or proof['archiveSha256'] != digest(Path(directory)/image['archive']):
            raise ValueError('SCANNED_IMAGE_DIGEST_MISMATCH')
        report_path = Path(directory)/(kind+'-vuln.json')
        sbom_path = Path(directory)/(kind+'-sbom.cdx.json')
        if digest(report_path) != proof['reportSha256'] or digest(sbom_path) != proof['sbomSha256']:
            raise ValueError('IMAGE_REPORT_OR_SBOM_CHANGED')
        report = strict_json(report_path)
        validate_report(report,image,manifest['sourceCommit'],kind)
        validate_image_binding(report,Path(directory)/image['archive'])
        validate_sbom(strict_json(sbom_path,16*1024**2),kind)
    return security
