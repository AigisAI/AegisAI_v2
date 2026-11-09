"""Synthetic sources only. Never builds, installs or executes repository code."""
import json
import datetime
import pathlib
import shutil
import subprocess
import tempfile
import uuid

CLI = '/opt/aegisai/scanner/nerdctl'
IMAGE = 'aegisai-scanner:java-v2'
root = pathlib.Path(tempfile.mkdtemp(prefix='aegisai-tools-verify-', dir='/opt/aegisai/scanner'))
root.chmod(0o755)
source = root / 'input'
source.mkdir(mode=0o755)
files = {
    'Unsafe.java': '''import javax.crypto.Cipher;
class Unsafe {
  void run(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
    String cmd = request.getParameter("cmd");
    Runtime.getRuntime().exec(cmd);
    String query = request.getParameter("query");
    stmt.executeQuery(query);
    Cipher.getInstance("DES");
  }
}
''',
    'Safe.java': '''import javax.crypto.Cipher;
class Safe {
  void run(java.sql.Statement stmt) throws Exception {
    stmt.executeQuery("SELECT 1");
    Cipher.getInstance("AES/GCM/NoPadding");
  }
}
''',
    'pom.xml': '''<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion><groupId>example.fixture</groupId>
<artifactId>synthetic-only</artifactId><version>1.0.0</version>
<dependencies><dependency><groupId>org.apache.logging.log4j</groupId>
<artifactId>log4j-core</artifactId><version>2.14.1</version>
</dependency></dependencies></project>'''
}
files['.trivyignore'] = 'CVE-2021-44228\n'
files['trivy.yaml'] = 'severity:\n  - UNKNOWN\n'
# Core protocol pinned by opengrep v1.33.1's semgrep-interfaces submodule:
# https://github.com/opengrep/semgrep-interfaces/blob/5e705660dc7381d4c4c247fa83c4c5860e61d555/semgrep_output_v1.atd
files['targets.json'] = json.dumps([
    ['CodeTarget', {'path':'/input/' + name, 'analyzer':'java', 'products':['sast']}]
    for name in ['Unsafe.java','Safe.java']
])
for name, content in files.items():
    target = source / name
    target.write_text(content)
    target.chmod(0o644)

def run(tool, args, accepted=(0,), database=None):
    name = 'aegisai-tool-verify-' + uuid.uuid4().hex
    try:
        result = subprocess.run([
            CLI, '--cgroup-manager', 'cgroupfs', 'run', '--name', name, '--log-driver', 'none',
            '--runtime', 'io.containerd.runsc.v1',
            '--annotation', 'io.kubernetes.cri.container-type=sandbox',
            '--network', 'none', '--user', '65532:65532', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '256', '--cpus', '1', '--memory', '1g', '--memory-swap', '1g',
            '--env', 'SYFT_JAVA_USE_NETWORK=false', '--env', 'SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=false',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777',
            '--volume', str(source) + ':/input:ro', '--entrypoint', '/usr/local/bin/' + tool,
            '--workdir', '/input' if tool == 'trivy' else '/tmp',
            *(['--tmpfs', '/cache:rw,noexec,nosuid,nodev,size=67108864,mode=1777',
               '--volume', str(database) + ':/cache/db:ro'] if database else []),
            IMAGE, *args
        ], capture_output=True, timeout=180)
        assert len(result.stdout) < 2 * 1024 * 1024 and len(result.stderr) < 1024 * 1024
        if result.returncode not in accepted:
            raise RuntimeError(tool + ' synthetic verification failed: ' + result.stderr.decode(errors='replace')[-4000:])
        return result
    finally:
        subprocess.run([CLI, 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)

try:
    result = run('opengrep-core', ['-rules', '/opt/aegisai/rules/java-initial.yaml',
        '-targets', '/input/targets.json', '-json_nodots', '-j', '1', '-timeout', '10', '-max_memory', '768',
        '-max_target_bytes', '1048576'])
    analysis = json.loads(result.stdout)
    assert not analysis.get('errors'), 'Synthetic Java analysis must have no parser errors'
    findings = analysis['results'] if 'results' in analysis else analysis['matches']
    expected = {'aegisai.java.request-to-process','aegisai.java.request-to-statement','aegisai.java.weak-des-cipher'}
    assert len(findings) == 3 and all(item['path'].endswith('Unsafe.java') for item in findings)
    assert all(any(item['check_id'].endswith(rule) for item in findings) for rule in expected)
    sbom = json.loads(run('syft', ['dir:/input', '-o', 'syft-json']).stdout)
    packages = sbom['artifacts']
    assert any(item['name'] == 'log4j-core' and item['version'] == '2.14.1' for item in packages)
    # A cold, offline vulnerability database must fail visibly, never report clean.
    cold = run('trivy', ['fs', '--scanners', 'vuln', '--offline-scan', '--skip-db-update',
        '--config=', '--ignorefile=', '--secret-config=', '--ignore-policy=',
        '--skip-java-db-update', '--format', 'json', '/input'], accepted=(1,))
    assert b'database' in cold.stderr.lower() or b'db' in cold.stderr.lower()
    db_info = json.loads(pathlib.Path('/opt/aegisai/scanner/databases/current.json').read_text())
    database = pathlib.Path(db_info['databasePath'])
    assert database.parent == pathlib.Path('/opt/aegisai/scanner/databases')
    assert database.name == db_info['layerDigest'].split(':')[1]
    updated = datetime.datetime.fromisoformat(db_info['updatedAt'].replace('Z','+00:00'))
    assert datetime.timedelta(minutes=-15) <= datetime.datetime.now(datetime.timezone.utc)-updated <= datetime.timedelta(hours=48)
    sca = json.loads(run('trivy', ['fs', '--cache-dir', '/cache', '--scanners', 'vuln',
        '--config=', '--ignorefile=', '--secret-config=', '--ignore-policy=',
        '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--skip-check-update',
        '--format', 'json', '/input'], database=database).stdout)
    vulnerabilities = [item for result in sca.get('Results',[]) for item in result.get('Vulnerabilities',[])]
    assert any(item['VulnerabilityID'] == 'CVE-2021-44228' and 'log4j-core' in item['PkgName'] for item in vulnerabilities), 'Known vulnerable declared dependency must be detected offline'
    report = {'syntheticOnly':True,'runtime':'gVisor','network':'none',
        'opengrep':{'positiveFindings':3,'safeFileFindings':0,'parserErrors':0},
        'syft':{'declaredJavaDependencyDetected':True},
        'trivy':{'missingOfflineDatabase':'explicit-failure','knownFixtureCveDetected':'CVE-2021-44228',
            'offlineDatabaseReady':True,'coverage':'declared direct Maven dependency fixture only','databaseDigest':db_info['layerDigest']},
        'customerCodeExecuted':False,'customerPackagesInstalled':False}
    pathlib.Path('/opt/aegisai/scanner/tool-verification.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
finally:
    # Exact directory created by this process; no user-controlled path is accepted.
    assert root.parent == pathlib.Path('/opt/aegisai/scanner') and root.name.startswith('aegisai-tools-verify-')
    shutil.rmtree(root)
