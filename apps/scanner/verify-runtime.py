"""Native acceptance for the supervisor library using trusted synthetic data only."""
import importlib.util
import json
import pathlib
import subprocess
import uuid

spec = importlib.util.spec_from_file_location('aegisai_scanner_runtime', pathlib.Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
# dataclasses resolves its module through sys.modules during class creation.
import sys
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)
from normalize import normalized_findings

key = runtime.job_key('synthetic-acceptance', uuid.uuid4().hex)
storage = runtime.JobStorage(key)
root = storage.prepare()
results = {}
try:
    source = root / 'source'
    (source / 'Unsafe.java').write_text('''import javax.crypto.Cipher;
class Unsafe {
  void run() throws Exception {
    Cipher.getInstance("DES"); // nosemgrep
  }
}
''')
    (source / 'Safe.java').write_text('''import javax.crypto.Cipher;
class Safe { void run() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); } }
''')
    (source / 'pom.xml').write_text('''<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>fixture</artifactId><version>1.0</version>
<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>
<version>2.14.1</version></dependency></dependencies></project>''')
    (source / '.trivyignore').write_text('CVE-2021-44228\n')
    (source / 'trivy.yaml').write_text('severity:\n  - UNKNOWN\n')
    for file in source.iterdir(): file.chmod(0o444)
    (root / 'control/targets.json').write_text(json.dumps([
        ['CodeTarget',{'path':'/input/'+name,'analyzer':'java','products':['sast']}]
        for name in ['Unsafe.java','Safe.java']
    ]))
    (root / 'control/targets.json').chmod(0o444)
    runner = runtime.SandboxRunner(key)
    for scanner in runtime.SCANNERS:
        output = runner.run(scanner)
        assert output.exit_code == 0, scanner + ' synthetic fixture failed: ' + output.stderr.decode(errors='replace')[-3000:]
        data = json.loads(output.stdout)
        reduced = normalized_findings(output, source)
        if scanner == 'OPENGREP':
            assert not data.get('errors')
            matches = data.get('results',data.get('matches'))
            assert len(matches) == 1 and matches[0]['path'].endswith('Unsafe.java')
            assert len(reduced)==1 and reduced[0]['ruleId']=='aegisai.java.weak-des-cipher'
        elif scanner == 'TRIVY':
            vulnerabilities = [v for item in data.get('Results',[]) for v in item.get('Vulnerabilities',[])]
            assert any(v['VulnerabilityID']=='CVE-2021-44228' for v in vulnerabilities)
            assert any(item['ruleId']=='CVE-2021-44228' and item['lineStart'] is None for item in reduced)
        else:
            assert any(item['name']=='log4j-core' for item in data['artifacts'])
            assert reduced==[]
        results[scanner]={'passed':True,'durationMs':output.duration_ms}
    # Test-only trusted shell commands, never exposed by SandboxRunner.run().
    # /bin/sh is inside the fixed trusted image; no repository command or
    # executable is used. The production enum accepts only approved tools.
    database, _ = runtime.current_database()
    faults = [
        ('SCANNER_TIMEOUT','sleep 10',0.8,1024*1024),
        ('SCANNER_OUTPUT_LIMIT','while true; do echo bounded-output-fixture; done',10,4096)
    ]
    for code, command, timeout, limit in ([] if '--tools-only' in sys.argv else faults):
        try:
            runner._execute('OPENGREP','/bin/sh',['-c',command],database,
                            timeout=timeout,stdout_limit=limit)
            raise AssertionError('Expected '+code)
        except runtime.RuntimeFailure as error:
            assert str(error)==code
        listed = subprocess.check_output([runtime.CLI,'ps','-a','--format','{{.Names}}'],text=True)
        assert runtime.container_name(key,'OPENGREP') not in listed.splitlines()
        results[code]={'cleanupVerified':True}
finally:
    storage.cleanup()
assert not root.exists() and str(root) not in runtime.mounts()
report={'nativeSupervisorAcceptance':results,'tmpfsRemoved':True,'sourceProcessed':'synthetic-only',
        'inlineSuppressedFindingStillReported':True,'repositoryTrivyConfigNotAuthoritative':True,
        'customerCodeExecuted':False,'applicationIngressPromoted':False}
pathlib.Path('/opt/aegisai/scanner/supervisor-verification.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
