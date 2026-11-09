"""Import only the reviewed trusted image into the independent scanner daemon."""
import json
import pathlib
import subprocess

tag = 'aegisai-scanner:java-v2'
expected = 'sha256:2a9af6fa8284b6c585370234f95179a58cb48e739fd9118a6e10e01ddd395d20'
configuration = 'sha256:6c029cc298258cdda2da04d2e673b961f6b1765b0050e17d2f017c9dcff6a1f0'
platform = 'sha256:ecc43146df992bf6b31457f3486dbd112292f1ee983a8882fa7007d686fab0f5'
original = json.loads(subprocess.check_output(['docker','image','inspect',tag],text=True))[0]
assert original['Id'] == expected, 'Review a rebuilt image before replacing the approved digest'
cli = '/opt/aegisai/scanner/nerdctl'
exporter = subprocess.Popen(['docker','save',tag],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
    imported = subprocess.run([cli,'load'],stdin=exporter.stdout,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=180)
    exporter.stdout.close()
    assert exporter.wait(timeout=30) == 0 and imported.returncode == 0, 'Trusted image import failed'
finally:
    if exporter.poll() is None:
        exporter.kill()
        exporter.wait()
image = json.loads(subprocess.check_output([cli,'image','inspect',tag],text=True))[0]
assert image['Id'] in (expected, configuration, platform), 'Imported image digest differs'
alias = 'docker.io/library/aegisai-scanner@' + expected
ctr = ['ctr','--address','/run/aegisai-scan/containerd.sock','--namespace','aegisai-scans','images']
rows = subprocess.check_output(ctr + ['ls'],text=True).splitlines()
existing = [line.split() for line in rows if line.split() and line.split()[0] == alias]
if not existing:
    subprocess.run(ctr + ['tag','docker.io/library/' + tag,alias],check=True,stdout=subprocess.DEVNULL)
rows = subprocess.check_output(ctr + ['ls'],text=True).splitlines()
assert any(line.split()[0] == alias and line.split()[2] == expected for line in rows if len(line.split()) >= 3)
report = {'tag':tag,'indexDigest':expected,'configurationDigest':configuration,'dedicatedContainerdImported':True,
    'immutableAlias':alias,'customerSourceIncluded':False}
pathlib.Path('/opt/aegisai/scanner/image-verification.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
