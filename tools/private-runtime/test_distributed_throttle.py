"""CI-only throwaway Redis/HTTP verification; no production endpoints or ports."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

assert os.name=='posix' and os.environ.get('GITHUB_ACTIONS')=='true','DISPOSABLE_CI_ONLY'
suffix=secrets.token_hex(6);network='aegisai-throttle-'+suffix;container=network+'-redis'
image='redis@sha256:c5d34a98396a4775e223c74e929162c35c5a2182901ba26b50ade939941ce14b'
password=secrets.token_hex(24)
created=False;started=False
try:
    subprocess.run(['docker','network','create','--internal',network],check=True,capture_output=True,timeout=15);created=True
    subprocess.run(['docker','run','-d','--name',container,'--network',network,'--network-alias','throttle-redis',
        '--log-driver','none','--user','999:999','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','64m','--cpus','0.25','--pids-limit','32',image,'redis-server','--save','','--appendonly','no',
        '--maxmemory','16mb','--maxmemory-policy','noeviction','--requirepass',password],check=True,capture_output=True,timeout=60);started=True
    for _ in range(30):
        probe=subprocess.run(['docker','exec','-e','REDISCLI_AUTH='+password,container,'redis-cli','ping'],capture_output=True,text=True,timeout=5)
        if probe.returncode==0 and probe.stdout.strip()=='PONG':break
        time.sleep(0.2)
    else:raise RuntimeError('DISPOSABLE_REDIS_NOT_READY')
    source=Path('test/private-throttle-native').resolve()
    result=subprocess.run(['docker','run','--rm','--network',network,'--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','384m','--cpus','1','--pids-limit','64',
        '-e','AEGISAI_DISPOSABLE_THROTTLE_REDIS=1','-e','REDIS_URL=redis://:'+password+'@throttle-redis:6379/15',
        '-v',str(source)+':/app/test/private-throttle-native:ro','aegisai-private-verify:ci',
        'node','--test','/app/test/private-throttle-native/shared-storage.test.mjs'],timeout=45)
    assert result.returncode==0,'DISPOSABLE_SHARED_THROTTLE_VERIFICATION_FAILED'
    print(json.dumps({'nativeSharedThrottle':'passed','realRedisImage':image,'productionNetworkUsed':False}))
finally:
    if started:subprocess.run(['docker','rm','-f',container],capture_output=True,timeout=15)
    if created:subprocess.run(['docker','network','rm',network],capture_output=True,timeout=15)
