"""One native lease-loss cleanup check, using only a trusted sleep fixture."""
import json
import time
import uuid
from runtime import JobStorage, RuntimeFailure, SandboxRunner, current_database, job_key, mounts

storage=JobStorage(job_key('synthetic-lease-loss',uuid.uuid4().hex))
root=storage.prepare()
started=time.monotonic()
try:
    runner=SandboxRunner(storage.key,cancelled=lambda:time.monotonic()-started>0.5)
    database,_=current_database()
    try:
        runner._execute('OPENGREP','/bin/sh',['-c','sleep 10'],database,timeout=15)
        raise AssertionError('Lost authority did not stop the sandbox')
    except RuntimeFailure as error: assert str(error)=='SCANNER_LEASE_LOST'
finally: storage.cleanup()
assert not root.exists() and str(root) not in mounts()
print(json.dumps({'leaseLossSandboxCleanup':'passed','tmpfsRemoved':True,'sourceProcessed':'synthetic-only'}))
