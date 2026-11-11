"""Singleton trusted host worker. No repository command, build or package execution."""
import fcntl
import json
import os
import pathlib
import re
import selectors
import signal
import subprocess
import threading
import time

from broker_client import BrokerClient
from normalize import normalized_findings
from runtime import CLI, JOBS, JobStorage, RuntimeFailure, SandboxRunner, job_key, remove_sandbox
from runtime_catalog import check_fetch_egress, local_runtime, write_catalog
from runtime_telemetry import ScanTrace

STOP = threading.Event()
CODE = '/usr/local/lib/aegisai-source-gateway/source_gateway.py'


def unit_name(key): return 'aegisai-fetch-'+key[:32]+'.service'


def stop_gateway(key):
    unit = unit_name(key)
    subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=20)
    # systemd transient units may already have been collected. Their exact
    # system.slice cgroup must be absent or unpopulated before sealing source.
    active = subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True,timeout=5)
    if active.returncode == 0:
        raise RuntimeFailure('GATEWAY_CLEANUP_UNCONFIRMED')
    group = pathlib.Path('/sys/fs/cgroup/system.slice') / unit
    if group.exists() and 'populated 1' in (group/'cgroup.events').read_text():
        raise RuntimeFailure('GATEWAY_CLEANUP_UNCONFIRMED')


def gateway_command(key):
    root = str(JOBS/key)
    properties = ['User=aegisai-fetch','Group=aegisai-fetch','SupplementaryGroups=',
        'NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=',
        'ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','PrivateDevices=yes',
        'ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectKernelLogs=yes','ProtectControlGroups=yes',
        'ProtectProc=invisible','RestrictNamespaces=yes','RestrictSUIDSGID=yes','RestrictRealtime=yes',
        'LockPersonality=yes','MemoryDenyWriteExecute=yes','RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
        'ReadWritePaths='+root,'WorkingDirectory=/','MemoryMax=512M','CPUQuota=50%','TasksMax=64',
        'RuntimeMaxSec=110','TimeoutStopSec=10','KillMode=control-group','LimitCORE=0','UMask=0077',
        'UnsetEnvironment=PYTHONPATH PYTHONHOME AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN DATABASE_URL GITHUB_APP_PRIVATE_KEY_PATH']
    command = ['systemd-run','--quiet','--pipe','--wait','--collect','--service-type=exec','--unit='+unit_name(key)]
    for value in properties: command += ['--property='+value]
    return command+['/usr/bin/python3','-E','-s','-B',CODE]


def run_gateway(key, assignment, cancelled):
    check_fetch_egress()
    process = subprocess.Popen(gateway_command(key),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout,selectors.EVENT_READ,1); selector.register(process.stderr,selectors.EVENT_READ,2)
    output = {1:bytearray(),2:bytearray()}
    started = time.monotonic()
    try:
        process.stdin.write(json.dumps(assignment).encode()); process.stdin.close()
        while selector.get_map():
            if cancelled() or time.monotonic()-started>120:
                raise RuntimeFailure('GATEWAY_CANCELED')
            for event,_ in selector.select(timeout=0.2):
                chunk = os.read(event.fileobj.fileno(),4096)
                if not chunk: selector.unregister(event.fileobj); continue
                output[event.data].extend(chunk)
                if len(output[event.data])>16384:
                    raise RuntimeFailure('GATEWAY_OUTPUT_LIMIT')
        code=process.wait(timeout=5)
        reply = json.loads(output[1])
        if isinstance(reply,dict) and reply.get('ok') is False:
            rejection={'UNSUPPORTED_SCAN_PROFILE':'UNSUPPORTED_SCAN_PROFILE','SOURCE_BLOB_LIMIT':'SOURCE_LIMIT_EXCEEDED',
                'SOURCE_SNAPSHOT_LIMIT':'SOURCE_LIMIT_EXCEEDED','UNSUPPORTED_REPOSITORY_ENTRY':'SOURCE_ENTRY_UNSUPPORTED',
                'UNSAFE_REPOSITORY_PATH':'SOURCE_ENTRY_UNSUPPORTED','DUPLICATE_REPOSITORY_PATH':'SOURCE_ENTRY_UNSUPPORTED',
                'INCOMPLETE_REPOSITORY_TREE':'SOURCE_LIMIT_EXCEEDED'}.get(reply.get('errorCode'))
            raise RuntimeFailure(rejection or 'SOURCE_FETCH_FAILED')
        if code!=0: raise RuntimeFailure('SOURCE_FETCH_FAILED')
        if not isinstance(reply,dict) or reply.get('ok') is not True or not isinstance(reply.get('data'),dict):
            raise RuntimeFailure('SOURCE_FETCH_FAILED')
        receipt = reply['data']
        lease = assignment['lease']
        if set(receipt)!= {'credentialId','tenantId','scanRequestId','commitSha','sourceBytes','javaFiles'} or \
          receipt['tenantId']!=lease['tenantId'] or receipt['scanRequestId']!=lease['scanRequestId']:
            raise RuntimeFailure('INVALID_GATEWAY_RECEIPT')
        return receipt
    finally:
        selector.close()
        stop_gateway(key)
        if process.poll() is None: process.kill(); process.wait(timeout=5)
        if not process.stdin.closed: process.stdin.close()
        process.stdout.close(); process.stderr.close()


class Heartbeat:
    def __init__(self,broker,lease):
        self.broker,self.lease = broker,lease
        self.failed,self.stopped = threading.Event(),threading.Event()
        self.thread = threading.Thread(target=self.run,daemon=True)
    def cancelled(self): return STOP.is_set() or self.failed.is_set()
    def run(self):
        while not self.stopped.wait(15):
            try:
                self.broker.request('/worker/heartbeat',{'lease':self.lease})
                write_catalog(True,busy=True)
            except Exception:
                self.failed.set(); return
    def start(self): self.thread.start()
    def close(self):
        self.stopped.set(); self.thread.join(timeout=22)
        if self.thread.is_alive(): raise RuntimeFailure('HEARTBEAT_SHUTDOWN_UNCONFIRMED')


def reconcile():
    # The independent namespace is reserved for this worker. Unknown resources
    # halt startup rather than being deleted speculatively.
    listed = subprocess.check_output([CLI,'ps','-a','--format','{{.Names}}'],timeout=15,text=True).splitlines()
    if len(listed)>100: raise RuntimeFailure('JOB_RECONCILIATION_REQUIRED')
    for name in listed:
        if not re.fullmatch(r'aegisai-scan-[a-f0-9]{32}-(opengrep|trivy|syft)',name):
            raise RuntimeFailure('JOB_RECONCILIATION_REQUIRED')
        remove_sandbox(name)
    for directory in JOBS.iterdir():
        if directory.is_symlink() or not re.fullmatch('[a-f0-9]{64}',directory.name):
            raise RuntimeFailure('JOB_RECONCILIATION_REQUIRED')
        stop_gateway(directory.name)
        JobStorage(directory.name).cleanup()


def execute(broker,assignment,telemetry,worker_span):
    lease,execution = assignment['lease'],assignment['execution']
    key = job_key(lease['tenantId'],lease['scanRequestId'])
    storage = JobStorage(key)
    heartbeat = Heartbeat(broker,lease)
    failure = None
    payload = None
    heartbeat.start()
    try:
        local = local_runtime()
        if execution['id']!=lease['scanRequestId'] or execution['tenantId']!=lease['tenantId'] or \
          execution['isolationClass']!='STANDARD' or execution['scannerSetVersion']!=local['scannerSetVersion'] or execution['policyVersion']!=local['policyVersion']:
            raise RuntimeFailure('RUNTIME_SCOPE_UNSUPPORTED')
        root = storage.prepare()
        storage.grant_gateway_writer()
        with telemetry.stage('scan.source.handoff'):
            issued = broker.request('/worker/capability',{'lease':lease})
            receipt = run_gateway(key,{'lease':lease,'capability':issued['capability']},heartbeat.cancelled)
            if receipt['credentialId']!=issued['credentialId'] or receipt['commitSha']!=execution['commitSha']:
                raise RuntimeFailure('INVALID_GATEWAY_RECEIPT')
            storage.seal()
            broker.request('/worker/start',{'lease':lease,'credentialId':receipt['credentialId']})
        runner = SandboxRunner(key,cancelled=heartbeat.cancelled,database_digest=local['vulnerabilityDatabaseDigest'])
        runs,findings = [],[]
        for scanner in ('OPENGREP','TRIVY','SYFT'):
            if heartbeat.cancelled(): raise RuntimeFailure('SCANNER_LEASE_LOST')
            started = time.monotonic()
            status = 'COMPLETED'
            try:
                with telemetry.stage('scan.tool.'+scanner.lower()):
                    output = runner.run(scanner)
                    reduced = normalized_findings(output,root/'source')
                    if len(findings)+len(reduced)>1000: raise RuntimeFailure('SCANNER_OUTPUT_LIMIT')
                    findings.extend(reduced)
                    del output
            except RuntimeFailure as error:
                if str(error) in ('SANDBOX_CLEANUP_UNCONFIRMED','SCANNER_LEASE_LOST'): raise
                status = 'TIMED_OUT' if str(error)=='SCANNER_TIMEOUT' else 'FAILED'
            runs.append({'scanner':scanner,'status':status,'durationMs':min(600000,round((time.monotonic()-started)*1000))})
        payload = {'scannerSetVersion':local['scannerSetVersion'],'vulnerabilityDatabaseDigest':local['vulnerabilityDatabaseDigest'],
                   'runs':runs,'findings':findings}
    except Exception as error:
        worker_span['failed'] = True
        failure = str(error) if isinstance(error,RuntimeFailure) and str(error) in {
            'UNSUPPORTED_SCAN_PROFILE','SOURCE_LIMIT_EXCEEDED','SOURCE_ENTRY_UNSUPPORTED','RUNTIME_SCOPE_UNSUPPORTED'} else 'UPSTREAM_UNAVAILABLE'
    finally:
        # Never publish or reschedule before both process and source destruction
        # are confirmed. A cleanup exception exits the worker and blocks new work.
        try:
            with telemetry.stage('scan.cleanup'):
                stop_gateway(key)
                storage.cleanup()
        finally:
            if payload is None or heartbeat.cancelled(): heartbeat.close()
    if not failure and not heartbeat.cancelled():
        try:
            with telemetry.stage('scan.result.publish') as publish_span:
                result = broker.request('/worker/publish',{'lease':lease,'credentialId':receipt['credentialId'],'result':payload})
                publish_span['failed'] = result['status'] != 'COMPLETED'
                worker_span['failed'] = publish_span['failed']
            print(json.dumps({'event':'SCAN_RESULT_PUBLISHED','status':result['status'],'findingCount':result['findingCount'],'ai':'DISABLED'}),flush=True)
        finally: heartbeat.close()
    elif not heartbeat.cancelled():
        try:
            with telemetry.stage('scan.result.reject'):
                if failure!='UPSTREAM_UNAVAILABLE': broker.request('/worker/reject',{'lease':lease,'reason':failure})
                else: broker.request('/worker/fail',{'lease':lease,'code':'UPSTREAM_UNAVAILABLE'})
        finally: heartbeat.close()
    else:
        worker_span['failed'] = True


def main():
    if os.geteuid()!=0: raise RuntimeFailure('PRIVILEGED_SUPERVISOR_REQUIRED')
    for name in ('SIGTERM','SIGINT'): signal.signal(getattr(signal,name),lambda *_:STOP.set())
    lock = open('/run/aegisai-scan-supervisor.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    write_catalog(False)
    reconcile()
    broker = None
    maintenance = open('/run/aegisai-scanner-maintenance.lock','a')
    try:
        while not STOP.is_set():
            try:
                fcntl.flock(maintenance,fcntl.LOCK_SH|fcntl.LOCK_NB)
            except BlockingIOError:
                write_catalog(False); STOP.wait(5); continue
            try:
                try: write_catalog(True)
                except Exception:
                    write_catalog(False); STOP.wait(10); continue
                try:
                    broker = broker or BrokerClient('control')
                    claimed_from = time.time_ns()
                    assignment = broker.request('/worker/claim',{'workerId':'private-single-host-v1'})
                except Exception:
                    # Cloud storage/database startup and transient outages do
                    # not consume scan attempts or require a manual restart.
                    broker = None
                    write_catalog(False); STOP.wait(10); continue
                if assignment:
                    telemetry = ScanTrace(assignment.get('trace'),claimed_from)
                    try:
                        with telemetry.stage('scan.worker') as worker_span:
                            execute(broker,assignment,telemetry,worker_span)
                    finally:
                        telemetry.export()
                else: STOP.wait(3)
            finally: fcntl.flock(maintenance,fcntl.LOCK_UN)
    finally: write_catalog(False)


if __name__=='__main__':
    try: main()
    except Exception:
        try: write_catalog(False)
        except Exception: pass
        print('PRIVATE_SUPERVISOR_STOPPED_UNCONFIRMED',flush=True)
        raise SystemExit(1)
