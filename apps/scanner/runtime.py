"""Bounded native gVisor execution. No endpoint or background consumer is enabled.

Only a trusted supervisor may call this module after validating dispatch ownership.
Repository data is never accepted through command strings or scanner configuration.
"""
from dataclasses import dataclass
import datetime
import hashlib
import json
import os
import pathlib
import re
import selectors
import shutil
import stat
import subprocess
import time

CLI = '/opt/aegisai/scanner/nerdctl'
JOBS = pathlib.Path('/run/aegisai-scan-jobs')
DATABASES = pathlib.Path('/opt/aegisai/scanner/databases')
# The reviewed loader creates this local immutable alias after verifying import.
IMAGE = 'docker.io/library/aegisai-scanner@sha256:2a9af6fa8284b6c585370234f95179a58cb48e739fd9118a6e10e01ddd395d20'
SCANNERS = ('OPENGREP', 'TRIVY', 'SYFT')


class RuntimeFailure(RuntimeError):
    """Fixed error codes only; never include source, output or credentials."""
    pass


def job_key(tenant_id, scan_id):
    if not all(isinstance(value, str) and 0 < len(value) <= 128 for value in (tenant_id, scan_id)):
        raise RuntimeFailure('INVALID_JOB_SCOPE')
    return hashlib.sha256(json.dumps([tenant_id, scan_id], separators=(',', ':')).encode()).hexdigest()


def checked_root(key):
    if not isinstance(key, str) or not re.fullmatch('[a-f0-9]{64}', key):
        raise RuntimeFailure('INVALID_JOB_SCOPE')
    root = JOBS / key
    if root.is_symlink() or (root.exists() and root.resolve() != root):
        raise RuntimeFailure('INVALID_JOB_STORAGE')
    return root


def mounts():
    result = {}
    for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1)
        fields = before.split()
        # Our root-controlled paths contain only ASCII letters/digits/slashes.
        result[fields[4]] = (after.split()[0], set(fields[5].split(',')))
    return result


def require_tmpfs(root):
    kind, flags = mounts().get(str(root), ('', set()))
    if kind != 'tmpfs' or not {'noexec', 'nosuid', 'nodev'} <= flags:
        raise RuntimeFailure('EPHEMERAL_STORAGE_REQUIRED')


def container_name(key, scanner):
    checked_root(key)
    if scanner not in SCANNERS:
        raise RuntimeFailure('SCANNER_NOT_APPROVED')
    return 'aegisai-scan-' + key[:32] + '-' + scanner.lower()


def remove_sandbox(name):
    try:
        removed = subprocess.run([CLI, 'rm', '-f', name], capture_output=True, timeout=30)
        code = removed.returncode
    except subprocess.TimeoutExpired:
        # The server-side removal may finish after the client's deadline. Only
        # a subsequent successful absence check can confirm cleanup.
        code = -1
    # A reachable daemon with no such container is the cleanup proof, even if rm
    # returned nonzero because the container had already disappeared.
    try:
        listed = subprocess.run([CLI, 'ps', '-a', '--format', '{{.Names}}'], capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise RuntimeFailure('SANDBOX_CLEANUP_UNCONFIRMED') from None
    if listed.returncode or name in listed.stdout.decode(errors='replace').splitlines():
        raise RuntimeFailure('SANDBOX_CLEANUP_UNCONFIRMED')
    return code


class JobStorage:
    def __init__(self, key):
        self.key = key
        self.root = checked_root(key)

    def prepare(self):
        JOBS.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = JOBS.stat()
        if JOBS.resolve() != JOBS or parent.st_uid != 0 or parent.st_mode & 0o022 or self.root.exists():
            raise RuntimeFailure('JOB_RECONCILIATION_REQUIRED')
        self.root.mkdir(mode=0o700)
        try:
            subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=67108864,mode=0700,noexec,nosuid,nodev',
                            'aegisai-scan', str(self.root)], check=True, capture_output=True, timeout=10)
            require_tmpfs(self.root)
            (self.root / 'source').mkdir(mode=0o755)
            (self.root / 'control').mkdir(mode=0o755)
        except Exception:
            self.cleanup()
            raise
        return self.root

    def grant_gateway_writer(self):
        """Only before fetch, for the dedicated trusted UID; never a parser UID."""
        require_tmpfs(self.root)
        if os.geteuid() != 0:
            raise RuntimeFailure('PRIVILEGED_SUPERVISOR_REQUIRED')
        parent=JOBS.stat()
        if parent.st_gid!=50001 or not parent.st_mode & 0o010:
            raise RuntimeFailure('GATEWAY_STORAGE_ADMISSION_REQUIRED')
        for name in ('source','control'):
            directory = self.root / name
            if directory.is_symlink() or any(directory.iterdir()):
                raise RuntimeFailure('SOURCE_STORAGE_NOT_EMPTY')
        for directory in (self.root,self.root/'source',self.root/'control'):
            os.chown(directory,50001,50001)
        self.root.chmod(0o700)

    def seal(self):
        """Call only after the source gateway unit has stopped and been verified."""
        require_tmpfs(self.root)
        if os.geteuid() != 0:
            raise RuntimeFailure('PRIVILEGED_SUPERVISOR_REQUIRED')
        directories=[]
        count=0
        for name in ('source','control'):
            base=self.root/name
            if base.is_symlink() or not base.is_dir():
                raise RuntimeFailure('INVALID_SOURCE_STORAGE')
            for current, children, files in os.walk(base,followlinks=False):
                directory=pathlib.Path(current)
                directories.append(directory)
                for child in children+files:
                    path=directory/child
                    info=path.lstat()
                    count+=1
                    if count>4096 or stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                        raise RuntimeFailure('INVALID_SOURCE_STORAGE')
                    if stat.S_ISREG(info.st_mode):
                        if info.st_nlink!=1:
                            raise RuntimeFailure('INVALID_SOURCE_STORAGE')
                        os.chown(path,0,0)
                        path.chmod(0o444)
        for directory in reversed(directories):
            os.chown(directory,0,0)
            directory.chmod(0o555)
        os.chown(self.root,0,0)
        self.root.chmod(0o700)

    def cleanup(self):
        root = checked_root(self.key)
        for scanner in SCANNERS:
            remove_sandbox(container_name(self.key, scanner))
        current = mounts()
        if any(path.startswith(str(root) + '/') for path in current):
            raise RuntimeFailure('UNEXPECTED_NESTED_MOUNT')
        if str(root) in current:
            require_tmpfs(root)
            result = subprocess.run(['umount', str(root)], capture_output=True, timeout=15)
            if result.returncode or str(root) in mounts():
                raise RuntimeFailure('EPHEMERAL_CLEANUP_UNCONFIRMED')
        if root.exists():
            # Exact root-controlled hash path, after confirming it is unmounted.
            shutil.rmtree(root)


def current_database():
    info = json.loads((DATABASES / 'current.json').read_text())
    digest = info.get('layerDigest', '')
    if not isinstance(digest, str) or not re.fullmatch('sha256:[a-f0-9]{64}', digest):
        raise RuntimeFailure('DATABASE_NOT_READY')
    directory = DATABASES / digest.split(':')[1]
    if directory.is_symlink() or directory.resolve() != directory:
        raise RuntimeFailure('DATABASE_NOT_READY')
    metadata = json.loads((directory / 'metadata.json').read_text())
    if metadata.get('Version') != 2 or metadata.get('UpdatedAt') != info.get('updatedAt'):
        raise RuntimeFailure('DATABASE_NOT_READY')
    updated = datetime.datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
    age = datetime.datetime.now(datetime.timezone.utc) - updated
    if not datetime.timedelta(minutes=-15) <= age <= datetime.timedelta(hours=48):
        raise RuntimeFailure('DATABASE_STALE')
    return directory, digest


@dataclass(frozen=True)
class ScannerOutput:
    scanner: str
    stdout: bytes
    stderr: bytes
    exit_code: int
    duration_ms: int


class SandboxRunner:
    def __init__(self, key, *, cancelled=None, database_digest=None):
        self.key = key
        self.root = checked_root(key)
        self.cancelled = cancelled or (lambda: False)
        self.database_digest = database_digest

    def run(self, scanner):
        require_tmpfs(self.root)
        for name in ('source', 'control'):
            directory = self.root / name
            if directory.is_symlink() or directory.resolve() != directory or not directory.is_dir():
                raise RuntimeFailure('INVALID_JOB_STORAGE')
        database, digest = current_database()
        if self.database_digest is not None and digest != self.database_digest:
            raise RuntimeFailure('SCANNER_SET_CHANGED')
        commands = {
            'OPENGREP': ('opengrep-core', ['-rules', '/opt/aegisai/rules/java-initial.yaml',
                '-targets', '/control/targets.json', '-json_nodots', '-j', '1', '-timeout', '5',
                '-timeout_threshold', '1', '-max_memory', '768', '-max_target_bytes', '1048576',
                '-max_match_per_file', '1000']),
            'TRIVY': ('trivy', ['fs', '--cache-dir', '/cache', '--scanners', 'vuln', '--offline-scan',
                '--config=', '--ignorefile=', '--secret-config=', '--ignore-policy=',
                '--skip-db-update', '--skip-java-db-update', '--skip-check-update', '--format', 'json', '/input']),
            'SYFT': ('syft', ['dir:/input', '-o', 'syft-json'])
        }
        if scanner not in commands:
            raise RuntimeFailure('SCANNER_NOT_APPROVED')
        program, args = commands[scanner]
        return self._execute(scanner, program, args, database)

    def _execute(self, scanner, program, args, database, *, timeout=120, stdout_limit=8*1024*1024, stderr_limit=1024*1024):
        """Internal executor; only fixed commands above are reachable from worker API.
        Native acceptance fixtures also exercise timeout/output-limit failure here.
        """
        name = container_name(self.key, scanner)
        remove_sandbox(name)
        command = [CLI, '--cgroup-manager', 'cgroupfs', 'run', '--name', name, '--log-driver', 'none',
            '--pull', 'never',
            '--runtime', 'io.containerd.runsc.v1', '--annotation', 'io.kubernetes.cri.container-type=sandbox',
            '--network', 'none', '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--cpus', '1',
            '--memory', '1g', '--memory-swap', '1g',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777',
            '--tmpfs', '/cache:rw,noexec,nosuid,nodev,size=67108864,mode=1777',
            '--env', 'SYFT_JAVA_USE_NETWORK=false', '--env', 'SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES=false',
            '--volume', str(self.root/'source') + ':/input:ro',
            '--volume', str(self.root/'control') + ':/control:ro',
            '--volume', str(database) + ':/cache/db:ro',
            '--entrypoint', program if program.startswith('/') else '/usr/local/bin/' + program, IMAGE, *args]
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        selector = selectors.DefaultSelector()
        outputs = {1: bytearray(), 2: bytearray()}
        selector.register(process.stdout, selectors.EVENT_READ, 1)
        selector.register(process.stderr, selectors.EVENT_READ, 2)
        failure = None
        failure_at = None
        killer = None

        def abort(code):
            nonlocal failure, failure_at, killer
            if failure is None:
                failure = RuntimeFailure(code)
                failure_at = time.monotonic()
                # Kill the actual sandbox while still draining its attachment.
                # Killing the CLI first can leave output FIFO teardown blocked.
                killer = subprocess.Popen([CLI,'kill','--signal','KILL',name],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            while selector.get_map():
                if failure is None and self.cancelled():
                    abort('SCANNER_LEASE_LOST')
                if failure is None and time.monotonic()-started > timeout:
                    abort('SCANNER_TIMEOUT')
                if failure_at is not None and time.monotonic()-failure_at > 10:
                    break
                for event, _ in selector.select(timeout=0.2):
                    chunk = os.read(event.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(event.fileobj)
                        continue
                    output = outputs[event.data]
                    if failure is None:
                        output.extend(chunk)
                        if len(output) > (stdout_limit if event.data == 1 else stderr_limit):
                            abort('SCANNER_OUTPUT_LIMIT')
                    # After abort, keep draining/discarding without retaining data.
            if failure is not None:
                raise failure
            code = process.wait(timeout=5)
            return ScannerOutput(scanner, bytes(outputs[1]), bytes(outputs[2]), code,
                                 round((time.monotonic()-started)*1000))
        finally:
            selector.close()
            if killer is not None:
                try: killer.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    killer.kill()
                    killer.wait(timeout=5)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()
            remove_sandbox(name)
