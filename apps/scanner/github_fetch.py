"""Trusted Scan Plane object fetcher; not a parser, broker or public endpoint.

The future broker supplies a single-repository upstream read token only to this
gateway. Source stays in scan-owned RAM storage; tokens never enter a sandbox.
No background consumer or repository activation is provided by this module.
"""
import base64
import hashlib
import json
import math
import os
import pathlib
import re
import time
import unicodedata
import urllib.error
import urllib.request

from runtime import RuntimeFailure, checked_root, require_tmpfs, job_key

MAX_FILES = 1000
MAX_PATH = 512
MAX_BLOB = 1024 * 1024
MAX_SOURCE = 20 * 1024 * 1024
SHA = re.compile('[a-f0-9]{40}')


class FetchFailure(RuntimeError):
    """Fixed code only; upstream bodies and credential values never escape."""
    pass


def safe_path(value):
    if not isinstance(value, str) or not value or len(value) > MAX_PATH or '\\' in value or ':' in value:
        raise FetchFailure('UNSAFE_REPOSITORY_PATH')
    if any(unicodedata.category(char) in ('Cc','Cf') for char in value):
        raise FetchFailure('UNSAFE_REPOSITORY_PATH')
    parts = value.split('/')
    if any(part in ('','.', '..') or part.casefold() == '.git' for part in parts):
        raise FetchFailure('UNSAFE_REPOSITORY_PATH')
    return parts


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class GitHubTransport:
    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, token, deadline, *, method='GET', limit=1024*1024):
        if not path.startswith('/') or '://' in path or '\r' in path or '\n' in path:
            raise FetchFailure('INVALID_PROVIDER_SCOPE')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchFailure('FETCH_TIMEOUT')
        request = urllib.request.Request('https://api.github.com' + path, method=method, headers={
            'Authorization':'Bearer ' + token, 'Accept':'application/vnd.github+json',
            'User-Agent':'AegisAI-Scan-Gateway','X-GitHub-Api-Version':'2026-03-10'})
        try:
            try:
                response = self.opener.open(request, timeout=min(10, remaining))
            except urllib.error.HTTPError as error:
                response = error
            with response:
                if method == 'DELETE' and response.status in (204,401):
                    return None  # Deleted or already unusable, without exposing body.
                if response.status != 200 or 'json' not in response.headers.get('Content-Type',''):
                    raise FetchFailure('PROVIDER_UNAVAILABLE')
                body = bytearray()
                while True:
                    if time.monotonic() >= deadline:
                        raise FetchFailure('FETCH_TIMEOUT')
                    chunk = response.read(min(65536, limit + 1 - len(body)))
                    if not chunk: break
                    body.extend(chunk)
                    if len(body) > limit:
                        raise FetchFailure('PROVIDER_RESPONSE_LIMIT')
                return json.loads(body)
        except FetchFailure:
            raise
        except Exception:
            raise FetchFailure('PROVIDER_UNAVAILABLE') from None


def object_record(value):
    if not isinstance(value, dict):
        raise FetchFailure('INVALID_PROVIDER_RESPONSE')
    return value


class GitHubObjectsFetcher:
    """A single bounded, single-use upstream session, never a worker credential."""
    def __init__(self, *, tenant_id, scan_id, repository_id, full_name, commit_sha, token, capability_expires_at, check_authority,
                 transport=None):
        try:
            self._job_key = job_key(tenant_id, scan_id)
        except RuntimeFailure:
            raise FetchFailure('INVALID_FETCH_SCOPE') from None
        if type(repository_id) is not int or repository_id <= 0 or repository_id > 2**53-1:
            raise FetchFailure('INVALID_FETCH_SCOPE')
        if not isinstance(full_name,str) or len(full_name)>201 or not re.fullmatch('[A-Za-z0-9-]+/[A-Za-z0-9_.-]+',full_name):
            raise FetchFailure('INVALID_FETCH_SCOPE')
        if not isinstance(commit_sha,str) or not SHA.fullmatch(commit_sha):
            raise FetchFailure('INVALID_FETCH_SCOPE')
        if not isinstance(token,str) or not token or len(token)>512 or '\r' in token or '\n' in token:
            raise FetchFailure('INVALID_FETCH_SCOPE')
        if not callable(check_authority):
            raise FetchFailure('INVALID_FETCH_SCOPE')
        if type(capability_expires_at) not in (int,float) or not math.isfinite(capability_expires_at):
            raise FetchFailure('INVALID_FETCH_SCOPE')
        remaining = capability_expires_at - time.time()
        if not 0 < remaining <= 600:
            raise FetchFailure('FETCH_CAPABILITY_EXPIRED')
        self.repository_id = repository_id
        self.full_name = full_name
        self.commit_sha = commit_sha
        self._token = token
        self._deadline = time.monotonic() + min(90,remaining)
        self._transport = transport or GitHubTransport()
        self._authority = check_authority
        self._used = False
        self.revocation_confirmed = False

    def _get(self, suffix, limit=1024*1024):
        if time.monotonic() >= self._deadline:
            raise FetchFailure('FETCH_TIMEOUT')
        try:
            if self._authority() is not True:
                raise FetchFailure('FETCH_AUTHORITY_LOST')
        except Exception:
            raise FetchFailure('FETCH_AUTHORITY_LOST') from None
        return object_record(self._transport.request('/repos/' + self.full_name + suffix,
            self._token, self._deadline, limit=limit))

    def _revoke(self):
        for attempt in range(3):
            try:
                self._transport.request('/installation/token', self._token, time.monotonic()+10, method='DELETE')
                self.revocation_confirmed = True
                return
            except Exception:
                if attempt < 2: time.sleep(0.25 * 2**attempt)
        raise FetchFailure('UPSTREAM_REVOCATION_UNCONFIRMED')

    def fetch(self, key):
        if self._used:
            raise FetchFailure('FETCH_CAPABILITY_CONSUMED')
        self._used = True
        try:
            root = checked_root(key)
            if key != self._job_key:
                raise FetchFailure('JOB_SCOPE_MISMATCH')
            source = root / 'source'
            control = root / 'control'
            require_tmpfs(root)
            if any(path.is_symlink() or path.resolve()!=path or not path.is_dir() for path in (source,control)):
                raise FetchFailure('INVALID_SOURCE_STORAGE')
            if any(source.iterdir()) or any(control.iterdir()):
                raise FetchFailure('SOURCE_STORAGE_NOT_EMPTY')
            repo = self._get('')
            if repo.get('id') != self.repository_id or repo.get('full_name') != self.full_name or repo.get('disabled') is True:
                raise FetchFailure('REPOSITORY_SCOPE_MISMATCH')
            if object_record(repo.get('owner')).get('id') != 241095585:
                raise FetchFailure('ORGANIZATION_NOT_ADMITTED')
            commit = self._get('/git/commits/' + self.commit_sha)
            tree_sha = object_record(commit.get('tree')).get('sha')
            if commit.get('sha') != self.commit_sha or not isinstance(tree_sha,str) or not SHA.fullmatch(tree_sha):
                raise FetchFailure('COMMIT_SCOPE_MISMATCH')
            tree = self._get('/git/trees/' + tree_sha + '?recursive=1')
            entries = tree.get('tree')
            if tree.get('sha') != tree_sha or tree.get('truncated') is not False or not isinstance(entries,list) or len(entries)>2000:
                raise FetchFailure('INCOMPLETE_REPOSITORY_TREE')
            files = []
            seen = set()
            total = 0
            for item in entries:
                entry = object_record(item)
                path = entry.get('path')
                safe_path(path)
                if path in seen:
                    raise FetchFailure('DUPLICATE_REPOSITORY_PATH')
                seen.add(path)
                if entry.get('type') == 'tree' and entry.get('mode') == '040000': continue
                if entry.get('type') != 'blob' or entry.get('mode') not in ('100644','100755'):
                    raise FetchFailure('UNSUPPORTED_REPOSITORY_ENTRY')
                size = entry.get('size')
                digest = entry.get('sha')
                if type(size) is not int or not 0<=size<=MAX_BLOB or not isinstance(digest,str) or not SHA.fullmatch(digest):
                    raise FetchFailure('SOURCE_BLOB_LIMIT')
                total += size
                files.append({'path':path,'sha':digest,'size':size})
                if len(files)>MAX_FILES or total>MAX_SOURCE:
                    raise FetchFailure('SOURCE_SNAPSHOT_LIMIT')
            java = sorted(file['path'] for file in files if file['path'].endswith('.java'))
            if not java:
                raise FetchFailure('UNSUPPORTED_SCAN_PROFILE')
            for entry in sorted(files,key=lambda file:file['path']):
                blob = self._get('/git/blobs/' + entry['sha'], limit=2*MAX_BLOB)
                encoded = blob.get('content')
                if blob.get('sha') != entry['sha'] or blob.get('size') != entry['size'] or blob.get('encoding')!='base64' or not isinstance(encoded,str):
                    raise FetchFailure('INVALID_SOURCE_BLOB')
                if len(encoded)>2*MAX_BLOB:
                    raise FetchFailure('SOURCE_BLOB_LIMIT')
                try: data = base64.b64decode(encoded.replace('\n',''),validate=True)
                except Exception: raise FetchFailure('INVALID_SOURCE_BLOB') from None
                actual = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data,usedforsecurity=False).hexdigest()
                if len(data)!=entry['size'] or actual!=entry['sha']:
                    raise FetchFailure('SOURCE_HASH_MISMATCH')
                parts = safe_path(entry['path'])
                parent = source
                for part in parts[:-1]:
                    parent = parent / part
                    parent.mkdir(mode=0o755,exist_ok=True)
                    if parent.is_symlink() or not parent.is_dir():
                        raise FetchFailure('INVALID_SOURCE_STORAGE')
                descriptor = os.open(parent / parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(descriptor,'wb') as stream: stream.write(data)
                (parent / parts[-1]).chmod(0o444)
            targets = [['CodeTarget',{'path':'/input/'+path,'analyzer':'java','products':['sast']}] for path in java]
            target_file = control / 'targets.json'
            with target_file.open('x') as stream: json.dump(targets,stream)
            target_file.chmod(0o444)
            result = {'repositoryId':self.repository_id,'commitSha':self.commit_sha,
                'files':[{'path':file['path'],'size':file['size']} for file in sorted(files,key=lambda file:file['path'])],
                'sourceBytes':total,'javaFiles':len(java)}
        except (FetchFailure,RuntimeFailure):
            raise
        except Exception:
            raise FetchFailure('SOURCE_FETCH_FAILED') from None
        finally:
            try:
                self._revoke()
            finally:
                self._token = None
        # Return metadata only, and only after confirmed revocation. The caller
        # must destroy this job's tmpfs on any exception; never parse partial data.
        if not self.revocation_confirmed:
            raise FetchFailure('UPSTREAM_REVOCATION_UNCONFIRMED')
        return result
