"""Local-only HTTP transport. Never follows redirects or uses TCP/proxy settings."""
import http.client
import json
import pathlib
import socket
import stat

from runtime import RuntimeFailure


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=15)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class BrokerClient:
    def __init__(self, role, *, directory='/run/aegisai-source-broker'):
        if role not in ('control', 'gateway'):
            raise RuntimeFailure('INVALID_BROKER_ROLE')
        root = pathlib.Path(directory)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 50001 or root.resolve() != root or info.st_mode & 0o027:
            raise RuntimeFailure('PRIVATE_BROKER_REQUIRED')
        self.path = root / (role+'.sock')
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != 50001 or stat.S_IMODE(info.st_mode) != (0o600 if role == 'control' else 0o660):
            raise RuntimeFailure('PRIVATE_BROKER_REQUIRED')

    def open(self, path, value):
        if path not in ('/worker/claim','/worker/capability','/worker/heartbeat','/worker/fail','/worker/reject','/worker/start','/worker/publish',
                        '/gateway/open','/gateway/check','/gateway/finish'):
            raise RuntimeFailure('INVALID_BROKER_OPERATION')
        connection = UnixConnection(self.path)
        try:
            encoded = json.dumps(value,separators=(',',':')).encode()
            if len(encoded)>1024*1024:
                raise RuntimeFailure('BROKER_REQUEST_LIMIT')
            connection.request('POST',path,body=encoded,headers={'Content-Type':'application/json','Connection':'close'})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeFailure('BROKER_AUTHORITY_LOST')
            return connection,response
        except Exception:
            connection.close()
            raise RuntimeFailure('BROKER_AUTHORITY_LOST') from None

    def request(self, path, value):
        connection,response = self.open(path,value)
        try:
            raw = response.read(65537)
            if len(raw)>65536:
                raise RuntimeFailure('BROKER_RESPONSE_LIMIT')
            reply = json.loads(raw)
            if not isinstance(reply,dict) or reply.get('ok') is not True or 'data' not in reply:
                raise RuntimeFailure('BROKER_AUTHORITY_LOST')
            return reply['data']
        except Exception:
            raise RuntimeFailure('BROKER_AUTHORITY_LOST') from None
        finally:
            response.close()
            connection.close()
