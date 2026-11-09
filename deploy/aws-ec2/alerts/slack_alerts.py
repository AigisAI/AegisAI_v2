"""Private host alerts. Only fixed operational summaries leave the host."""
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path('/opt/aegisai/alerts')
LABELS = {'collector_down':'호스트 지표 수집 중단', 'api_down':'API 상태 확인 실패',
          'low_disk':'디스크 여유 공간 부족', 'low_memory':'메모리 여유 공간 부족',
          'observability_down':'모니터링 지표 조회 실패'}


def valid_webhook(value):
    return isinstance(value, str) and len(value) <= 256 and bool(re.fullmatch(
        r'https://hooks\.slack\.com/services/T[A-Z0-9]{6,32}/B[A-Z0-9]{6,32}/[A-Za-z0-9]{16,128}', value))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def send(value, message):
    if not valid_webhook(value):
        return False
    request = urllib.request.Request(value, data=json.dumps({'text':message}).encode(),
                                     headers={'Content-Type':'application/json'}, method='POST')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=5) as response:
            return response.status == 200 and response.read(1024).strip() == b'ok'
    except (OSError, urllib.error.URLError):
        # Exception strings can contain the secret URL. Never print or persist them.
        return False


def private_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    assert not path.is_symlink() and not temporary.is_symlink()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
    os.replace(temporary, path)


def notification_steps(states, conditions, now, deliver):
    """Two-minute sustained failure; hourly reminders; recovery only after delivery."""
    for name, failed in conditions.items():
        assert name in LABELS
        state = states.setdefault(name, {'since':None, 'delivered':False, 'last':0})
        if failed:
            if state['since'] is None:
                state['since'] = now
            if now - state['since'] >= 120 and (not state['delivered'] or now - state['last'] >= 3600):
                if deliver('[AegisAI 장애] ' + LABELS[name]):
                    state.update(delivered=True, last=now)
        else:
            if state['delivered'] and not deliver('[AegisAI 복구] ' + LABELS[name]):
                continue
            state.update(since=None, delivered=False, last=0)
    return states


def conditions():
    result = subprocess.run(['docker','inspect','--format',
        '{{(index .NetworkSettings.Networks "aegisai-observability").IPAddress}}',
        'aegisai-observability-prometheus-1'], capture_output=True, text=True, timeout=5, check=True)
    address = result.stdout.strip()
    import ipaddress
    assert ipaddress.ip_address(address) in ipaddress.ip_network('172.29.240.0/24')
    def metric(expression):
        url = 'http://' + address + ':9090/api/v1/query?' + urllib.parse.urlencode({'query':expression})
        with urllib.request.urlopen(url, timeout=3) as response:
            payload = json.loads(response.read(32768))
        assert payload['status'] == 'success'
        rows = payload['data']['result']
        return float(rows[0]['value'][1]) if rows else None
    host, api = metric('up{job="aegisai-host"}'), metric('up{job="aegisai-api"}')
    disk, memory = metric('aegisai_host_disk_free_bytes'), metric('aegisai_host_memory_available_bytes')
    return {'collector_down':host != 1, 'api_down':api != 1,
            'low_disk':disk is not None and disk < 4 * 1024**3,
            'low_memory':memory is not None and memory < 512 * 1024**2,
            'observability_down':False}


def main():
    assert os.geteuid() == 0
    os.umask(0o077)
    import fcntl
    with (ROOT/'notifier.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        secret = ROOT/'webhook.json'
        assert not secret.is_symlink() and secret.stat().st_mode & 0o077 == 0
        webhook = json.loads(secret.read_text())['webhook']
        assert valid_webhook(webhook)
        states_path = ROOT/'notification-state.json'
        states = json.loads(states_path.read_text()) if states_path.exists() else {}
        try:
            current = conditions()
        except (OSError, ValueError, AssertionError, subprocess.SubprocessError, KeyError):
            current = {'observability_down':True}
        delivered = []
        def deliver(message):
            accepted = send(webhook, message)
            if accepted:
                delivered.append(message)
            return accepted
        states = notification_steps(states, current, time.time(), deliver)
        private_json(states_path, states)
        private_json(ROOT/'last-check.json', {'checkedAt':int(time.time()), 'conditions':current,
                                             'notificationsAccepted':len(delivered)})


if __name__ == '__main__':
    main()
