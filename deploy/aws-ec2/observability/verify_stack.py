#!/usr/bin/env python3
"""Config/startup proof only; never a claim of application tracing acceptance."""
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path('/opt/aegisai/observability')
COMPOSE = ['docker', 'compose', '-f', str(ROOT / 'config/compose.json')]


def request(url, headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=3) as response:
            return response.status, response.read(32768)
    except urllib.error.HTTPError as error:
        return error.code, b''


def main():
    roots = {}
    for service, port in {'grafana':3000, 'loki':3100, 'prometheus':9090, 'alloy':12345, 'tempo':3200}.items():
        container_id = subprocess.check_output(COMPOSE + ['ps', '-q', service], text=True).strip()
        assert container_id, service + ' not created'
        container = json.loads(subprocess.check_output(['docker', 'inspect', container_id]))[0]
        address = container['NetworkSettings']['Networks']['aegisai-observability']['IPAddress']
        assert address, service + " has no running network endpoint"
        roots[service] = f'http://{address}:{port}'
        assert not container['HostConfig']['PortBindings'], 'Unexpected host port'
        assert container['HostConfig']['ReadonlyRootfs']
    endpoints = {'grafana':'/api/health', 'loki':'/ready', 'prometheus':'/-/ready', 'alloy':'/-/ready', 'tempo':'/ready'}
    deadline = time.monotonic() + 150
    pending = set(endpoints)
    while pending and time.monotonic() < deadline:
        for service in tuple(pending):
            try:
                if request(roots[service] + endpoints[service])[0] == 200:
                    pending.remove(service)
            except (OSError, urllib.error.URLError):
                pass
        if pending:
            time.sleep(2)
    assert not pending, 'Backends not ready: ' + ','.join(sorted(pending))
    for headers in ({}, {'X-WEBAUTH-USER':'github-161540124', 'X-WEBAUTH-ROLE':'Admin'}):
        status, _ = request(roots['grafana'] + '/api/search', headers)
        assert status in (401, 403), 'Untrusted identity admitted'
    # Readiness precedes the first 30s scrape. Poll actual observations, not time alone.
    self_scrape = host_scrape = host_logs = False
    deadline = time.monotonic() + 65
    while time.monotonic() < deadline:
        for job in ('prometheus', 'aegisai-host'):
            status, body = request(roots['prometheus'] + '/api/v1/query?' +
                urllib.parse.urlencode({'query': 'up{job="' + job + '"}'}))
            rows = json.loads(body).get('data', {}).get('result', []) if status == 200 else []
            observed = bool(rows and rows[0]['value'][1] == '1')
            if job == 'prometheus':
                self_scrape = observed
            else:
                host_scrape = observed
        status, body = request(roots['loki'] + '/loki/api/v1/query_range?' +
            urllib.parse.urlencode({'query':'{job="aegisai-host"}', 'limit':'1'}))
        rows = json.loads(body).get('data', {}).get('result', []) if status == 200 else []
        host_logs = bool(rows and rows[0]['values'])
        if self_scrape and host_scrape and host_logs:
            break
        time.sleep(2)
    assert self_scrape and host_scrape and host_logs, 'Actual metric/log collection missing'
    print(json.dumps({'backendStartup':'passed', 'directIdentitySpoof':'denied',
                      'prometheusSelfScrape':'passed', 'hostMetricAndLogCollection':'passed', 'applicationTracingVerified':False,
                      'ownerGrafanaAccessVerified':False, 'externalAlertsVerified':False}))


if __name__ == '__main__':
    main()
