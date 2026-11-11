"""Bounded OTLP spans from the trusted supervisor process."""
from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
import re
import secrets
import time


STAGES = frozenset((
    'scan.queue.wait', 'scan.broker.claim', 'scan.worker', 'scan.source.handoff',
    'scan.tool.opengrep', 'scan.tool.trivy', 'scan.tool.syft', 'scan.cleanup',
    'scan.result.publish', 'scan.result.reject',
))


class ScanTrace:
    def __init__(self, carrier, claimed_from):
        self.spans = []
        self.trace_id = self.parent_id = self.collector = None
        if not isinstance(carrier, dict):
            return
        try:
            ip = ipaddress.IPv4Address(os.environ.get('AEGISAI_TRACE_COLLECTOR', ''))
            if ip not in ipaddress.IPv4Network('172.29.240.128/25'):
                return
            trace_id = carrier.get('traceId', '')
            parent_id = carrier.get('parentSpanId', '')
            if not re.fullmatch('[a-f0-9]{32}', trace_id) or not int(trace_id, 16):
                return
            if not re.fullmatch('[a-f0-9]{16}', parent_id) or not int(parent_id, 16):
                return
            queued = datetime.fromisoformat(carrier['queuedAt'].replace('Z', '+00:00'))
            if queued.tzinfo is None:
                return
            ended = time.time_ns()
            queued_ns = int(queued.astimezone(timezone.utc).timestamp() * 1e9)
            if not 0 < queued_ns <= ended:
                return
            self.collector, self.trace_id, self.parent_id = str(ip), trace_id, parent_id
            self._append('scan.queue.wait', secrets.token_hex(8), parent_id, queued_ns, ended, False)
            claim_id = secrets.token_hex(8)
            self._append('scan.broker.claim', claim_id, parent_id, claimed_from, ended, False)
            self.parent_id = claim_id
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            return

    def _append(self, name, span_id, parent, start, end, failed):
        if name in STAGES and len(self.spans) < 16:
            self.spans.append({'name': name, 'kind': 1, 'traceId': self.trace_id, 'spanId': span_id,
                'parentSpanId': parent, 'startTimeUnixNano': str(start), 'endTimeUnixNano': str(max(start, end)),
                'status': {'code': 2 if failed else 1}})

    @contextmanager
    def stage(self, name):
        status = {'failed': False}
        if not self.collector:
            yield status
            return
        start = time.time_ns()
        parent, span_id = self.parent_id, secrets.token_hex(8)
        self.parent_id = span_id
        try:
            yield status
        except BaseException:
            status['failed'] = True
            raise
        finally:
            self.parent_id = parent
            self._append(name, span_id, parent, start, time.time_ns(), status['failed'])

    def export(self):
        if not self.collector or not self.spans:
            return
        body = json.dumps({'resourceSpans': [{'resource': {'attributes': [
            {'key': 'service.name', 'value': {'stringValue': 'aegisai-scan-supervisor'}},
            {'key': 'deployment.environment.name', 'value': {'stringValue': 'private-ec2'}},
        ]}, 'scopeSpans': [{'scope': {'name': 'aegisai-private-scan'}, 'spans': self.spans}]}]}).encode()
        connection = http.client.HTTPConnection(self.collector, 4318, timeout=0.75)
        try:
            connection.request('POST', '/v1/traces', body, {'Content-Type': 'application/json'})
            connection.getresponse()
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
