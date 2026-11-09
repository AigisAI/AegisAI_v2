#!/usr/bin/env python3
"""Bounded host-only diagnostics. No credentials, Docker socket or customer logs."""
import json
import logging
from logging.handlers import RotatingFileHandler
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path('/opt/aegisai/observability')
LOG = logging.getLogger('host-status')
LOG.setLevel(logging.INFO)
handler = RotatingFileHandler(ROOT / 'logs/status.jsonl', maxBytes=1048576, backupCount=2)
handler.setFormatter(logging.Formatter('%(message)s'))
LOG.addHandler(handler)
LOCK = threading.Lock()
METRICS = b''


def collect():
    global METRICS
    while True:
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        available = int(memory['MemAvailable'].split()[0]) * 1024
        free = shutil.disk_usage('/').free
        protected = free < 3328 * 1024 ** 2
        if protected:
            # Never prune application images, volumes, backups or authoritative data.
            try:
                subprocess.run(['docker', 'compose', '-f', str(ROOT / 'config/compose.json'),
                                'stop', '-t', '5', 'alloy', 'tempo', 'loki'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=25, check=False)
            except subprocess.TimeoutExpired:
                LOG.error('{"service":"aegisai-host","event":"collection_stop_timeout","level":"error"}')
        with LOCK:
            METRICS = (f'aegisai_host_memory_available_bytes {available}\n'
                       f'aegisai_host_disk_free_bytes {free}\n'
                       f'aegisai_observability_disk_protection {int(protected)}\n').encode()
        LOG.info(json.dumps({'service': 'aegisai-host', 'level': 'warn' if protected else 'info',
                             'event': 'resource_status', 'memory_available_bytes': available,
                             'disk_free_bytes': free, 'collection_stopped': protected,
                             'time_unix': int(time.time())}, separators=(',', ':')))
        time.sleep(30)


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def do_GET(self):
        if self.path != '/metrics':
            self.send_error(404)
            return
        with LOCK:
            payload = METRICS
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; version=0.0.4')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


class BoundedServer(ThreadingHTTPServer):
    slots = threading.BoundedSemaphore(4)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


if __name__ == '__main__':
    threading.Thread(target=collect, daemon=True).start()
    server = BoundedServer(('172.29.240.1', 9464), Handler)
    server.daemon_threads = True
    server.serve_forever()
