import html
import re
from http.server import HTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request

from slack_alerts import notification_steps, valid_webhook
from setup_portal import handler_for, ORIGIN, Session

FIXTURE = 'https://hooks.slack.com/services/T00000000/B00000000/' + 'X'*24


class AlertSafety(unittest.TestCase):
    def test_receiver_is_exact_https_slack_without_ssrf_redirect_or_query(self):
        self.assertTrue(valid_webhook(FIXTURE))
        for value in [FIXTURE+'?token=x', FIXTURE+'#x', FIXTURE.replace('https:', 'http:'),
                      FIXTURE.replace('hooks.slack.com','hooks.slack.com.evil.example'),
                      'https://127.0.0.1/services/T00000000/B00000000/'+'X'*24,
                      FIXTURE.replace('hooks.slack.com','user@hooks.slack.com')]:
            self.assertFalse(valid_webhook(value))

    def test_sustain_dedup_failed_delivery_retry_and_recovery(self):
        calls = []
        def accepted(message):
            calls.append(message)
            return True
        states = notification_steps({}, {'api_down':True}, 0, accepted)
        notification_steps(states, {'api_down':True}, 119, accepted)
        self.assertFalse(calls)
        notification_steps(states, {'api_down':True}, 120, lambda _:False)
        self.assertFalse(states['api_down']['delivered'])
        notification_steps(states, {'api_down':True}, 180, accepted)
        notification_steps(states, {'api_down':True}, 200, accepted)
        self.assertEqual(len(calls), 1)
        notification_steps(states, {'api_down':False}, 210, accepted)
        notification_steps(states, {'api_down':False}, 220, accepted)
        self.assertEqual(len(calls), 2)
        self.assertIn('복구', calls[-1])

    def test_portal_denies_csrf_and_secret_is_saved_only_after_slack_accepts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = Session(root)
            server = HTTPServer(('127.0.0.1',0), handler_for(session))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f'http://127.0.0.1:{server.server_port}/' + session.nonce
            def post(origin=ORIGIN, csrf=None):
                data = urllib.parse.urlencode({'csrf':csrf or session.csrf,'webhook':FIXTURE}).encode()
                request = urllib.request.Request(url,data=data,headers={'Origin':origin})
                try:
                    with urllib.request.urlopen(request,timeout=3) as response:
                        return response.status,response.read()
                except urllib.error.HTTPError as error:
                    return error.code,error.read()
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    page = response.read().decode()
                link = html.unescape(re.search('href="([^"]+)"', page).group(1))
                manifest = json.loads(urllib.parse.parse_qs(urllib.parse.urlparse(link).query)['manifest_json'][0])
                self.assertTrue(manifest['settings']['incoming_webhooks']['incoming_webhooks_enabled'])
                self.assertNotIn('features', manifest)
                with patch('setup_portal.send', return_value=False) as send:
                    self.assertEqual(post(origin='https://other.example')[0],403)
                    self.assertEqual(post(csrf='invalid')[0],400)
                    send.assert_not_called()
                    self.assertEqual(post()[0],502)
                    self.assertFalse((root/'webhook.json').exists())
                with patch('setup_portal.send', return_value=True):
                    status, body = post()
                    self.assertEqual(status,200)
                    self.assertNotIn(FIXTURE.encode(),body)
                    self.assertEqual(json.loads((root/'webhook.json').read_text())['webhook'],FIXTURE)
                    self.assertTrue(json.loads((root/'connection-proof.json').read_text())['slackTestAccepted'])
                    self.assertEqual(post()[0],409)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
