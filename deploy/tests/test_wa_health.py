"""Tests for wa_health.py."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import wa_health  # noqa: E402

MAIL = {"SMTP_USER": "r@x.com", "SMTP_PASS": "pw", "MAIL_TO": "r@x.com"}


class TestHealth(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        for name, port in (("personal", 8865), ("second", 8866)):
            with open(os.path.join(self.dir, name + ".env"), "w") as f:
                f.write("MCP_ADDR=127.0.0.1:%d\nADMIN_ADDR=127.0.0.1:%d\n" % (port - 100, port))
        with open(os.path.join(self.dir, "mail.env"), "w") as f:
            f.write("SMTP_USER=x\n")
        self.state = os.path.join(self.dir, "health.json")
        self.up = {"127.0.0.1:8865": True, "127.0.0.1:8866": True}
        self.tunnel = True
        self.mails = []
        self.mail_fails = False

    def http(self, url):
        if "hc-ping" in url:
            self.mails.append(("PING", url))
            return True
        return self.up[url.split("/")[2]]

    def send(self, subject, body, ok):
        if self.mail_fails:
            raise ConnectionError("smtp down")
        self.mails.append((subject, body))

    def run_once(self, env=MAIL):
        return wa_health.run(self.dir, self.state, self.http, lambda n: self.tunnel, self.send, dict(env))

    def test_discovers_accounts_from_env_files(self):
        self.assertEqual(wa_health.discover(self.dir), {"personal": "127.0.0.1:8865", "second": "127.0.0.1:8866"})

    def test_alerts_only_on_change(self):
        self.run_once()
        self.assertEqual(self.mails, [])
        self.up["127.0.0.1:8866"] = False
        self.run_once()
        self.run_once()
        self.assertEqual(len(self.mails), 1)
        self.assertIn("whatsapp second: DOWN", self.mails[0][0])
        self.up["127.0.0.1:8866"] = True
        self.run_once()
        self.assertIn("back up", self.mails[1][0])

    def test_tunnel_down_alerts(self):
        self.run_once()
        self.tunnel = False
        self.run_once()
        self.assertIn("cloudflared", self.mails[0][0])

    def test_failed_alert_is_retried(self):
        self.run_once()
        self.up["127.0.0.1:8865"] = False
        self.mail_fails = True
        self.run_once()
        self.mail_fails = False
        self.run_once()
        self.assertEqual(len(self.mails), 1)
        self.assertIn("personal: DOWN", self.mails[0][0])

    def test_unconfigured_mail_does_not_swallow_alert(self):
        self.run_once(env={})
        self.up["127.0.0.1:8865"] = False
        self.run_once(env={})
        self.run_once()
        self.assertEqual(len(self.mails), 1)

    def test_heartbeat_only_when_all_healthy(self):
        env = dict(MAIL, HEARTBEAT_URL="https://hc-ping.com/abc")
        self.run_once(env)
        self.assertIn(("PING", "https://hc-ping.com/abc"), self.mails)
        self.mails.clear()
        self.up["127.0.0.1:8865"] = False
        self.run_once(env)
        self.assertNotIn(("PING", "https://hc-ping.com/abc"), self.mails)


if __name__ == "__main__":
    unittest.main()
