"""WhatsApp ("Message yourself") delivery for wa_todo.py, against a local
HTTP server that behaves like the daemon's /self-note endpoint."""
import http.server
import os
import shutil
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import wa_todo  # noqa: E402
from test_wa_todo import Base  # noqa: E402

TOKEN = "s3cret"


class FakeSelfNote(http.server.BaseHTTPRequestHandler):
    received = []
    fail_after = None  # fail every request once this many have succeeded

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        if self.path != "/self-note" or self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_response(401); self.end_headers(); return
        if FakeSelfNote.fail_after is not None and len(FakeSelfNote.received) >= FakeSelfNote.fail_after:
            self.send_response(502); self.end_headers(); return
        FakeSelfNote.received.append(body)
        self.send_response(200); self.end_headers(); self.wfile.write(b"SENT\n")

    def log_message(self, *a):
        pass


class WhatsAppDelivery(Base):
    def setUp(self):
        super().setUp()
        FakeSelfNote.received, FakeSelfNote.fail_after = [], None
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), FakeSelfNote)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.shutdown)
        self.addCleanup(self.srv.server_close)
        self.conf = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.conf)
        with open(os.path.join(self.conf, "personal.env"), "w") as f:
            f.write("ADMIN_ADDR=127.0.0.1:%d\nWHATSAPP_SELF_NOTE_TOKEN=%s\n" % (self.srv.server_address[1], TOKEN))
        self.cfg.update(deliver="whatsapp", whatsapp_account="personal")

    def send(self):
        s, problem = wa_todo.make_sender(self.cfg, {}, self.conf)
        self.assertIsNone(problem)
        return s

    def test_digest_arrives_as_self_note(self):
        self.put("m1", "Ron bring cups")
        self.model.script = [[{"op": "add", "text": "Bring cups", "chat": "c"}]]
        self.assertEqual(wa_todo.run(self.cfg, {}, self.model, self.send()), 0)
        self.assertEqual(len(FakeSelfNote.received), 1)
        self.assertIn("NEW  t1: Bring cups", FakeSelfNote.received[0])
        self.assertTrue(FakeSelfNote.received[0].startswith("WhatsApp to-dos"))

    def test_failure_keeps_changes_for_next_run(self):
        self.put("m1", "Ron bring cups")
        self.model.script = [[{"op": "add", "text": "Bring cups", "chat": "c"}]]
        FakeSelfNote.fail_after = 0
        self.assertEqual(wa_todo.run(self.cfg, {}, self.model, self.send()), 1)
        FakeSelfNote.fail_after = None
        wa_todo.run(self.cfg, {}, self.model, self.send())
        self.assertEqual(len(self.model.prompts), 1, "retry must not re-run the model")
        self.assertIn("Bring cups", FakeSelfNote.received[-1])

    def test_wrong_token_is_a_failure(self):
        with open(os.path.join(self.conf, "personal.env"), "w") as f:
            f.write("ADMIN_ADDR=127.0.0.1:%d\nWHATSAPP_SELF_NOTE_TOKEN=wrong\n" % self.srv.server_address[1])
        self.put("m1", "x")
        self.model.script = [[{"op": "add", "text": "T", "chat": "c"}]]
        self.assertEqual(wa_todo.run(self.cfg, {}, self.model, self.send()), 1)
        self.assertEqual(FakeSelfNote.received, [])

    def test_long_digest_is_split_in_order(self):
        for i in range(60):
            self.put("m%d" % i, "task %d" % i, days_ago=1 - i * 0.001)
        self.model.script = [[{"op": "add", "text": ("Long task number %d " % i) * 6, "chat": "c"} for i in range(60)]]
        wa_todo.run(self.cfg, {}, self.model, self.send())
        n = len(FakeSelfNote.received)
        self.assertGreater(n, 1)
        for i, part in enumerate(FakeSelfNote.received, 1):
            self.assertTrue(part.startswith("(%d/%d) " % (i, n)), part[:20])
            self.assertLessEqual(len(part), wa_todo.WA_PART_LIMIT + 10)

    def test_not_configured_reports_problem(self):
        os.remove(os.path.join(self.conf, "personal.env"))
        s, problem = wa_todo.make_sender(self.cfg, {}, self.conf)
        self.assertIsNone(s)
        self.assertIn("personal.env", problem)


class Split(unittest.TestCase):
    def test_split(self):
        self.assertEqual(wa_todo.split_message("a\nb", 10), ["a\nb"])
        parts = wa_todo.split_message("x" * 25, 10)
        self.assertEqual(parts, ["x" * 10, "x" * 10, "x" * 5])
        parts = wa_todo.split_message("aaaa\nbbbb\ncccc\n", 10)
        self.assertEqual(parts, ["aaaa\nbbbb", "cccc"])


if __name__ == "__main__":
    unittest.main()
