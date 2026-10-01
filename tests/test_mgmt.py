# -*- coding: utf-8 -*-
"""mgmt.VCenterRest 离线桩测试（本地 HTTP 桩，覆盖 v1.5.0 新增面）。"""
import json
import threading
import http.server
import unittest

from vcstrike.mgmt import VCenterRest, MgmtError

SESSION = "sess-test"


class _Stub(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = {}

    def log_message(self, *a):
        pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n else b""

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        _Stub.seen["post:" + self.path] = self._read_body()
        if self.path == "/rest/com/vmware/cis/session":
            import base64
            ok_b64 = base64.b64encode(b"user@d.local:pw").decode()
            if self.headers.get("Authorization", "").endswith(ok_b64):
                self._json(201, {"value": SESSION})
            else:
                self._json(401, {})
        elif self.path.endswith("/power/stop"):
            if self.headers.get("vmware-api-session-id") == SESSION:
                self._json(204, {})
            else:
                self._json(401, {})
        else:
            self._json(404, {})

    def do_DELETE(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/rest/vcenter/vm":
            self._json(200, {"value": [
                {"vm": "vm-1", "name": "web01", "power_state": "POWERED_OFF",
                 "cpu_count": 2, "memory_size_MiB": 4096}]})
        elif self.path == "/rest/vcenter/vm/vm-1":
            self._json(200, {"value": {"name": "web01", "cpu_count": 2,
                                       "memory_size_MiB": None,
                                       "guest_OS": "ubuntu64Guest"}})
        elif self.path == "/rest/vcenter/vm/vm-1/snapshot":
            # 6.5/6.7 裸列表形态
            self._json(200, {"value": [
                {"name": "pre-patch", "create_time": "2026-05-01T00:00:00Z",
                 "state": "POWERED_OFF"}]})
        elif self.path == "/rest/vcenter/vm/vm-1/power":
            self._json(200, {"value": {"state": "POWERED_OFF"}})
        else:
            self._json(404, {})


class TestMgmtRest(unittest.TestCase):
    srv = None
    thread = None

    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 46446), _Stub)
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()
        _Stub.seen = {}

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _client(self):
        return VCenterRest("127.0.0.1", 46446, timeout=5, tls=False)

    def test_login_201_and_list_5tuple(self):
        c = self._client()
        c.login("user@d.local", "pw")
        self.assertEqual(c.token, SESSION)
        rows = c.vms()
        self.assertEqual(len(rows), 1)
        name, power, cpu, mem, vmid = rows[0]      # 5 元组（P0 契约）
        self.assertEqual((name, power, cpu, mem, vmid),
                         ("web01", "POWERED_OFF", "2", "4096", "vm-1"))
        c.logout()

    def test_login_401(self):
        c = self._client()
        with self.assertRaises(MgmtError) as ctx:
            c.login("user@d.local", "WRONG")
        self.assertIn("认证失败", str(ctx.exception))

    def test_vm_detail_none_filtered(self):
        c = self._client()
        c.login("user@d.local", "pw")
        d = c.vm_detail("vm-1")
        self.assertNotIn("memory_size_MiB", d)     # None 值过滤
        self.assertEqual(d["guest_OS"], "ubuntu64Guest")

    def test_snapshots_list_shape(self):
        c = self._client()
        c.login("user@d.local", "pw")
        snaps = c.vm_snapshots("vm-1")
        self.assertEqual(snaps[0][0], "pre-patch")  # 裸列表形态兼容
        c.logout()

    def test_power_stop_body_and_204(self):
        c = self._client()
        c.login("user@d.local", "pw")
        ok, detail = c.power_set("vm-1", "stop")
        self.assertTrue(ok)
        body = _Stub.seen.get("post:/rest/vcenter/vm/vm-1/power/stop", b"")
        self.assertIn(b'"action": "stop"', body)    # 6.x stop 必带 action body
        c.logout()

    def test_power_unknown_action_no_post(self):
        c = self._client()
        c.login("user@d.local", "pw")
        before = dict(_Stub.seen)
        with self.assertRaises(MgmtError):
            c.power_set("vm-1", "format")
        self.assertEqual(_Stub.seen, before)        # 未发出任何 POST
        c.logout()

    def test_logout_swallows_and_clears(self):
        c = self._client()
        c.login("user@d.local", "pw")
        c._req = lambda *a, **k: (_ for _ in ()).throw(MgmtError("net down"))
        c.logout()                                   # 不抛异常
        self.assertIsNone(c.token)


if __name__ == "__main__":
    unittest.main()
