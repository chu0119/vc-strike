"""极简 BER / LDAP 客户端（CVE-2026-59309 所需子集）。

支持：匿名/SASL bind、Search、Add、Modify、Delete、Unbind；
可选 SASL 安全层由外部注入（self.layer 需实现 wrap/unwrap，见 srp59309.SRPLayer），
通过 duck-typing 解耦，避免模块循环依赖。
"""
import re
import socket
import ssl


# ---------------- BER 编码 ----------------

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + ber_len(len(content)) + content


def _int_content(v):
    if v == 0:
        return b"\x00"
    b = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def ber_int(v):
    return tlv(0x02, _int_content(v))


def ber_enum(v):
    return tlv(0x0A, _int_content(v))


def ber_str(b):
    return tlv(0x04, b)


def ber_bool(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def ber_seq(*parts):
    return tlv(0x30, b"".join(parts))


def ber_parse_tlv(data, off=0):
    """返回 (tag, value, next_off)。"""
    tag = data[off]
    off += 1
    l = data[off]
    off += 1
    if l & 0x80:
        nb = l & 0x7F
        if nb == 0:
            raise ValueError("indefinite BER length not supported")
        l = int.from_bytes(data[off:off + nb], "big")
        off += nb
    val = data[off:off + l]
    if len(val) < l:
        raise ValueError("truncated BER")
    return tag, val, off + l


def ber_children(data):
    """解析 constructed 值内部的子 TLV 列表。"""
    out = []
    off = 0
    while off < len(data):
        tag, val, off = ber_parse_tlv(data, off)
        out.append((tag, val))
    return out


# ---------------- 连接与消息 IO ----------------

class LDAPConn:
    """LDAP 连接：SASL SRP bind + 查询/增改删，支持可选安全层。"""

    def __init__(self, sock):
        self.sock = sock
        self.layer = None      # SRPLayer 或 None（明文）
        self.msgid = 0

    def _readn(self, n):
        buf = b""
        while len(buf) < n:
            d = self.sock.recv(n - len(buf))
            if not d:
                raise ConnectionError("连接被对端关闭")
            buf += d
        return buf

    def _read_tlv(self):
        tag = self._readn(1)[0]
        l1 = self._readn(1)[0]
        if l1 & 0x80:
            nb = l1 & 0x7F
            if nb == 0:
                raise ValueError("LDAP 响应含不定长(0x80)编码，无法解析")
            ln = int.from_bytes(self._readn(nb), "big")
        else:
            ln = l1
        if tag != 0x30:
            raise ValueError("LDAP 帧顶层 tag=0x%02x（预期 0x30 SEQUENCE）" % tag)
        return tag, self._readn(ln)

    def send_op(self, op_bytes):
        self.msgid += 1
        pdu = tlv(0x30, ber_int(self.msgid) + op_bytes)
        if self.layer:
            self.sock.sendall(self.layer.wrap(pdu))
        else:
            self.sock.sendall(pdu)
        return self.msgid

    def recv_op(self):
        """返回 (msgid, tag, value)。"""
        if self.layer:
            n = int.from_bytes(self._readn(4), "big")
            if n > 16 * 1024 * 1024:
                raise ValueError("安全层帧长 %d 超过 16MB 上限" % n)
            pdu = self.layer.unwrap(self._readn(n))
        else:
            _tag, pdu = self._read_tlv()   # 顶层 SEQUENCE，pdu 为其内容
        t_id, v_id, off = ber_parse_tlv(pdu, 0)
        t_op, v_op, _ = ber_parse_tlv(pdu, off)
        return int.from_bytes(v_id, "big"), t_op, v_op

    def close(self):
        try:
            self.send_op(tlv(0x42, b""))  # UnbindRequest
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def connect_ldap(host, port, use_tls=False, timeout=8):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    if use_tls:
        # vCenter 出厂自签证书，测试工具按惯例不校验（见仓库 README 安全说明）
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return LDAPConn(s)


# ---------------- LDAP 操作构造与解析 ----------------

def op_bind_simple(dn=b"", pw=b""):
    return tlv(0x60, ber_int(3) + ber_str(dn) + tlv(0x80, pw))


def op_bind_sasl(mech=b"SRP", creds=None):
    body = ber_str(mech)
    if creds is not None:
        body += ber_str(creds)
    return tlv(0x60, ber_int(3) + ber_str(b"") + tlv(0xA3, body))


def parse_bind_response(val):
    """返回 (resultCode, diag, serverSaslCreds)。

    LDAPResult 字段序固定：resultCode(ENUM), matchedDN(OCTET),
    errorMessage(OCTET), [serverSaslCreds(0x87)] —— matchedDN 不能当诊断文本。
    """
    code, diag, creds = None, b"", None
    for i, (tag, v) in enumerate(ber_children(val)):
        if tag == 0x0A and code is None:
            code = int.from_bytes(v, "big")
        elif tag == 0x87:
            creds = v
        elif tag == 0x04 and i != 1:      # 跳过 matchedDN（第 2 个子项）
            diag = v
    return code, diag, creds


def parse_ldap_result(val):
    code, diag = None, b""
    for i, (tag, v) in enumerate(ber_children(val)):
        if tag == 0x0A and code is None:
            code = int.from_bytes(v, "big")
        elif tag == 0x04 and i != 1:      # 跳过 matchedDN
            diag = v
    return code, diag


def op_search(base, scope=2, ffilter="(objectClass=*)", attrs=None):
    if ffilter in ("(objectClass=*)", "", None):
        f = tlv(0x87, b"objectClass")
    else:
        m = re.fullmatch(r"\(([^=()]+)=([^*)]+)\)", ffilter.strip())
        if not m:
            raise ValueError("仅支持 (attr=value) 形式的过滤器")
        f = tlv(0xA3, ber_str(m.group(1).encode()) + ber_str(m.group(2).encode()))
    attrlist = b"".join(ber_str(a.encode()) for a in (attrs or []))
    body = (ber_str(base.encode()) + ber_int(scope) + ber_int(0) +
            ber_int(0) + ber_int(0) + ber_bool(False) + f + ber_seq(attrlist))
    return tlv(0x63, body)


def op_add(dn, attrs):
    """attrs: [(type, [vals])]"""
    lst = b"".join(tlv(0x30, ber_str(t.encode()) +
                       tlv(0x31, b"".join(ber_str(v.encode()) for v in vs)))
                   for t, vs in attrs)
    return tlv(0x68, ber_str(dn.encode()) + tlv(0x30, lst))


def op_modify(dn, changes):
    """changes: [(op(0=add,1=delete,2=replace), type, [vals])]"""
    lst = b""
    for o, t, vs in changes:
        lst += tlv(0x30, ber_enum(o) +
                   tlv(0x30, ber_str(t.encode()) +
                       tlv(0x31, b"".join(ber_str(v.encode()) for v in vs))))
    return tlv(0x66, ber_str(dn.encode()) + tlv(0x30, lst))


def op_delete(dn):
    return tlv(0x4A, dn.encode())


def collect_search(conn):
    """循环收 SearchResultEntry 直到 Done。返回 (entries, doneCode)。"""
    entries = []
    while True:
        _, tag, val = conn.recv_op()
        if tag == 0x64:
            kids = ber_children(val)
            dn = kids[0][1].decode("utf-8", "replace") if kids else ""
            attributes = {}
            if len(kids) > 1:
                for _t, av in ber_children(kids[1][1]):
                    parts = ber_children(av)
                    if len(parts) != 2:
                        continue
                    name = parts[0][1].decode("utf-8", "replace")
                    vals = [v.decode("utf-8", "replace")
                            for _vt, v in ber_children(parts[1][1])]
                    attributes.setdefault(name, []).extend(vals)
            entries.append((dn, attributes))
        elif tag == 0x65:
            code, _ = parse_ldap_result(val)
            return entries, code
        # 其余（searchResRef 等）忽略


def has_srp(mechs):
    """判断 SASL 机制列表是否含 SRP。

    vmdird 的 rootDSE 可能把机制作为单个含空格的值返回（如 "GSSAPI SRP"），
    按列表元素 `in` 判断会漏判 —— 统一用子串判断。
    """
    return any("SRP" in str(m).upper() for m in (mechs or []))


def root_dse_probe(host, port, use_tls=False, timeout=8):
    """匿名读取 rootDSE：supportedSASLMechanisms / namingContexts。"""
    conn = connect_ldap(host, port, use_tls, timeout)
    try:
        conn.send_op(op_bind_simple())
        conn.recv_op()
        conn.send_op(op_search("", scope=0, ffilter="(objectClass=*)",
                               attrs=["supportedSASLMechanisms", "namingContexts"]))
        entries, _ = collect_search(conn)
        mechs, ncs = [], []
        for _dn, at in entries:
            mechs += at.get("supportedSASLMechanisms", [])
            ncs += at.get("namingContexts", [])
        return {"mechs": mechs, "namingContexts": ncs}
    finally:
        try:
            conn.close()
        except Exception:
            pass
