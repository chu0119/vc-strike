"""纯 Python AES-128（仅加密；OFB 模式加解同构）。

[协议保真] SRP 安全层的保密算法固定为 aes-128-ofb（cyrus-sasl srp.c
cipher_options 表），密钥取 K 前 16 字节 —— 与服务端 OpenSSL EVP 行为一致，
不可替换。S-box 按 Rijndael 生成算法计算（见 _gen_sbox），并由
FIPS-197 测试向量在 selftest/tests 中验证。
"""


def _rotl8(x, s):
    return ((x << s) | (x >> (8 - s))) & 0xFF


def _gen_sbox():
    sb = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sb[p] = x ^ 0x63
        if p == 1:
            break
    sb[0] = 0x63
    return sb


SBOX = _gen_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
    return r & 0xFF


def _aes128_expand(key):
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    rks = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk += w[r * 4 + c]
        rks.append(rk)
    return rks


def aes128_encrypt_block(blk, rks):
    """blk: 16 bytes（列主序同 FIPS-197 输入布局）。返回 16 bytes。"""
    s = [blk[i] ^ rks[0][i] for i in range(16)]
    for rnd in range(1, 10):
        s = [SBOX[b] for b in s]                       # SubBytes
        ns = [0] * 16                                  # ShiftRows
        for r in range(4):
            for c in range(4):
                ns[c * 4 + r] = s[((c + r) % 4) * 4 + r]
        s = ns
        for c in range(4):                             # MixColumns
            a0, a1, a2, a3 = s[c * 4:c * 4 + 4]
            s[c * 4 + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
            s[c * 4 + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
            s[c * 4 + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
            s[c * 4 + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
        s = [s[i] ^ rks[rnd][i] for i in range(16)]    # AddRoundKey
    s = [SBOX[b] for b in s]
    ns = [0] * 16
    for r in range(4):
        for c in range(4):
            ns[c * 4 + r] = s[((c + r) % 4) * 4 + r]
    s = [ns[i] ^ rks[10][i] for i in range(16)]
    return bytes(s)


class AES128OFB:
    """AES-128-OFB 流（OpenSSL EVP_aes_128_ofb 兼容：密钥取 K 前 16 字节）。"""

    def __init__(self, key16, iv16):
        assert len(key16) == 16 and len(iv16) == 16
        self._rk = _aes128_expand(key16)
        self._reg = bytes(iv16)
        self._ks = b""
        self._pos = 16

    def crypt(self, data):
        out = bytearray()
        for b in data:
            if self._pos >= 16:
                self._ks = aes128_encrypt_block(self._reg, self._rk)
                self._reg = self._ks
                self._pos = 0
            out.append(b ^ self._ks[self._pos])
            self._pos += 1
        return bytes(out)

    encrypt = crypt
    decrypt = crypt
