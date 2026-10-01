"""通用小工具。"""
import secrets
import string
import struct
import hashlib


def rand_name(n=6):
    """随机标识（安全随机）。"""
    return "".join(secrets.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


def i2b(x):
    """大整数 → 最小大端字节（BN_bn2bn 语义，0 → b''）。"""
    if x == 0:
        return b""
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def be32(n):
    return struct.pack(">I", n)


# ---------------------------------------------------------------------------
# [协议保真区] CVE-2026-59309 核心常量：服务端 S = 0 经 BN_bn2bin 后为空字节串，
# 故 K = SHA1(b"") 为公开常量。此 SHA-1 是被攻击协议（Cyrus SASL SRP）的构成，
# 不是本工具自身的加密选择；替换为 SHA-256 会导致利用必然失败。
# ---------------------------------------------------------------------------
SHA1_EMPTY = hashlib.sha1(b"").digest()   # da39a3ee5e6b4b0d3255bfef95601890afd80709
