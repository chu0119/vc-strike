"""目标指纹与批量探测（仅探测，不利用）。"""
import re
import socket

import urllib.request
import urllib.error

from .berldap import root_dse_probe


def tcp_open(host, port, timeout=4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def http_get(host, port, path, timeout=8, proxy=None, tls_on=True):
    scheme = "https" if tls_on else "http"
    url = "%s://%s:%d%s" % (scheme, host, port, path)
    import ssl
    ctx = ssl._create_unverified_context()   # vCenter 自签证书，见 README 安全说明
    handlers = [urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {})]
    hs = [urllib.request.HTTPSHandler(context=ctx)] if tls_on else []
    opener = urllib.request.build_opener(*handlers, *hs)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (VC-Strike)"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, b""
    except Exception as e:
        return None, str(e).encode()


def api_version(host, proxy=None):
    """/sdk/vimServiceVersions.xml → API 命名空间版本（非 build，仅指纹参考）。"""
    st, body = http_get(host, 443, "/sdk/vimServiceVersions.xml", proxy=proxy)
    if st != 200:
        return None
    m = re.search(rb"<namespace>.*?<version>([^<]+)</version>", body, re.S)
    return m.group(1).decode() if m else "?"


def probe_target(host, proxy=None, timeout=6, log=lambda s: None):
    """单目标指纹：端口面 + API 版本 + rootDSE SASL 机制。"""
    res = {"host": host}
    for p in ("443", "5480", "514tcp", "1514", "389", "636", "2020"):
        res[p] = False
    res["443"] = tcp_open(host, 443, timeout)
    res["5480"] = tcp_open(host, 5480, timeout)
    res["514tcp"] = tcp_open(host, 514, timeout)
    res["1514"] = tcp_open(host, 1514, timeout)
    res["389"] = tcp_open(host, 389, timeout)
    res["636"] = tcp_open(host, 636, timeout)
    res["2020"] = tcp_open(host, 2020, timeout)
    res["api"] = api_version(host, proxy) if res["443"] else None
    res["mechs"] = res["nc"] = None
    for port, tls_on in ((389, False), (636, True), (2020, False)):
        if res.get(str(port)):
            try:
                dse = root_dse_probe(host, port, tls_on, timeout)
                res["mechs"] = ",".join(dse["mechs"])
                res["nc"] = ";".join(dse["namingContexts"])
                res["dse_port"] = port
                break
            except Exception as e:
                log("[!] %s:%d rootDSE 失败: %s" % (host, port, e))
    notes = []
    if res["514tcp"] or res["5480"]:
        notes.append("59310 攻击面可达(syslog/VAMI)")
    if res["mechs"] and "SRP" in res["mechs"]:
        notes.append("59309 SRP 机制开启")
    elif res["mechs"] is not None:
        notes.append("SASL=%s" % res["mechs"])
    res["conclusion"] = "；".join(notes) or ("开放端口: %s" %
        ",".join(p for p in ("443", "5480", "514tcp", "1514", "389", "636", "2020")
                 if res.get(p)) or "无")
    return res


def probe_many(hosts, proxy=None, timeout=6, log=lambda s: None):
    return [probe_target(h, proxy=proxy, timeout=timeout, log=log) for h in hosts]
