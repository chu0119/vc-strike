"""vCenter Management REST 盘点（用已交付的合法账户做影响力证明）。

通过 vCenter 官方 REST API（443, /rest/com/vmware/cis/session +
/rest/vcenter/*）以交付的 SSO 管理员账户做**只读**清单采集：
虚拟机 / 主机 / 数据存储 / 集群 / 网络。
另提供 VM 导出（OVF/OVA，封装 VMware 官方 ovftool）——导出需要
已交付的管理员凭据，属标准管理操作；仅单台，全程审计。
"""
import base64
import os
import shutil
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
import urllib.error

from .util import human_size


class MgmtError(Exception):
    pass


def vapi_error(body):
    """从 vAPI 结构化错误响应提取可读文本（default_message 等）。

    6.x 常见：{"type":"...internal_server_error","value":{"messages":
    [{"default_message":"Provider method implementation ..."}]}}"""
    try:
        import json
        d = json.loads(body)
        val = d.get("value") or {}
        msgs = val.get("messages") or []
        parts = [m.get("default_message") for m in msgs
                 if isinstance(m, dict) and m.get("default_message")]
        t = d.get("type") or ""
        detail = " | ".join(parts) if parts else \
            body[:300].decode("utf-8", "replace")
        return ("[%s] %s" % (t, detail)) if t else detail
    except Exception:
        return body[:300].decode("utf-8", "replace")


def _opener():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # vCenter 自签证书，见 README 说明
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),     # 内网直连
        urllib.request.HTTPSHandler(context=ctx))


class VCenterRest:
    """最小 vCenter REST 客户端（仅认证 + 只读清单端点）。

    tls=False 仅用于本地测试桩（vCenter 真实环境恒为 TLS）。"""

    def __init__(self, host, port=443, timeout=15, tls=True):
        self.base = "%s://%s:%d" % ("https" if tls else "http", host, port)
        self.host = host
        self.timeout = timeout
        self.token = None
        self.opener = _opener() if tls else urllib.request.build_opener(
            urllib.request.ProxyHandler({}))

    def _req(self, path, method="GET", headers=None, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=body, headers=headers or {})
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            raise MgmtError("%s %s → %r" % (method, path, e))

    # ---- 会话 ----
    def login(self, user, password):
        self._user, self._password = user, password
        b64 = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        st, body = self._req("/rest/com/vmware/cis/session", method="POST",
                             headers={
                                 "Authorization": "Basic " + b64,
                                 "Accept": "application/json",
                             })
        if st == 401:
            raise MgmtError("认证失败（账户/密码错误或被锁定）")
        if st != 201 and st != 200:
            raise MgmtError("登录失败 HTTP %d: %s"
                            % (st, vapi_error(body)))
        try:
            import json
            self.token = json.loads(body)["value"]
        except Exception:
            raise MgmtError("登录响应解析失败: %s" % body[:200].decode("utf-8", "replace"))
        return True

    def logout(self):
        if self.token:
            try:
                self._req("/rest/com/vmware/cis/session", method="DELETE",
                          headers={"vmware-api-session-id": self.token})
            except Exception:
                pass                    # 登出失败不顶替业务异常
            self.token = None

    # ---- 只读清单 ----
    def _list(self, endpoint, fields):
        if not self.token:
            raise MgmtError("未登录")
        st, body = self._req(endpoint,
                             headers={"vmware-api-session-id": self.token,
                                      "Accept": "application/json"})
        if st != 200:
            raise MgmtError("GET %s → HTTP %d: %s"
                            % (endpoint, st, vapi_error(body)))
        import json
        try:
            items = json.loads(body).get("value", [])
        except Exception as e:
            raise MgmtError("GET %s 响应解析失败: %r" % (endpoint, e))
        rows = []
        for it in items:
            rows.append(tuple("?" if it.get(k) is None else str(it.get(k))
                              for k in fields))
        return rows

    def vms(self):
        """VM 清单，5 元组 (name, power, cpu, mem, vmid)。"""
        return self._list("/rest/vcenter/vm",
                          ("name", "power_state", "cpu_count",
                           "memory_size_MiB", "vm"))

    def hosts(self):
        return self._list("/rest/vcenter/host", ("name", "connection_state"))

    def datastores(self):
        rows = self._list("/rest/vcenter/datastore",
                          ("name", "type", "status", "capacity",
                           "free_space", "datastore"))
        return [(n, t, st, human_size(cap), human_size(fr), ds)
                for n, t, st, cap, fr, ds in rows]

    def clusters(self):
        return self._list("/rest/vcenter/cluster", ("name",))

    def datacenters(self):
        return self._list("/rest/vcenter/datacenter", ("name",))

    def networks(self):
        return self._list("/rest/vcenter/network", ("name", "type"))

    # ---- 单资产只读详情（⑨ 管理面板）----
    def _get(self, endpoint):
        if not self.token:
            raise MgmtError("未登录")
        st, body = self._req(endpoint,
                             headers={"vmware-api-session-id": self.token,
                                      "Accept": "application/json"})
        if st != 200:
            raise MgmtError("GET %s → HTTP %d: %s"
                            % (endpoint, st, vapi_error(body)))
        import json
        try:
            return json.loads(body).get("value", {})
        except Exception as e:
            raise MgmtError("GET %s 响应解析失败: %r" % (endpoint, e))

    def vm_detail(self, vm_id):
        """单台 VM 详情（含电源状态/客户机 OS 等）。"""
        it = self._get("/rest/vcenter/vm/" + vm_id)
        if not isinstance(it, dict):
            return {}
        keys = ("name", "power_state", "cpu_count", "memory_size_MiB",
                "guest_OS", "instant_clone_state")
        return {k: it.get(k) for k in keys if it.get(k) is not None}

    def vm_disks(self, vm_id):
        """单台 VM 磁盘清单（容量/数据存储）。"""
        return self._list("/rest/vcenter/vm/%s/hardware/disk" % vm_id,
                          ("label", "capacity", "datastore"))

    def vm_snapshots(self, vm_id):
        """单台 VM 快照清单（陈旧快照本身是给客户的风险发现）。

        兼容两种响应形态：7.x 的 {"snapshots": [...]} 与
        6.5/6.7 的裸列表。"""
        try:
            val = self._get("/rest/vcenter/vm/%s/snapshot" % vm_id)
        except MgmtError as e:
            if "HTTP 404" in str(e):
                return []          # 6.x：无快照的 VM 返回 404（视为无快照）
            raise
        if isinstance(val, dict):
            snaps = val.get("snapshots", [])
        elif isinstance(val, list):
            snaps = val
        else:
            snaps = []
        return [(s.get("name", "?"), s.get("create_time", "?"),
                 s.get("state", "?")) for s in snaps if isinstance(s, dict)]

    def datastore_detail(self, ds_id):
        """数据存储容量明细（字节）。"""
        it = self._get("/rest/vcenter/datastore/" + ds_id)
        return {k: it.get(k) for k in
                ("name", "type", "status", "capacity", "free_space",
                 "accessible")}

    # ---- 单台 VM 电源操作（写；调用方负责确认与审计；不做批量）----
    POWER_ACTIONS = ("start", "stop", "suspend", "reset")

    def power_get(self, vm_id):
        val = self._get("/rest/vcenter/vm/%s/power" % vm_id)
        return val.get("state", "?") if isinstance(val, dict) else "?"

    def power_set(self, vm_id, action):
        """action ∈ start/stop/suspend/reset。返回 (ok, detail)。

        请求体带 {"action": ...}：6.5/6.7 的 stop 必须携带（空 {} 会 400），
        新版本兼容。"""
        if action not in self.POWER_ACTIONS:
            raise MgmtError("未知电源动作: %s" % action)
        if not self.token:
            raise MgmtError("未登录")
        st, body = self._req("/rest/vcenter/vm/%s/power/%s" % (vm_id, action),
                             method="POST",
                             headers={"vmware-api-session-id": self.token,
                                      "Accept": "application/json",
                                      "Content-Type": "application/json"},
                             body=('{"action": "%s"}' % action).encode())
        if st in (200, 201, 204):
            return True, "HTTP %d" % st
        return False, "HTTP %d: %s" % (st, vapi_error(body))

    # ---- 汇总 ----
    def summary(self, max_rows=12, log=None):
        def table(title, headers, rows):
            out = ["  %s（%d）: %s" % (title, len(rows),
                                       " | ".join(headers))]
            for r in rows[:max_rows]:
                out.append("    · " + " | ".join(r))
            if len(rows) > max_rows:
                out.append("    · …（其余 %d 条略，完整清单见报告）"
                           % (len(rows) - max_rows))
            return out

        lines = ["═ vSphere 资产盘点（只读）═"]
        for title, headers, fn in (
                ("虚拟机", ("名称", "电源", "vCPU", "内存MiB"), self.vms),
                ("主机", ("名称", "连接状态"), self.hosts),
                ("数据存储", ("名称", "类型", "状态", "容量", "剩余"),
                 self.datastores),
                ("集群", ("名称",), self.clusters),
                ("网络", ("名称", "类型"), self.networks)):
            try:
                lines += table(title, headers, fn())
            except MgmtError as e:
                lines.append("  %s: 采集失败（%s）" % (title, e))
        return "\n".join(lines)

    # ---- VM 导出（OVF/OVA，封装 VMware 官方 ovftool；仅单台，全程审计）----
    def export_vm_ovftool(self, vm_name, dest_dir, ovftool=None,
                          log=None, stop_flag=None, auto_power=True,
                          power_confirm_cb=None):
        """用本机 ovftool 把 vm_name 导出为 OVA 到 dest_dir。

        auto_power=True 时：若 VM 处于开机状态（OVF 导出要求关机），
        自动关机 → 等待关机完成 → 导出 → 恢复开机。
        返回 (ok, detail)。数据经管理网络（443）拉到本机，耗时与磁盘
        大小成正比；stop_flag 置位可中止。"""
        if not self.token:
            raise MgmtError("未登录")
        ovftool = ovftool or find_ovftool()
        if not ovftool:
            raise MgmtError(
                "未找到 ovftool（VMware 官方 OVF 工具）。"
                "请安装 VMware OVF Tool 并加入 PATH，或用 --ovftool 指定路径")
        if not dest_dir:
            raise MgmtError("需要导出目录")
        dcs = [d for d, in self.datacenters()] or ["Datacenter"]
        os.makedirs(dest_dir, exist_ok=True)
        target = os.path.join(dest_dir, vm_name + ".ova")
        last_err = None
        for dc in dcs:                       # 多数据中心时逐个尝试（错误即快败）
            if stop_flag is not None and stop_flag.is_set():
                return False, "已取消"
            url = ovftool_source_url(self.host, self._user, self._password,
                                     dc, vm_name)
            cmd = [ovftool, "--acceptAllEulas", "--noSSLVerify", url, target]
            if log:
                log("[*] ovftool: %s → %s（数据中心 %s）" % (vm_name, target, dc))
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            except OSError as e:
                raise MgmtError("ovftool 启动失败: %r" % e)
            buf = ""
            out_lines = []
            while True:
                if stop_flag is not None and stop_flag.is_set():
                    proc.kill()
                    break
                # 二进制 BufferedReader 才有 read1；Windows text=True 下是
                # TextIOWrapper（无 read1）—— 实弹踩雷点，保持二进制自行解码
                chunk = proc.stdout.read1(512)
                if not chunk:
                    break
                text = chunk.decode("utf-8", "replace")
                buf += text
                while "\n" in buf or "\r" in buf:
                    i = min(x for x in (buf.find("\n"), buf.find("\r")) if x >= 0)
                    line, buf = buf[:i], buf[i + 1:]
                    if line.strip():
                        out_lines.append(line.strip())
                        if log:
                            log("    " + line.strip())
            rc = proc.wait()
            if stop_flag is not None and stop_flag.is_set():
                try:
                    os.remove(target)
                except OSError:
                    pass
                return False, "已取消"
            if rc == 0 and os.path.isfile(target):
                return True, "导出完成: %s（%.1f MB）" % (
                    target, os.path.getsize(target) / 1048576)
            err = "\n".join(out_lines)
            # 开机状态不可导出 → 自动关机重试一次，完成后恢复开机
            if ("Powered on" in err or "InvalidState" in err) and auto_power:
                if power_confirm_cb:
                    if not power_confirm_cb(
                            "VM「%s」处于开机状态，OVF 导出需要关机。\n"
                            "是否自动关机并在导出完成后恢复开机？" % vm_name):
                        if log:
                            log("[!] 已取消自动关机，导出中止（VM 保持开机）")
                        return False, "已取消（VM 开机，未导出）"
                vm_id = self._find_vm_id(vm_name)
                if vm_id:
                    if log:
                        log("[*] VM 处于开机状态 → 自动关机后重试导出（完成后恢复开机）")
                    if self._power_off_and_wait(vm_id, log=log,
                                                stop_flag=stop_flag):
                        try:
                            r2 = self.export_vm_ovftool(
                                vm_name, dest_dir, ovftool=ovftool, log=log,
                                stop_flag=stop_flag, auto_power=False)
                            if r2[0]:
                                if log:
                                    log("[*] 导出完成 → 恢复开机…")
                                self.power_set(vm_id, "start")
                            return r2
                        finally:
                            pass
            last_err = "ovftool 退出码 %d（数据中心 %s）：%s" % (
                rc, dc, err[-200:] if err else "无输出")
        return False, last_err or "导出失败"

    def _find_vm_id(self, vm_name):
        """按名称查找 VM-ID（精确匹配优先，其次唯一前缀匹配）。"""
        try:
            rows = self.vms()
        except Exception:
            return None
        exact = [r for r in rows if r[0] == vm_name]
        if exact:
            return exact[0][4]
        prefix = [r for r in rows if r[0].startswith(vm_name)]
        return prefix[0][4] if len(prefix) == 1 else None

    def _power_off_and_wait(self, vm_id, log=None, stop_flag=None,
                            timeout=120):
        """软关机并轮询至 POWERED_OFF（超时返回 False）。"""
        try:
            ok, detail = self.power_set(vm_id, "stop")
            if not ok:
                if log:
                    log("[!] 关机指令失败: %s" % detail)
                return False
        except Exception as e:
            if log:
                log("[!] 关机指令异常: %r" % e)
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            if stop_flag is not None and stop_flag.is_set():
                return False
            try:
                if self.power_get(vm_id) == "POWERED_OFF":
                    if log:
                        log("[+] VM 已关机")
                    return True
            except Exception:
                pass
            time.sleep(3)
        if log:
            log("[!] 等待关机超时（%ds）" % timeout)
        return False


def find_ovftool():
    """定位本机 ovftool（VMware 官方 OVF 工具）。返回路径或 None。"""
    p = shutil.which("ovftool")
    if p:
        return p
    for c in (r"C:\Program Files\VMware\VMware OVF Tool\ovftool.exe",
              r"C:\Program Files (x86)\VMware\VMware OVF Tool\ovftool.exe",
              "/usr/bin/ovftool", "/usr/local/bin/ovftool"):
        if os.path.isfile(c):
            return c
    return None


def ovftool_source_url(host, user, password, datacenter, vm_name):
    """组装 ovftool 的 vi:// 源地址（凭据 percent-encode）。"""
    return "vi://%s:%s@%s/%s/vm/%s" % (
        urllib.parse.quote(user, safe=""),
        urllib.parse.quote(password, safe=""),
        host, urllib.parse.quote(datacenter, safe=""),
        urllib.parse.quote(vm_name, safe=""))


def gather_inventory(host, user, password, port=443, timeout=15):
    """一次性登录 + 盘点 + 登出。返回汇总文本。"""
    c = VCenterRest(host, port, timeout)
    try:
        c.login(user, password)
        return c.summary()
    finally:
        c.logout()
