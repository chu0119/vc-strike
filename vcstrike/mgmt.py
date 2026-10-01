"""vCenter Management REST 盘点（用已交付的合法账户做影响力证明）。

通过 vCenter 官方 REST API（443, /rest/com/vmware/cis/session +
/rest/vcenter/*）以交付的 SSO 管理员账户做**只读**清单采集：
虚拟机 / 主机 / 数据存储 / 集群 / 网络。

定位：授权测试报告的"影响范围"章节素材。只读，不修改任何资产，
不做配置导出/凭据抽取，登出即结束会话。
"""
import base64
import ssl
import urllib.request
import urllib.error


class MgmtError(Exception):
    pass


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
        b64 = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        st, body = self._req("/rest/com/vmware/cis/session", method="POST",
                             headers={
                                 "Authorization": "Basic " + b64,
                                 "Accept": "application/json",
                             })
        if st == 401:
            raise MgmtError("认证失败（账户/密码错误或被锁定）")
        if st != 201 and st != 200:
            raise MgmtError("登录失败 HTTP %d: %s" % (st, body[:200].decode("utf-8", "replace")))
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
            raise MgmtError("GET %s → HTTP %d: %s" % (endpoint, st, body[:150].decode("utf-8", "replace")))
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
        return self._list("/rest/vcenter/datastore",
                          ("name", "type", "status", "capacity",
                           "free_space"))

    def clusters(self):
        return self._list("/rest/vcenter/cluster", ("name",))

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
                            % (endpoint, st,
                               body[:150].decode("utf-8", "replace")))
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
        val = self._get("/rest/vcenter/vm/%s/snapshot" % vm_id)
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
        return False, "HTTP %d: %s" % (st,
                                       body[:150].decode("utf-8", "replace"))

    # ---- 汇总 ----
    def summary(self, max_rows=12):
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


def gather_inventory(host, user, password, port=443, timeout=15):
    """一次性登录 + 盘点 + 登出。返回汇总文本。"""
    c = VCenterRest(host, port, timeout)
    try:
        c.login(user, password)
        return c.summary()
    finally:
        c.logout()
