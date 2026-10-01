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
    """最小 vCenter REST 客户端（仅认证 + 只读清单端点）。"""

    def __init__(self, host, port=443, timeout=15):
        self.base = "https://%s:%d" % (host, port)
        self.host = host
        self.timeout = timeout
        self.token = None
        self.opener = _opener()

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
            rows.append(tuple(str(it.get(k) or "?") for k in fields))
        return rows

    def vms(self):
        return self._list("/rest/vcenter/vm",
                          ("name", "power_state", "cpu_count",
                           "memory_size_MiB"))

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
