# -*- coding: utf-8 -*-
"""v1.6.0 修复批 3b：批 3 中断后的剩余项。"""
import re

def patch(path, old, new):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:90]))
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))

# ---------- ① Return 绑定 + 空输入反馈（批3 已完成则跳过） ----------
s = open(r"vcstrike/gui.py", encoding="utf-8").read()
if "_e_tgt" not in s:
    patch(r"vcstrike/gui.py",
'''        ttk.Entry(top, textvariable=self.tgt_input, width=20).pack(side="left", padx=4)''',
'''        _e_tgt = ttk.Entry(top, textvariable=self.tgt_input, width=20)
        _e_tgt.pack(side="left", padx=4)
        _e_tgt.bind("<Return>", lambda e: self._tgt_add())''')

# ---------- ② 向量值映射 ----------
patch(r"vcstrike/gui.py",
'''        ttk.Combobox(wf, textvariable=self.v510_vec, values=["app", "host"],
                     width=6, state="readonly").grid(row=3, column=0, sticky="w", padx=4)''',
'''        ttk.Combobox(wf, textvariable=self.v510_vec, values=["APP-NAME", "HOSTNAME"],
                     width=10, state="readonly").grid(row=3, column=0, sticky="w", padx=4)''')
patch(r"vcstrike/gui.py",
'''            written, pkt = write_file(host, port, dest, content,
                                      vector=self.v510_vec.get(), tcp=tcp, tls=tls)''',
'''            vec = "app" if self.v510_vec.get().startswith("APP") else "host"
            written, pkt = write_file(host, port, dest, content, vector=vec,
                                      tcp=tcp, tls=tls)''')

# ---------- 扫描可取消 + 进度 ----------
patch(r"vcstrike/gui.py",
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

# ---------- ③ TLS 联动 + rstpass 宽度 ----------
patch(r"vcstrike/gui.py",
'''        ttk.Combobox(pf, textvariable=self.v590_port, values=["389", "636", "2020"],
                     width=6, state="readonly").grid(row=0, column=1)''',
'''        _port_cb = ttk.Combobox(pf, textvariable=self.v590_port,
                                values=["389", "636", "2020"], width=6,
                                state="readonly")
        _port_cb.grid(row=0, column=1)
        _port_cb.bind("<<ComboboxSelected>>",
                      lambda e: self.v590_tls.set(self.v590_port.get() == "636"))''')
patch(r"vcstrike/gui.py",
'''        ttk.Entry(af, textvariable=self.v590_rstpass, width=11).grid(
            row=2, column=4, padx=(0, 4))''',
'''        ttk.Entry(af, textvariable=self.v590_rstpass, width=14).grid(
            row=2, column=4, padx=(0, 4))''')

# ---------- ③ 删除账户按钮（兑现清理中心承诺） ----------
patch(r"vcstrike/gui.py",
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
patch(r"vcstrike/gui.py",
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
patch(r"vcstrike/gui.py",
'''from .berldap import (connect_ldap, root_dse_probe, op_search, op_add,
                      op_modify, collect_search, parse_ldap_result, has_srp)''',
'''from .berldap import (connect_ldap, root_dse_probe, op_search, op_add,
                      op_modify, op_delete, collect_search,
                      parse_ldap_result, has_srp)''')

# ---------- ⑤ Return 绑定 ----------
patch(r"vcstrike/gui.py",
'''        ttk.Entry(cf, textvariable=self.postex_cmd).pack(side="left", fill="x",
                                                         expand=True, padx=4)''',
'''        _e_px = ttk.Entry(cf, textvariable=self.postex_cmd)
        _e_px.pack(side="left", fill="x", expand=True, padx=4)
        _e_px.bind("<Return>", lambda e: self._postex("cmd"))''')

# ---------- ④ term 错误就地提示 ----------
patch(r"vcstrike/gui.py",
'''        if not s:
            self.log("[!] 无会话（先监听并等回连，双击会话行）", "!")
            return''',
'''        if not s:
            self._term_append("[!] 无会话：先启动监听并等待回连，双击左侧会话行接管")
            return''')

# ---------- ⑥ Danger + 二次确认 + 滚动条 ----------
patch(r"vcstrike/gui.py",
'''        ttk.Button(top, text="一键清除目标残留（经 RCE）",
                   command=self._clean_remote).pack(side="left", padx=6)''',
'''        ttk.Button(top, text="一键清除目标残留（经 RCE）", style="Danger.TButton",
                   command=self._clean_remote).pack(side="left", padx=6)''')
patch(r"vcstrike/gui.py",
'''        cmd = ("rm -rf /etc/cron.d/cve59310* /tmp/cve59310_* /tmp/cve59310_check_* "
               "/tmp/ws*-syslog.log /opt/vmware/share/htdocs/r*.txt 2>/dev/null; "
               "echo '--- /etc/cron.d/ after cleanup ---'; ls -la /etc/cron.d/ | head -20")''',
'''        if not messagebox.askyesno(
                "二次确认", "将通过 RCE 在目标上执行清理命令：\\n"
                "rm -rf /etc/cron.d/cve59310* 等全部本工具落点。\\n继续？"):
            return
        cmd = ("rm -rf /etc/cron.d/cve59310* /tmp/cve59310_* /tmp/cve59310_check_* "
               "/tmp/ws*-syslog.log /opt/vmware/share/htdocs/r*.txt 2>/dev/null; "
               "echo '--- /etc/cron.d/ after cleanup ---'; ls -la /etc/cron.d/ | head -20")''')
patch(r"vcstrike/gui.py",
'''        self.act_tree = ttk.Treeview(awf, columns=("time", "type", "target", "detail"),
                                     show="headings", height=6)''',
'''        self.act_tree = ttk.Treeview(awf, columns=("time", "type", "target", "detail"),
                                     show="headings", height=6)
        _as = ttk.Scrollbar(awf, orient="vertical", command=self.act_tree.yview)
        self.act_tree.configure(yscrollcommand=_as.set)''')
patch(r"vcstrike/gui.py",
'''        self.act_tree.pack(fill="x", padx=4, pady=4)''',
'''        self.act_tree.pack(side="left", fill="x", padx=4, pady=4)
        _as.pack(side="right", fill="y")''')

# ---------- 日志横向滚动 ----------
patch(r"vcstrike/gui.py",
'''        self.log_txt.pack(fill="both", expand=True)''',
'''        _lx = ttk.Scrollbar(logf, orient="horizontal", command=self.log_txt.xview)
        _lx.pack(side="bottom", fill="x")
        self.log_txt.pack(fill="both", expand=True)
        self.log_txt.configure(xscrollcommand=_lx.set)''')

# ---------- util 助手替换（gui ③⑧ 生成处） ----------
s = open(r"vcstrike/gui.py", encoding="utf-8").read()
s = s.replace('self.v590_newuser = tk.StringVar(value="pentest_" + rand_name(4))',
              'self.v590_newuser = tk.StringVar(value=gen_user())')
s = s.replace('self.v590_newpass = tk.StringVar(value=rand_name(12))',
              'self.v590_newpass = tk.StringVar(value=gen_password())')
s = s.replace('self.vch_user = tk.StringVar(value="pentest_" + rand_name(4))',
              'self.vch_user = tk.StringVar(value=gen_user())')
s = s.replace('self.vch_pass = tk.StringVar(value=rand_name(10) + "!Aa1" + rand_name(2))',
              'self.vch_pass = tk.StringVar(value=gen_password())')
s = s.replace('command=lambda: (self.vch_user.set("pentest_" + rand_name(4)),\n'
              '                                    self.vch_pass.set(rand_name(10) + "!Aa1"\n'
              '                                                      + rand_name(2)))).pack(',
              'command=lambda: (self.vch_user.set(gen_user()),\n'
              '                                    self.vch_pass.set(gen_password()))).pack(')
s = s.replace('command=lambda: (self.vch_user.set("pentest_" + rand_name(4)),\n'
              '                                    self.vch_pass.set(gen_password()))).pack(',
              'command=lambda: (self.vch_user.set(gen_user()),\n'
              '                                    self.vch_pass.set(gen_password()))).pack(')
s = s.replace('        self.v590_newuser = tk.StringVar(value=gen_user())\n'
              '        ttk.Entry(af, textvariable=self.v590_newuser, width=13).grid(',
              '        self.v590_newuser = tk.StringVar(value=gen_user())\n'
              '        ttk.Entry(af, textvariable=self.v590_newuser, width=13).grid(')
if "from .util import rand_name" in s and "gen_user" not in s.split("from .util import")[1].split("\n")[0]:
    s = s.replace("from .util import rand_name",
                  "from .util import gen_password, gen_user, rand_name", 1)
open(r"vcstrike/gui.py", "w", encoding="utf-8").write(s)
print("gui gen helpers routed")

# ---------- chain.py 生成助手 + user_attrs ----------
p = r"vcstrike/chain.py"
s = open(p, encoding="utf-8").read()
s = s.replace("from .util import rand_name",
              "from .util import gen_password, gen_user")
s = s.replace('    user = user or ("pentest_" + rand_name(4))',
              '    user = user or gen_user()')
s = s.replace('    password = password or (rand_name(10) + "!Aa1" + rand_name(2))',
              '    password = password or gen_password()')
s = s.replace(
    '        conn.send_op(op_add(udn, [\n'
    '            ("objectClass", ["top", "person", "organizationalPerson", "user"]),\n'
    '            ("cn", [user]), ("sn", [dom]), ("givenName", [user]),\n'
    '            ("sAMAccountName", [user]), ("userPrincipalName", [upn]),\n'
    '            ("uid", [user]), ("userPassword", [password]),\n'
    '        ]))',
    '        from .berldap import user_attrs\n'
    '        conn.send_op(op_add(udn, user_attrs(user, password, dom)))')
open(p, "w", encoding="utf-8").write(s)
print("chain helpers routed")

# ---------- cli.py: add-admin 走 user_attrs + 死导入清理 ----------
p = r"vcstrike/cli.py"
s = open(p, encoding="utf-8").read()
s = s.replace(
    '            conn.send_op(op_add(udn, [\n'
    '                ("objectClass", ["top", "person", "organizationalPerson", "user"]),\n'
    '                ("cn", [user]), ("sn", [dom]), ("givenName", [user]),\n'
    '                ("sAMAccountName", [user]), ("userPrincipalName", ["%s@%s" % (user, dom)]),\n'
    '                ("uid", [user]), ("userPassword", [pw])]))',
    '            from .berldap import user_attrs\n'
    '            conn.send_op(op_add(udn, user_attrs(user, pw, dom)))')
s = s.replace("import argparse\nimport base64\nimport csv\nimport ssl\nimport sys\nimport time\n",
              "import argparse\nimport base64\nimport csv\nimport ssl\nimport sys\n")
s = s.replace(
    "from .syslog59310 import (build_rfc5424, check_write, write_file, plant_cron,\n"
    "                          rce_readback, drop_webshell, traversal_app,\n"
    "                          traversal_host, plant_revshell)",
    "from .syslog59310 import (check_write, write_file, plant_cron,\n"
    "                          rce_readback, drop_webshell, plant_revshell)")
open(p, "w", encoding="utf-8").write(s)
print("cli dedup done")

# ---------- version ----------
p = r"vcstrike/__init__.py"
s = open(p, encoding="utf-8").read()
s = s.replace('__version__ = "1.5.0"', '__version__ = "1.6.0"')
open(p, "w", encoding="utf-8").write(s)
print("version 1.6.0")
