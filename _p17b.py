# -*- coding: utf-8 -*-
"""v1.7.0 gui 剩余补丁（批 B）。"""

def patch(path, old, new):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:90]))
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))

P = "vcstrike/gui.py"

# ③ 随机按钮同步 + 提示
patch(P,
'''        ttk.Button(af, text="↻", width=3,
                   command=self._b309_randacct).grid(row=0, column=4)''',
'''        ttk.Button(af, text="↻", width=3,
                   command=self._b309_randacct).grid(row=0, column=4)
        ttk.Label(af, text="命名伪装为 vCenter 解决方案用户").grid(
            row=0, column=5, padx=(6, 0), sticky="w")''')

# ⑧ 账号库 UI
patch(P,
'''        bf = ttk.LabelFrame(left, text="执行")
        bf.pack(fill="x", pady=4)
        ttk.Button(bf, text="开始一键打通 [F7]", style="Acc.TButton",''',
'''        af2 = ttk.LabelFrame(left, text="账号库（持久化 · 多机共用同一账户）")
        af2.pack(fill="x", pady=4)
        self.chain_acc = tk.StringVar()
        _acc_cb = ttk.Combobox(af2, textvariable=self.chain_acc, state="readonly")
        _acc_cb.pack(side="left", fill="x", expand=True, padx=4)
        self.chain_acc_cb = _acc_cb
        _abar = ttk.Frame(af2)
        _abar.pack(fill="x", padx=4, pady=(0, 3))
        ttk.Button(_abar, text="刷新", width=6,
                   command=self._acc_refresh).pack(side="left")
        ttk.Button(_abar, text="用作交付账户", width=14,
                   command=self._acc_use_chain).pack(side="left", padx=4)
        ttk.Button(_abar, text="删除选中", width=10,
                   command=self._acc_del).pack(side="left")
        self._acc_refresh()

        bf = ttk.LabelFrame(left, text="执行")
        bf.pack(fill="x", pady=4)
        ttk.Button(bf, text="开始一键打通 [F7]", style="Acc.TButton",''')

# chain 成功 → 入库刷新
patch(P,
'''                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))
                self._add_cred("机器账户@%s" % host, r.info.get("identity", "?"))''',
'''                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))
                self._add_cred("机器账户@%s" % host, r.info.get("identity", "?"))
                self.root.after(0, lambda h=host, u=r.upn, p2=r.password:
                                self._acc_add(h, u, p2, source="chain"))''')

# 账号库方法
patch(P,
'''    # ================= Tab6 清理中心 =================''',
'''    # ---------- 账号库 ----------
    def _acc_refresh(self):
        accs = store.load_accounts()
        labels = ["%s @ %s" % (a["user"], a.get("host", "?")) for a in accs]
        cb = getattr(self, "chain_acc_cb", None)
        if cb:
            cb["values"] = labels
            if labels and not cb.get():
                cb.current(0)
        self._acc_map = dict(zip(labels, accs))

    def _acc_use_chain(self):
        label = self.chain_acc.get()
        a = getattr(self, "_acc_map", {}).get(label)
        if not a:
            messagebox.showinfo("提示", "请先在账号库下拉中选择一条记录")
            return
        self.vch_user.set(a["user"])
        self.vch_pass.set(a["password"])
        if a.get("host"):
            self.vch_host.set(a["host"])
        self.log("[+] 已带入账号库账户 %s（%s）" % (a["user"], a.get("host")), "+")

    def _acc_add(self, host, user, password, source="manual"):
        store.add_account(host, user, password, source=source)
        self._acc_refresh()

    def _acc_del(self):
        label = self.chain_acc.get()
        a = getattr(self, "_acc_map", {}).get(label)
        if not a:
            messagebox.showinfo("提示", "请先选择一条记录")
            return
        if not messagebox.askyesno("二次确认", "从账号库删除 %s @ %s？" %
                                   (a["user"], a.get("host"))):
            return
        accs = [x for x in store.load_accounts()
                if not (x.get("user") == a.get("user")
                        and x.get("host") == a.get("host"))]
        store.save_accounts(accs)
        self._acc_refresh()
        self.log("[i] 账号库已删除: %s" % label, "m")

    # ---------- ⑨ 账号库带入 ----------
    def _vops_use_acc(self):
        accs = store.load_accounts()
        if not accs:
            messagebox.showinfo("提示", "账号库为空（先 ⑧ 打通或 ③ 创建）")
            return
        menu = tk.Menu(self, tearoff=0)
        for a in accs:
            label = "%s @ %s" % (a["user"], a.get("host", "?"))
            menu.add_command(label=label,
                             command=lambda aa=a: self._vops_apply_acc(aa))
        menu.tk_popup(self.winfo_rootx() + 300, self.winfo_rooty() + 150)

    def _vops_apply_acc(self, a):
        self._vv_conn = None
        if a.get("host"):
            self.vv_host.set(a["host"])
        self.vv_user.set(a["user"])
        self.vv_pass.set(a["password"])
        self.log("[+] 已带入账号库账户 %s（记得点登录并刷新）" % a["user"], "+")

    # ---------- ⑨ 排序 ----------
    def _vv_sort(self, col):
        state = getattr(self, "_vv_sort_state", {"col": None, "desc": False})
        desc = (state["col"] == col) and not state["desc"]
        self._vv_sort_state = {"col": col, "desc": desc}
        items = [(self.vv_tree.set(k, col), k)
                 for k in self.vv_tree.get_children()]
        if col in ("cpu", "mem"):
            def num(v):
                m2 = re.sub(r"[^0-9.]", "", v)
                return float(m2) if m2 else 0.0
            items.sort(key=lambda t: num(t[0]), reverse=desc)
        else:
            items.sort(key=lambda t: t[0].lower(), reverse=desc)
        for i, (_v, k) in enumerate(items):
            self.vv_tree.move(k, "", i)
        for colname in list(self.vv_tree["columns"]):
            base = (self.vv_tree.heading(colname, "text")
                    .replace(" ↓", "").replace(" ↑", ""))
            mark = ""
            if colname == col:
                mark = " ↓" if desc else " ↑"
            self.vv_tree.heading(colname, text=base + mark)

    # ---------- ⑨ 右键菜单 ----------
    def _vv_menu(self, event):
        row = self.vv_tree.identify_row(event.y)
        if not row:
            return
        self.vv_tree.selection_set(row)
        vmid = self.vv_tree.set(row, "vmid")
        name = self.vv_tree.item(row, "text")
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="复制 VM-ID",
                         command=lambda: (self.root.clipboard_clear(),
                                          self.root.clipboard_append(vmid),
                                          self.log("[+] VM-ID 已复制: %s" % vmid, "+")))
        menu.add_command(label="复制名称",
                         command=lambda: (self.root.clipboard_clear(),
                                          self.root.clipboard_append(name)))
        menu.add_separator()
        menu.add_command(label="VM 详情", command=self._vv_detail)
        menu.add_command(label="磁盘清单", command=self._vv_disks)
        menu.add_command(label="快照清单", command=self._vv_snaps)
        menu.add_separator()
        menu.add_command(label="电源 · 开机",
                         command=lambda: self._vv_power_guarded("start", name, vmid))
        menu.add_command(label="电源 · 重启",
                         command=lambda: self._vv_power_guarded("reset", name, vmid))
        menu.add_command(label="电源 · 挂起",
                         command=lambda: self._vv_power_guarded("suspend", name, vmid))
        menu.add_command(label="电源 · 关机",
                         command=lambda: self._vv_power_guarded("stop", name, vmid))
        menu.add_separator()
        menu.add_command(label="导出此 VM（OVA）",
                         command=lambda: (self.vv_expname.set(name),
                                          self._vv_export()))
        menu.tk_popup(event.x_root, event.y_root)

    def _vv_power_guarded(self, action, name, vmid):
        self.vv_action.set(action)
        self.vv_confirm.set(vmid)
        if not messagebox.askyesno(
                "二次确认", "对 %s（%s）执行电源操作「%s」？\n"
                "这是对客户资产的写操作，请确认 RoE 允许。" % (name, vmid, action)):
            return
        self._vv_power_confirm(vmid, name, action)

    def _vv_power_confirm(self, vmid, name, action):
        host, user, password = self._vv_creds()

        def work():
            from .mgmt import MgmtError
            try:
                try:
                    c = self._vv_client(host, user, password)
                    ok, detail = c.power_set(vmid, action)
                except MgmtError as e:
                    s2 = str(e)
                    if "401" in s2 or "认证失败" in s2:
                        self._vv_conn = None
                        c = self._vv_connect(host, user, password)
                        ok, detail = c.power_set(vmid, action)
                    else:
                        raise
                msg = "电源[%s] %s（%s）→ %s" % (action, name, vmid, detail)
                if ok and action in ("start", "reset"):
                    msg += "，当前状态 %s" % c.power_get(vmid)
                elif action == "stop":
                    msg += "（软关机发起，状态需数秒后复查）"
                self.root.after(0, lambda: self._vv_out_append(msg))
                self.log("[%s] %s" % ("+" if ok else "!", msg),
                         "+" if ok else "!")
                self.record("vops-电源", host, "%s %s" % (action, name),
                            "（写操作；如需恢复请执行相反动作）")
            except Exception as e:
                self.log("[!] 电源操作失败: %s" % e, "!")
        self.run_bg(work, "电源操作")

    # ================= Tab6 清理中心 =================''')

# 主按钮电源 → confirm 复用
patch(P,
'''        host, user, password = self._vv_creds()

        def work():
            from .mgmt import MgmtError
            try:
                try:
                    c = self._vv_client(host, user, password)
                    ok, detail = c.power_set(vmid, action)''',
'''        self._vv_power_confirm(vmid, name, action)

    def _vv_power_confirm(self, vmid, name, action):
        host, user, password = self._vv_creds()

        def work():
            from .mgmt import MgmtError
            try:
                try:
                    c = self._vv_client(host, user, password)
                    ok, detail = c.power_set(vmid, action)''')

# ⑨ 排序/右键绑定
patch(P,
'''        self.vv_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self._tree_resizable(self.vv_tree)''',
'''        self.vv_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self._tree_resizable(self.vv_tree)
        for _col in ("power", "cpu", "mem", "vmid"):
            self.vv_tree.heading(_col,
                                 command=lambda cc=_col: self._vv_sort(cc))
        self.vv_tree.bind("<Button-3>", self._vv_menu)''')

# ⑨ 账号库按钮
patch(P,
'''        ttk.Button(lf, text="登录并刷新 [F9]", style="Acc.TButton",
                   command=self._vv_refresh).pack(side="left", padx=6)''',
'''        ttk.Button(lf, text="登录并刷新 [F9]", style="Acc.TButton",
                   command=self._vv_refresh).pack(side="left", padx=6)
        ttk.Button(lf, text="账号库", width=8,
                   command=self._vops_use_acc).pack(side="left", padx=2)''')

# 状态持久化：加载
patch(P,
'''        self.root.after(120, self._poll_log)''',
'''        self.root.after(120, self._poll_log)
        self._load_ui_state()''')
patch(P,
'''    def _on_close(self):''',
'''    _UI_VARS = (("http_proxy", "str"), ("v510_port", "str"),
                ("v510_proto", "str"), ("v510_vport", "str"),
                ("v510_lhost", "str"), ("v510_lport", "str"),
                ("v590_port", "str"), ("v590_ident", "str"),
                ("v590_cbase", "str"), ("vv_dest", "str"))

    def _load_ui_state(self):
        """启动恢复上次界面状态（目标清单/当前目标/端口/代理，不含密码）。"""
        try:
            st = store.load_ui()
        except Exception:
            return
        for var, _k in self._UI_VARS:
            v = st.get(var)
            if v is not None and hasattr(self, var):
                try:
                    getattr(self, var).set(v)
                except Exception:
                    pass
        for h in st.get("targets", []):
            try:
                self.scan_tree.insert("", "end",
                                      values=(h, "", "", "", "", "", "", "", "", "", "", ""))
            except Exception:
                pass
        cur = st.get("cur_target")
        if cur:
            self.cur_target.set(cur)
        proxy = st.get("http_proxy")
        if proxy:
            self.http_proxy.set(proxy)
        dest = st.get("vv_dest")
        if dest:
            self.vv_dest.set(dest)

    def _save_ui_state(self):
        try:
            targets = [self.scan_tree.item(i, "values")[0]
                       for i in self.scan_tree.get_children()]
            state = {"targets": targets,
                     "cur_target": self.cur_target.get(),
                     "vv_dest": self.vv_dest.get()}
            for var, _k in self._UI_VARS:
                if hasattr(self, var):
                    state[var] = getattr(self, var).get()
            store.save_ui(state)
        except Exception:
            pass

    def _on_close(self):''')

# 关闭时保存
patch(P,
'''        try:
            if self._vv_conn is not None:
                self._vv_conn.logout()
        except Exception:
            pass
        logutil.finish()
        self.root.destroy()''',
'''        try:
            if self._vv_conn is not None:
                self._vv_conn.logout()
        except Exception:
            pass
        self._save_ui_state()
        logutil.finish()
        self.root.destroy()''')

print("batch B applied")
