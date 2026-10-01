# -*- coding: utf-8 -*-
"""v1.6.0 修复批 2b：续接 _p16b 中断处。"""
import re

def patch(path, old, new):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:90]))
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))

p = r"vcstrike/gui.py"

# ---------- P1: ⑤ creds 面板 ----------
patch(p,
'''        of = ttk.LabelFrame(f, text="输出 / 已收集凭据")
        of.grid(row=3, column=0, sticky="nsew", pady=4)
        self.postex_out = tk.Text(of, bg=COLORS["logbg"], fg=COLORS["fg"],
                                  relief="flat", font=(self.font_family, 9))
        self.postex_out.pack(fill="both", expand=True, padx=4, pady=4)
        ttk.Label(of, text="机器账户可用于直连 LDAPS 做任意 LDAP 操作，或作为横向凭据。"
                           "（安全边界：不含 ESXi 破坏/勒索与隐蔽持久化功能）",
                  style="Muted.TLabel").pack(anchor="w", padx=6)''',
'''        of = ttk.LabelFrame(f, text="输出 / 已收集凭据")
        of.grid(row=3, column=0, sticky="nsew", pady=4)
        credf = ttk.Frame(of)
        credf.pack(fill="x", padx=4, pady=(4, 0))
        ttk.Label(credf, text="已收集凭据:", style="Muted.TLabel").pack(side="left")
        ttk.Button(credf, text="复制全部", width=10,
                   command=self._creds_copy).pack(side="right")
        self.cred_tree = ttk.Treeview(of, columns=("key", "value"),
                                      show="headings", height=4)
        for c, t, w in (("key", "来源", 170), ("value", "凭据", 340)):
            self.cred_tree.heading(c, text=t)
            self.cred_tree.column(c, width=w, anchor="w")
        self.cred_tree.pack(fill="x", padx=4, pady=(0, 4))
        self.postex_out = tk.Text(of, height=6, bg=COLORS["logbg"], fg=COLORS["fg"],
                                  relief="flat", font=(self.font_family, 9))
        self.postex_out.pack(fill="both", expand=True, padx=4, pady=4)
        ttk.Label(of, text="机器账户可用于直连 LDAPS 做任意 LDAP 操作，或作为横向凭据。"
                           "（安全边界：不含 ESXi 破坏/勒索与隐蔽持久化功能）",
                  style="Muted.TLabel").pack(anchor="w", padx=6)

    def _add_cred(self, key, value):
        """凭据统一入口：会话记录 + ⑤ 页面板同步。"""
        self.creds[key] = value
        if hasattr(self, "cred_tree"):
            self.root.after(0, lambda: self.cred_tree.insert(
                "", "end", values=(key, value)))

    def _creds_copy(self):
        if not self.creds:
            messagebox.showinfo("提示", "尚无已收集凭据")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\\n".join(
            "%s = %s" % (k, v) for k, v in self.creds.items()))
        self.log("[+] 已复制 %d 条凭据" % len(self.creds), "+")''')

# ---------- P2: Esc 统一取消 ----------
patch(p,
'''                        ("<Escape>", lambda e: self.stop_flag.set()),''',
'''                        ("<Escape>", lambda e: self._cancel()),''')

# ---------- P2: ② 页取消按钮反馈 ----------
patch(p,
'''        ttk.Button(bb, text="取消 [Esc]", command=self.stop_flag.set).pack(side="left")''',
'''        ttk.Button(bb, text="取消 [Esc]", command=self._cancel).pack(side="left")''')

# ---------- P2: ⑧ 页取消按钮反馈 ----------
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
        threading.Thread(target=wrap, daemon=True).start()

    def _cancel(self):
        self.stop_flag.set()
        self.log("[!] 已请求取消，等待当前步骤结束…", "!")''')

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
        s_id, s_addr = sess.id, sess.addr

        def go():
            self.nb.select(self.tab_shell)
            self.cur_sess = sess
            self._term_append("== 已自动接管会话 #%d (%s) ==" % (s_id, s_addr))
            self.log("[i] 已自动接管会话 #%d（%s）" % (s_id, s_addr), "m")
        self.root.after(0, go)''')

# ---------- P2: _vv_refresh 主线程取凭据 + 401 自愈 ----------
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

# ---------- P2: 轮询吞错可见化 ----------
patch(p,
'''        except Exception:
            pass
        self.root.after(200, self._poll_term)''',
'''        except Exception as e:
            if not getattr(self, "_poll_err_logged", False):
                self._poll_err_logged = True
                logutil.write("!", "终端轮询异常（已静默）: %r" % e)
        self.root.after(200, self._poll_term)''')

print("batch2b applied")
