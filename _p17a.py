# -*- coding: utf-8 -*-
"""v1.7.0 批：GUI 状态持久化 + 账号库 + 伪装命名 + 排序/右键菜单。"""

def patch(path, old, new):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:90]))
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))

p = r"vcstrike/gui.py"
patch(p,
'''from . import __version__, logutil
from .util import rand_name''',
'''from . import __version__, logutil, store
from .util import gen_password, gen_user, rand_name, stealth_user''')
patch(p,
'        self.v590_newuser = tk.StringVar(value=gen_user())',
'        self.v590_newuser = tk.StringVar(value=stealth_user())')
patch(p,
'''    def _b309_randacct(self):
        self.v590_newuser.set("pentest_" + rand_name(4))
        self.v590_newpass.set(rand_name(12))''',
'''    def _b309_randacct(self):
        self.v590_newuser.set(stealth_user())
        self.v590_newpass.set(gen_password())''')
patch(p,
'        self.vch_user = tk.StringVar(value=gen_user())',
'        self.vch_user = tk.StringVar(value=stealth_user())')
patch(p,
'        ttk.Button(af, text="↻", width=3, command=self._b309_randacct).grid(row=0, column=4)',
'        ttk.Button(af, text="↻", width=3, command=self._b309_randacct).grid(row=0, column=4)
'
        '        ttk.Label(af, text="命名伪装为 vCenter 解决方案用户").grid(
'
        '            row=0, column=5, padx=(6, 0), sticky="w")')

patch(p,
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
patch(p,
'''                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))
                self._add_cred("机器账户@%s" % host, r.info.get("identity", "?"))''',
'''                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))
                self._add_cred("机器账户@%s" % host, r.info.get("identity", "?"))
                self.root.after(0, lambda h=host, u=r.upn, p2=r.password:
                                self._acc_add(h, u, p2, source="chain"))''')
