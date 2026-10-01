"""UI 审查辅助：启动 GUI、填充示例数据、逐页签截图（不走网络）。

用法: python tools_ui_shots.py <输出目录>
截图用 PowerShell CopyFromScreen，无第三方依赖。
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tkinter as tk

from vcstrike.gui import ToolApp, ensure_dpi_awareness


def capture(x, y, w, h, path):
    ps = (
        "Add-Type -AssemblyName System.Drawing;"
        "$b = New-Object System.Drawing.Bitmap({w}, {h});"
        "$g = [System.Drawing.Graphics]::FromImage($b);"
        "$g.CopyFromScreen({x}, {y}, 0, 0, $b.Size);"
        "$b.Save('{path}');"
        "$g.Dispose(); $b.Dispose()"
    ).format(w=w, h=h, x=x, y=y, path=path)
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True,
                   capture_output=True)


def window_rect(root):
    """用 Win32 取窗口物理矩形（含标题栏）——不受 Tk 逻辑坐标/DPI 虚拟化影响。"""
    import ctypes

    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                    ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

    hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
    if not hwnd:
        hwnd = root.winfo_id()
    dpi = ctypes.windll.user32.GetDpiForWindow(hwnd) if hasattr(
        ctypes.windll.user32, "GetDpiForWindow") else 96
    rect = RECT()
    ctypes.windll.user32.GetWindowRect(hwnd, ctypes.byref(rect))
    print("DPI=%d (scale %.0f%%) rect=(%d,%d)-(%d,%d)" %
          (dpi, dpi / 96.0 * 100, rect.left, rect.top, rect.right, rect.bottom))
    return (rect.left, rect.top,
            rect.right - rect.left, rect.bottom - rect.top)


def main(outdir, size=None):
    os.makedirs(outdir, exist_ok=True)
    ensure_dpi_awareness()
    root = tk.Tk()
    app = ToolApp(root)          # 窗口尺寸由 ToolApp 按 DPI 自适应决定
    if size:
        root.geometry("%s+60+40" % size)
    root.update_idletasks()
    root.update()

    # ---- 填充代表性示例数据（不联网） ----
    app.log("[i] VC-Strike v1.0.0 就绪（示例截图数据）", "i")
    app.log("[+] 10.0.0.10 → 59310 攻击面可达(syslog/VAMI)；59309 SRP 机制开启", "+")
    app.log("[!] 10.0.0.22 → 389 拒绝连接", "!")
    app.log("[*] RCE(回显) → 10.0.0.10 : id; hostname", "m")
    app.log("[+] 命令输出已取回（128 字节）", "+")
    for h, concl in (("10.0.0.10", "59310 攻击面可达(syslog/VAMI)；59309 SRP 机制开启"),
                     ("10.0.0.22", "开放端口: 443,5480"),
                     ("vcsa.lab.local", "59309 SRP 机制开启")):
        app.scan_tree.insert("", "end", values=(
            h, "●", "●", "", "●", "●", "", "●", "9.0.0.0",
            "SRP,DIGEST-MD5,PLAIN", "dc=vsphere,dc=local", concl))
    app.scan_results["10.0.0.10"] = {}
    app.v59310_host.set("10.0.0.10")
    app.v590_host.set("10.0.0.10")
    app.vpx_host.set("10.0.0.10")
    app.v510_lhost.set("10.0.0.5")
    app.v590_cbase.set("dc=vsphere,dc=local")
    app.v590_info.insert("1.0", "身份: administrator@vsphere.local\nN: 1024 bit\n"
                                "服务端选项: mda=SHA-1,replay_detection,integrity=HMAC-SHA-1\n"
                                "客户端选项: mda=sha-1,integrity=hmac-sha-1,replay_detection\n"
                                "安全层: HMAC-SHA-1（完整性）")
    for dn, attrs in (("cn=administrator,cn=Users,dc=vsphere,dc=local",
                       "cn=administrator | userPrincipalName=administrator@vsphere.local"),
                      ("cn=pentest_ab12,cn=Users,dc=vsphere,dc=local",
                       "cn=pentest_ab12 | sAMAccountName=pentest_ab12"),
                      ("cn=Administrators,cn=Builtin,dc=vsphere,dc=local",
                       "member=cn=administrator,… | member=cn=pentest_ab12,…")):
        app.v590_tree.insert("", "end", text=dn, values=(attrs,))
    app.v590_ctext.insert("1.0", "DN: cn=administrator,cn=Users,dc=vsphere,dc=local\n"
                                 "  cn: administrator\n  sAMAccountName: administrator\n"
                                 "  userPrincipalName: administrator@vsphere.local")
    app.postex_out.insert("1.0", "uid=0(root) gid=0(root) groups=0(root)\n"
                                 "VMware vCenter Server 9.0.2.0 (Build 25148086)\n"
                                 "dcAccountDN: cn=vcadmin,ou=Domain Controllers,dc=vsphere,dc=local")
    app.actions.append({"time": "10-01 10:23:01", "type": "59310-写入验证",
                        "target": "10.0.0.10",
                        "detail": "/tmp/cve59310_check_ab12c3-syslog.log",
                        "cleanup": "rm -f /tmp/cve59310_check_ab12c3-syslog.log"})

    names = ["01-目标与指纹", "02-CVE-2026-59310", "03-CVE-2026-59309",
             "04-C2会话", "05-后渗透", "06-清理中心", "07-检测与加固"]
    shots = []
    for i in range(7):
        app.nb.select(i)
        root.update_idletasks()
        root.update()
        time.sleep(0.25)
        x, y, w, h = window_rect(root)
        p = os.path.join(outdir, "%s.png" % names[i])
        capture(x + 8, y, w - 16, h - 16, p)   # 内缩去 DWM 阴影边
        shots.append(p)
        print("captured:", p)
    root.after(100, app._on_close)
    root.mainloop()
    return shots


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ui-review",
         sys.argv[2] if len(sys.argv) > 2 else None)
