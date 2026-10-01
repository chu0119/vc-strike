# -*- coding: utf-8 -*-
"""v1.6.0 三路审计修复批（P0/P1/P2 + 死代码），每处带断言，执行后自删。"""
import re

def patch(path, old, new, must=True):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        if must:
            raise SystemExit("PATCH MISS in %s: %r..." % (path, old[:80]))
        return
    s = s.replace(old, new, 1)
    open(path, "w", encoding="utf-8").write(s)

def patch_re(path, pat, new, flags=0):
    s = open(path, encoding="utf-8").read()
    s2, n = re.subn(pat, new, s, count=1, flags=flags)
    if n != 1:
        raise SystemExit("PATCH-RE MISS in %s: %r" % (path, pat[:80]))
    open(path, "w", encoding="utf-8").write(s2)

# ============ P1-1: mgmt.summary 移回类体 ============
p = r"vcstrike/mgmt.py"
summary_block = '''    # ---- 汇总 ----
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
        return "\\n".join(lines)


def gather_inventory'''
patch(p,
'''    # ---- 汇总 ----
    def summary(self, max_rows=12):''', summary_block.replace(
'''    # ---- 汇总 ----
    def summary(self, max_rows=12):''',
'''    # ---- 汇总 ----
    def summary(self, max_rows=12):''')) if False else None
# 上面的占位避免误替换；真正操作：把嵌套段裁出，插到类尾（power_set 之后）
s = open(p, encoding="utf-8").read()
nested_start = s.index("    # ---- 汇总 ----")
nested_end = s.index("def gather_inventory")
nested = s[nested_start:nested_end]
s = s[:nested_start] + s[nested_end:]
# summary 段当前缩进为类体级（4 空格 def summary），可直接放回 power_set 之后
anchor = '        return False, "HTTP %d: %s" % (st,\n                                       body[:150].decode("utf-8", "replace"))\n'
assert anchor in s, "power_set tail not found"
s = s.replace(anchor, anchor + "\n" + nested.rstrip() + "\n", 1)
open(p, "w", encoding="utf-8").write(s)
print("P1-1 summary restored into class")

# ============ P1-2: cli vops 分支结构 ============
p = r"vcstrike/cli.py"
patch(p,
'''        elif a.action == "detail":
            for k, v in c.vm_detail(a.vm).items():
                print("%s: %s" % (k, v))
        elif a.action == "disks":
            for r in c.vm_disks(a.vm):
                print(" | ".join(r))
        elif a.action == "export":''',
'''        elif a.action == "detail":
            for k, v in c.vm_detail(a.vm).items():
                print("%s: %s" % (k, v))
        elif a.action == "disks":
            for r in c.vm_disks(a.vm):
                print(" | ".join(r))
        elif a.action == "snapshots":
            snaps = c.vm_snapshots(a.vm)
            if not snaps:
                print("快照：无")
            for sn in snaps:
                print(" | ".join(sn))
        elif a.action == "export":''')
# --vm help 文案：VM-ID
patch(p, 'help="VM 名称（vms 可列出；export 用名称）"',
        'help="VM-ID（--action vms 可列出；export 用 VM 名称）"')
open(p, "w", encoding="utf-8").write(s) if False else None
print("P1-2 vops branches fixed")
PYEOF
