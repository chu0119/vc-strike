#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VC-Strike 启动器（等价 python -m vcstrike；无参数启动 GUI）。

仅限已获书面授权的渗透测试 / 漏洞验证 / 防御研究使用。
"""
import sys

try:
    from vcstrike.cli import main
except ImportError:
    sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
    from vcstrike.cli import main

if __name__ == "__main__":
    sys.exit(main())
