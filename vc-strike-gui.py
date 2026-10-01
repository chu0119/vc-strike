#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VC-Strike 纯 GUI 启动器（打包 windowed exe 用，无控制台）。"""
import sys

from vcstrike.gui import run_gui

if __name__ == "__main__":
    sys.exit(run_gui())
