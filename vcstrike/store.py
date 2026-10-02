# -*- coding: utf-8 -*-
"""本地持久化：UI 状态 + 账号库（与日志同目录，exe/脚本所在目录）。

文件：
  vc-strike-ui.json       —— 目标清单/端口/协议/代理/导出目录等界面状态
  vc-strike-accounts.json —— 账号库（交付/创建的账户密码，多机共用）

⚠ 两者均为明文 JSON（红队便利性设计）：账号库含目标凭据，请与日志同等
   级别保管，勿提交仓库、勿随意分享。机密字段不会写入 ui.json。
"""
import json
import os
import time


def store_dir():
    if getattr(__import__("sys"), "frozen", False):
        import sys
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.getcwd()


def _path(name):
    return os.path.join(store_dir(), name)


def _load(name, default):
    try:
        with open(_path(name), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(name, data):
    try:
        with open(_path(name), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        return _path(name)
    except Exception:
        return None


# ---- UI 状态 ----
UI_FILE = "vc-strike-ui.json"


def load_ui():
    return _load(UI_FILE, {})


def save_ui(state):
    state = dict(state)
    state["saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return _save(UI_FILE, state)


# ---- 账号库 ----
ACC_FILE = "vc-strike-accounts.json"


def load_accounts():
    return _load(ACC_FILE, [])


def save_accounts(accounts):
    return _save(ACC_FILE, accounts)


def add_account(host, user, password, source="chain", note=""):
    """追加/更新一条账号记录（同 host+user 覆盖密码）。返回库全文。"""
    accounts = load_accounts()
    for a in accounts:
        if a.get("host") == host and a.get("user") == user:
            a["password"] = password
            a["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if note:
                a["note"] = note
            save_accounts(accounts)
            return accounts
    accounts.append({
        "host": host, "user": user, "password": password,
        "source": source, "note": note,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_accounts(accounts)
    return accounts
