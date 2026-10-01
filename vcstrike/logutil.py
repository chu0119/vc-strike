"""运行日志：全程记录到 exe/脚本同目录下的日志文件。

用途：测试结束后把日志文件直接交给维护者，即可基于真实运行数据做
二次加固与修复。文件命名 `vc-strike-<tag>-<时间戳>.log`，每次运行一个。

记录范围：
  - 环境头（版本 / 系统 / DPI 缩放 / 是否打包运行）
  - GUI 日志面板的全部条目（操作、结果、报错）
  - CLI 模式下所有 print 输出（stdout/stderr Tee）
  - 未处理异常的完整堆栈（excepthook）
  - C2 会话的原始输出流（ANSI 已剥离，见 c2.Session._reader）
"""
import os
import sys
import threading
import time

_lock = threading.Lock()
_state = {"fh": None, "path": None}


def log_dir():
    """日志目录：exe 同目录（打包运行）或当前目录（源码运行）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.getcwd()


def path():
    return _state["path"]


def start(tag="run"):
    """打开本次运行的日志文件；已在记录中则返回现有路径（幂等）。"""
    with _lock:
        if _state["fh"]:
            return _state["path"]
        candidates = [log_dir(), os.getcwd(), os.path.join(
            os.environ.get("TEMP", os.path.expanduser("~")), "vc-strike")]
        last_err = None
        for d in candidates:
            try:
                os.makedirs(d, exist_ok=True)
                name = "vc-strike-%s-%s.log" % (tag, time.strftime("%Y%m%d-%H%M%S"))
                p = os.path.join(d, name)
                fh = open(p, "a", encoding="utf-8", errors="replace")
                _state["fh"] = fh
                _state["path"] = p
                break
            except OSError as e:
                last_err = e
        else:
            return None
        if _state["path"] != os.path.join(candidates[0], os.path.basename(_state["path"])):
            _write_locked("w", "首选日志目录不可写（%s），已回退: %s（%s）"
                          % (candidates[0], _state["path"], last_err))
        _write_locked("i", "== VC-Strike 会话开始 ==")
        return _state["path"]


def _write_locked(level, msg):
    """调用方必须已持有 _lock（start/finish 内部使用，避免非重入死锁）。"""
    fh = _state["fh"]
    if not fh:
        return
    try:
        fh.write("[%s] [%s] %s\n" % (time.strftime("%H:%M:%S"), level, msg))
        fh.flush()
    except Exception:
        pass


def write(level, msg):
    """带时间戳与级别的条目。"""
    with _lock:
        _write_locked(level, msg)


def raw(chunk):
    """无时间戳的原始文本（C2 会话流 / 堆栈 / Tee 输出）。"""
    if not chunk:
        return
    with _lock:
        fh = _state["fh"]
        if not fh:
            return
        try:
            fh.write(chunk)
            if not chunk.endswith("\n"):
                fh.write("\n")
            fh.flush()
        except Exception:
            pass


def finish(note="会话结束"):
    with _lock:
        _write_locked("i", "== %s ==" % note)
        fh = _state["fh"]
        _state["fh"] = None
        try:
            if fh:
                fh.close()
        except Exception:
            pass


class StdoutTee:
    """把 print 输出同步进日志文件（CLI 模式）。"""

    def __init__(self, orig):
        self._orig = orig

    def write(self, s):
        self._orig.write(s)
        raw(s)
        return len(s)

    def flush(self):
        try:
            self._orig.flush()
        except Exception:
            pass


def install_stdout_tee():
    if not isinstance(sys.stdout, StdoutTee):
        sys.stdout = StdoutTee(sys.stdout)
    if not isinstance(sys.stderr, StdoutTee):
        sys.stderr = StdoutTee(sys.stderr)


def install_excepthook():
    orig = sys.excepthook

    def hook(t, v, tb):
        import io
        import traceback
        write("!", "未处理异常: %r" % (v,))
        buf = io.StringIO()
        traceback.print_exception(t, v, tb, file=buf)
        raw(buf.getvalue())
        orig(t, v, tb)

    sys.excepthook = hook
