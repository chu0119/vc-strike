# Changelog

本项目的显著变更记录。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-10-01

### 首个公开版本

- **CVE-2026-59310**（vCenter syslog 路径穿越 → root RCE）：
  非破坏写入验证、任意文件写（APP-NAME / HOSTNAME 双向量、报文预览）、
  RCE + VAMI(5480) HTTP 回显、RCE 落盘、反弹 shell、JSP WebShell 植入。
- **CVE-2026-59309**（vmdird SRP 认证绕过）：SRP 机制探测、
  A=N 认证绕过（M1/M2 与 AES-128-OFB+HMAC-SHA1 安全层逐字段对照
  cyrus-sasl 2.1.26 srp.c）、SSO 用户/管理员组枚举、创建 SSO 管理员、
  重置账户密码、LDAP 查询控制台。
- **C2**：多端口监听、多会话管理、交互直通、exec 回显、
  上传/下载（shell 通道 base64 分块）；CLI REPL 与 GUI 会话表双入口。
- **指纹**：批量端口/版本/rootDSE 探测，CSV 导出（仅探测不利用）。
- **后渗透**：系统信息、机器账户凭据提取、SSO 域名、
  网络/服务/计划任务盘点、59310 入侵痕迹快扫。
- **清理中心 / 检测加固** 页。
- 纯 Python AES-128（FIPS-197 向量校验）；BER/LDAP 自实现；零第三方依赖。
- GUI（tkinter 深色）与 CLI 利用功能等价（清理中心/检测加固为 GUI 专属）；
  CI（Ubuntu，selftest + unittest）。
