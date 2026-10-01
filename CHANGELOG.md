# Changelog

本项目的显著变更记录。格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [1.1.1] - 2026-10-01

### Fixed
- C2 终端交互重做（对齐原始 POC 的裸 shell 行为）：
  - 会话改用**持续读取线程**，输出以原始流实时上屏，不再按"静默窗口"切块
    （修复命令/提示符显示断断续续、交错）
  - 剥离 ANSI 转义序列（修复带颜色 PS1 的目标显示 `[1;31m` 乱码）
  - 取消本地命令回显（远端 PTY 会回显，此前双份显示）
  - 上传/下载期间自动暂停实时流，避免抢读（md5 校验不再丢输出）

## [1.1.0] - 2026-10-01

### Added
- Windows 预编译版本（Releases）：VC-Strike.exe（CLI+GUI）与
  VC-Strike-GUI.exe（纯 GUI），附 SHA256 校验。
- 全局快捷键：F2 写入验证 / F3 SRP 探测 / F4 启动监听 / F5 批量指纹 /
  F6 生成清理方案 / Esc 取消 RCE 轮询 / Ctrl+L、Ctrl+S 日志。
- 快捷动作：② 页"一键取证"（系统信息→机器账户→SSO 域名）、
  ③ 页"一键评估"（探测→绕过→枚举用户/管理员组）。

### Changed
- UI 全面重做为浅色专业主题（原生控件、白底高对比），经 4 轮截图审查循环。
- **DPI 自适应**：启动时检测系统缩放，窗口/行高/间距/换行宽度按系数缩放并
  clamp 到屏幕；修复高 DPI 下文字发糊。
- **字体锁定**：全部 Tk 命名字体与默认字体统一锁死单一字族
  （Microsoft YaHei UI），日志/输出区不再出现中英文粗细混排；
  Consolas 仅保留在 C2 交互终端。
- 目标表端口列头语义化（"443 Web"/"5480 VAMI"/…）并支持横向滚动；
  清理中心增加动作登记表与空态提示。

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
