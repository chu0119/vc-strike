"""检测/加固参考与 IOC（防御侧资料，来自公开 POC 仓库与 QTR IR 案例）。"""

DETECTION_TEXT = """\
【自查：版本核对】(Build < 25629525 的 9.0 分支即未修复)
    cat /etc/vmware-release
    cat /etc/applmgmt/appliance/version
    修复版本: 9.1.0.0300 / 9.0.2.0100(Build 25629525) / 8.0 U3k / 8.0 U2f

【自查：rsyslog 危险模板与换行穿透】
    grep -nE '%(app-name|hostname)%' /etc/rsyslog.conf /usr/lib/vmware-visl-integration/config/vmware-syslog.conf.template
    grep -n 'EscapeControlCharactersOnReceive' /etc/rsyslog.conf

【入侵痕迹排查（CVE-2026-59310）】
    ls -la /etc/cron.d/ && grep -rl 'syslog.log' /etc/cron.d/ 2>/dev/null
    find / -name '*-syslog.log' -not -path '/var/log/vmware/*' -not -path '/storage/log/vmware/*' 2>/dev/null
    ls -la / | grep -E '\\.\\.|%' ; ls -la /var/log/vmware/ | grep -E '\\.\\.|%|rsyslog[^d]'
    ls -la /opt/vmware/share/htdocs/
    grep -nE '(\\.\\./|/)' /var/log/vmware/messages | head
    # IOC cron 名(QTR IR 案例): vmware-vpxd-stats-* / vmware-perf-collect-* / vmware-perf-sync-*
    # IOC 文件: statsreport 目录异常 jsp（如 vmware-perf-update.jsp）/ sso_domain.txt 等非业务文件

【入侵痕迹排查（CVE-2026-59309）】
    # 监听侧：SASL SRP bind 中 A 字段以 RFC5054 素数 N 前 32 字节开头的报文（mobeta YARA）
    # 审计 SSO 用户: cn=Users 下异常账户与 Administrators 成员变动

【缓解措施（无法立即升级时）】
    1. 514/1514 仅对受管 ESXi 与受信日志转发器开放（ACL/防火墙隔离）
    2. 为 syslog 输入显式绑定 pmrfc3164 解析器，关闭 RFC5424 攻击面:
         parser(name="p3164" type="pmrfc3164")
         input(type="imudp" port="514" ruleset="all" parser="p3164")
    3. omfile 启用 securepath="normal" 与 secpath-drop="replace"（GHSA-xmp9-244p-5ggv）
    4. $EscapeControlCharactersOnReceive on
    5. 收紧选择器: :app-name, startswith, "rsyslog" 改精确匹配 + 来源白名单
    6. 389/636/2020 限制为管理网可达；长期方案升级到修复版本
"""

ABOUT_TEXT = """\
VC-Strike 定位：面向已授权渗透测试 / 漏洞验证 / 防御研究的 vCenter
一体化工具（CVE-2026-59310 + CVE-2026-59309）。

安全边界（有意不实现）：
  - ESXi 勒索 / 虚拟机破坏类操作
  - 隐蔽持久化（systemd/SysV/cron 常驻、开机自启下载器）
  - 免杀 / 检测规避
演示止步于：root RCE、webshell、SSO 目录管理员、凭据提取与回传取证。
"""

REFERENCES = [
    ("POC/EXP（上游）", "https://github.com/ChinaRan0/CVE-2026-59310-POC"),
    ("IR 工件 / IOC", "https://github.com/QUIRSO/QTR"),
    ("技术分析（Mobeta）", "https://mobeta.fr/blog/vcenter-cve-2026-59309-cve-2026-59310/"),
    ("厂商通告 VMSA-2026-0006",
     "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017"),
    ("rsyslog GHSA-xmp9-244p-5ggv",
     "https://github.com/rsyslog/rsyslog/security/advisories/GHSA-xmp9-244p-5ggv"),
    ("vCenter 9.0.2.0100 发行说明",
     "https://techdocs.broadcom.com/us/en/vmware-cis/vcf/vcf-9-0-and-later/9-0/release-notes/patch-releases-9-0-0-x/vsphere/vcenter/vcenter-9-0-2-0100-release-notes.html"),
]
