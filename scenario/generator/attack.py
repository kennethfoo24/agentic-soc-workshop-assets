"""The planted APT29-style intrusion and the benign look-alikes that trip the same rules."""
from __future__ import annotations

from datetime import datetime, timedelta

from . import ecs, payload
from .ecs import Doc
from .org import (
    ADMIN_FP_HOST,
    ADMIN_FP_USER,
    EMAIL_DOMAIN,
    LATERAL_TARGET,
    STOLEN_ACCOUNT,
    USER_BY_HOST,
    VICTIM_HOST,
    VICTIM_USER,
    host,
)

INITIAL_ACCESS_AT = timedelta(hours=-50)
HANDS_ON_AT = timedelta(hours=-3)

_SYS32 = "C:\\Windows\\System32\\"
_PS_EXE = _SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
_PERSISTENCE_SCRIPT = f"C:\\Users\\{VICTIM_USER}\\AppData\\Local\\Microsoft\\EdgeUpdate\\update.ps1"

_INVENTORY_SCRIPT = (
    "Get-CimInstance Win32_ComputerSystem | Select-Object Name,Manufacturer,Model | "
    "Export-Csv -Path C:\\ProgramData\\Elastibank\\inventory.csv -NoTypeInformation"
)


def _proc(at, h, user, exe, cmdline, parent, parent_cmd="", pid=4120, ppid=3980) -> Doc:
    name = exe.rsplit("\\", 1)[-1]
    return ecs.process_start(at, host(h), user, name, exe, cmdline, parent, parent_cmd, pid=pid, ppid=ppid)


def build_attack_chain(anchor: datetime) -> list[Doc]:
    t0 = anchor + INITIAL_ACCESS_AT
    hands_on = anchor + HANDS_ON_AT
    docs: list[Doc] = []

    docs.append(
        ecs.email_received(
            t0,
            f"{VICTIM_USER}@{EMAIL_DOMAIN}",
            "invoices@northgate-payments.example",
            "Q3 invoice attached - action required",
            "Invoice_Q3.iso",
            "delivered",
        )
    )

    # LNK on the mounted ISO starts stage 1 (-enc, UTF-16LE); stage 1 launches stage 2 (UTF-8 inner base64).
    stage2 = payload.stage2_command(payload.STAGE2_SCRIPT)
    launcher = "$c = @'\n" + stage2 + "\n'@\ncmd.exe /c $c\n"
    stage1 = payload.stage1_command(launcher)
    docs.append(
        _proc(t0 + timedelta(minutes=4), VICTIM_HOST, VICTIM_USER, _PS_EXE, stage1,
              "explorer.exe", "C:\\Windows\\Explorer.EXE", pid=6112, ppid=4012)
    )
    docs.append(
        _proc(t0 + timedelta(minutes=5), VICTIM_HOST, VICTIM_USER, _PS_EXE, stage2,
              "powershell.exe", stage1, pid=6240, ppid=6112)
    )
    docs.append(
        _proc(t0 + timedelta(minutes=6), VICTIM_HOST, VICTIM_USER, _SYS32 + "schtasks.exe",
              "schtasks.exe /create /tn MicrosoftEdgeUpdateTaskCore /sc hourly /f /tr "
              f'"powershell.exe -nop -w hidden -File {_PERSISTENCE_SCRIPT}"',
              "powershell.exe", pid=6301, ppid=6240)
    )

    docs.append(
        _proc(hands_on, VICTIM_HOST, VICTIM_USER, _SYS32 + "rundll32.exe",
              "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 724 C:\\Users\\Public\\dbg.dmp full",
              "powershell.exe", pid=7010, ppid=6988)
    )
    docs.append(
        _proc(hands_on + timedelta(minutes=10), VICTIM_HOST, VICTIM_USER, _SYS32 + "nltest.exe",
              "nltest.exe /domain_trusts", "cmd.exe", pid=7144, ppid=7102)
    )
    docs.append(
        _proc(hands_on + timedelta(minutes=11), VICTIM_HOST, VICTIM_USER, _SYS32 + "net.exe",
              'net.exe group "domain admins" /domain', "cmd.exe", pid=7160, ppid=7102)
    )

    lateral_at = hands_on + timedelta(minutes=30)
    docs.append(ecs.auth_logon(lateral_at, host(LATERAL_TARGET), STOLEN_ACCOUNT, host(VICTIM_HOST).ip, "Network"))
    docs.append(
        _proc(lateral_at + timedelta(minutes=1), LATERAL_TARGET, STOLEN_ACCOUNT, _SYS32 + "cmd.exe",
              "cmd.exe /c whoami & ipconfig", "WmiPrvSE.exe", pid=3320, ppid=912)
    )
    return docs


def build_false_positives(anchor: datetime) -> list[Doc]:
    docs: list[Doc] = []

    # IT inventory script run by Configuration Manager every 4h (-enc).
    inventory = payload.stage1_command(_INVENTORY_SCRIPT)
    for k in range(1, 13):
        docs.append(
            _proc(anchor - timedelta(hours=4 * k), ADMIN_FP_HOST, ADMIN_FP_USER, _PS_EXE, inventory,
                  "ccmexec.exe", "C:\\Windows\\CCM\\CcmExec.exe", pid=5000 + k, ppid=1884)
        )

    # Software-deployment tasks pushed to ten workstations.
    for i in range(10):
        docs.append(
            _proc(anchor - timedelta(hours=30) + timedelta(hours=2 * i), f"WS-OPS-{i + 1:03d}", "SYSTEM",
                  _SYS32 + "schtasks.exe",
                  'schtasks.exe /create /tn "Elastibank\\AgentUpdate" '
                  "/xml C:\\Windows\\CCM\\SystemTemp\\agentupdate.xml /f",
                  "ccmexec.exe", "C:\\Windows\\CCM\\CcmExec.exe", pid=5200 + i, ppid=1884)
        )

    # Routine group audits from the IT desk.
    it_user = USER_BY_HOST["WS-IT-001"]
    for hours in (30, 18, 6):
        docs.append(
            _proc(anchor - timedelta(hours=hours), "WS-IT-001", it_user, _SYS32 + "net.exe",
                  'net.exe group "domain admins" /domain', "cmd.exe", pid=5400 + hours, ppid=5301)
        )

    # Known vendor sends statements as ISO files.
    for hours in (26, 9):
        docs.append(
            ecs.email_received(
                anchor - timedelta(hours=hours),
                f"procurement@{EMAIL_DOMAIN}",
                "vendor@contoso.example",
                "Monthly statement",
                f"Statement_{hours}h.iso",
                "delivered",
            )
        )

    # Backup software authenticates to the core banking DB every three hours.
    backup_src = host("WS-IT-002").ip
    for k in range(15):
        docs.append(
            ecs.auth_logon(anchor - timedelta(minutes=15) - timedelta(hours=3 * k), host(LATERAL_TARGET),
                           "svc_backup", backup_src, "Network")
        )
    return docs
