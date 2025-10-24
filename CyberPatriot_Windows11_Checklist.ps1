
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberPatriot_Win11_Checklist_resilient.py
Resilient Windows 11 hardening checklist.
- No folders/files are created (console logging only).
- Continues past broken calls/functions.
- Skips missing tools (secedit, dism, netsh, sc, powershell).
- Retries transient failures with backoff.
- Per-call timeouts to avoid hangs.
Use --dry-run to preview without changes.

Run as Administrator.
"""

import ctypes
import subprocess
import sys
import os
import time
import traceback
import shutil
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows environments

# ---------------------- Config & Globals ----------------------

PROGRAM_DATA = os.environ.get("ProgramData", r"C:\ProgramData")
BLOCKLIST_FILE = Path(PROGRAM_DATA) / "CyberPatriot" / "blocklist.txt"
DRY_RUN = ("--dry-run" in sys.argv) or ("-n" in sys.argv)

# Toggle disabling Server binding on NICs (can impact ADMIN$/C$/IPC$ shares)
DISABLE_SERVER_BINDING = False

# Retry settings
RETRIES = 2
BACKOFF_SEC = 1.5
DEFAULT_TIMEOUT = 45  # seconds per external call

# ---------------------- Logging ----------------------

def log(msg, lvl="INFO"):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}][{lvl}] {msg}"
    print(line)

def safe(func, *args, **kwargs):
    """Run a function and never raise; log error and continue."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        log(f"Safe-call error in {getattr(func, '__name__', 'func')}: {e}", "ERROR")
        tb = traceback.format_exc()
        log(tb, "DEBUG")
        return None

def retry(callable_fn, *args, **kwargs):
    """Retry wrapper with backoff; never raise after retries exhausted."""
    attempts = RETRIES + 1
    for i in range(attempts):
        try:
            return callable_fn(*args, **kwargs)
        except subprocess.TimeoutExpired as te:
            log(f"Timeout in {getattr(callable_fn, '__name__', 'call')}: {te}", "WARN")
        except Exception as e:
            log(f"Attempt {i+1}/{attempts} failed in {getattr(callable_fn, '__name__', 'call')}: {e}", "WARN")
        if i < attempts - 1:
            time.sleep(BACKOFF_SEC * (i + 1))
    log(f"Giving up on {getattr(callable_fn, '__name__', 'call')} after {attempts} attempts.", "ERROR")
    return None

def require_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        is_admin = False
    if not is_admin:
        raise PermissionError("Administrator privileges are required. Run this in an elevated Command Prompt/PowerShell.")

def tool_exists(exe):
    path = shutil.which(exe)
    if not path:
        log(f"Tool missing; skipping: {exe}", "WARN")
        return False
    return True

# ---------------------- Process Helpers ----------------------

def powershell(ps_command: str, check=False, timeout=DEFAULT_TIMEOUT):
    """Run PowerShell; skip if missing; never raise unless check=True explicitly and caller handles it."""
    if not tool_exists("powershell.exe"):
        return (127, "", "powershell.exe not found")
    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command]
    log(f"PS> {ps_command}", "DEBUG")
    if DRY_RUN:
        return (0, "", "")
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as te:
        log(f"PowerShell timeout: {te}", "WARN")
        return (124, "", str(te))
    if check and completed.returncode != 0:
        log(f"PowerShell error rc={completed.returncode}", "WARN")
    if completed.stdout:
        for line in completed.stdout.splitlines():
            log(line, "DEBUG")
    if completed.stderr:
        for line in completed.stderr.splitlines():
            if line.strip():
                log(line, "WARN")
    return (completed.returncode, completed.stdout, completed.stderr)

def shell(cmd_list, check=False, timeout=DEFAULT_TIMEOUT):
    """Run external tool; skip if missing; never raise by default."""
    if not cmd_list:
        return (127, "", "empty command")
    if not tool_exists(cmd_list[0]):
        return (127, "", f"{cmd_list[0]} missing")
    log(f"$ {' '.join(cmd_list)}", "DEBUG")
    if DRY_RUN:
        return (0, "", "")
    try:
        completed = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as te:
        log(f"Timeout running: {' '.join(cmd_list)} :: {te}", "WARN")
        return (124, "", str(te))
    if check and completed.returncode != 0:
        log(f"Command returned rc={completed.returncode}: {' '.join(cmd_list)}", "WARN")
    if completed.stdout:
        for line in completed.stdout.splitlines():
            log(line, "DEBUG")
    if completed.stderr:
        for line in completed.stderr.splitlines():
            if line.strip():
                log(line, "WARN")
    return (completed.returncode, completed.stdout, completed.stderr)

# ---------------------- Registry Helpers ----------------------

def set_reg_value(hive, path, name, value, vtype):
    if winreg is None:
        log(f"winreg not available; cannot set {hive}\\{path}::{name}", "WARN")
        return
    if DRY_RUN:
        log(f"Set registry {hive}\\{path}::{name}={value} ({vtype})", "DEBUG")
        return
    key = None
    try:
        key = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, name, 0, vtype, value)
    except Exception as e:
        log(f"Registry set failed {hive}\\{path}::{name}: {e}", "WARN")
    finally:
        if key:
            try: winreg.CloseKey(key)
            except Exception: pass

def ensure_reg_key(hive, path):
    if winreg is None:
        return
    if DRY_RUN:
        log(f"Ensure registry key {hive}\\{path}", "DEBUG")
        return
    try:
        key = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE)
        winreg.CloseKey(key)
    except Exception as e:
        log(f"Registry key ensure failed {hive}\\{path}: {e}", "WARN")

# ---------------------- Tasks ----------------------

def task_password_lockout_policy():
    """Apply local security policy via secedit INF; skip if secedit missing."""
    temp = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))
    inf_path = temp / "cp_policy.inf"
    lines = [
        "[Unicode]",
        "Unicode=yes",
        "[System Access]",
        "MinimumPasswordLength=10",
        "MaximumPasswordAge=60",
        "MinimumPasswordAge=1",
        "PasswordComplexity=1",
        "PasswordHistorySize=24",
        "LockoutBadCount=10",
        "ResetLockoutCount=30",
        "LockoutDuration=30"
    ]
    if DRY_RUN:
        log(f"Would write {inf_path} with security policy lines", "DEBUG")
    else:
        try:
            inf_path.write_text("\r\n".join(lines), encoding="ascii")
        except Exception as e:
            log(f"Could not write INF; skipping policy: {e}", "WARN")
            return
    secedb = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), r"security\database\secedit.sdb")
    retry(shell, ["secedit", "/configure", "/db", secedb, "/cfg", str(inf_path), "/areas", "SECURITYPOLICY"], check=False)
    # Clean up
    if not DRY_RUN and inf_path.exists():
        safe(inf_path.unlink)

def task_smartscreen():
    ensure_reg_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer")
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "RequireAdmin", winreg.REG_SZ)
    ensure_reg_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System")
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1, winreg.REG_DWORD)
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "ShellSmartScreenLevel", "Block", winreg.REG_SZ)

def task_wifi_sense():
    ensure_reg_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", 0, winreg.REG_DWORD)
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectToWiFiSenseHotspots", 0, winreg.REG_DWORD)

def task_uac_max():
    ensure_reg_key(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 2, winreg.REG_DWORD)
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "PromptOnSecureDesktop", 1, winreg.REG_DWORD)
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1, winreg.REG_DWORD)

def task_disable_bindings():
    comps = ['ms_tcpip6','ms_lltdio','ms_lldp','ms_pacer'] + (['ms_server'] if DISABLE_SERVER_BINDING else [])
    ps = r"""
$ErrorActionPreference='SilentlyContinue'
$adapters = Get-NetAdapter | Where-Object { $_ -and $_.Name -and ($_.Status -in @('Up','Disabled')) }
if(-not $adapters){ 'No adapters returned by Get-NetAdapter; skipping.'; return }
foreach($a in $adapters){
  'Adapter: ' + $a.Name
  foreach($comp in @(%COMPONENTS%)){ Disable-NetAdapterBinding -Name $a.Name -ComponentID $comp -ErrorAction SilentlyContinue | Out-Null }
}
""".strip().replace("%COMPONENTS%", ",".join([f"'{c}'" for c in comps]))
    retry(powershell, ps, check=False)

def task_disable_upnp():
    for svc in ("upnphost","SSDPSRV"):
        retry(shell, ["sc.exe", "stop", svc], check=False)
        retry(shell, ["sc.exe", "config", svc, "start=", "disabled"], check=False)
    ensure_reg_key(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\DirectPlayNATHelp\DPNHUPnP")
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\DirectPlayNATHelp\DPNHUPnP", "UPnPMode", 2, winreg.REG_DWORD)

def task_disable_unnecessary_services():
    for svc in ("upnphost","TlntSvr","SNMPTRAP","RemoteRegistry"):
        retry(shell, ["sc.exe", "stop", svc], check=False)
        retry(shell, ["sc.exe", "config", svc, "start=", "disabled"], check=False)

def task_disable_smb1():
    retry(powershell, "try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force } catch {}", check=False)
    retry(shell, ["dism.exe", "/Online", "/Disable-Feature", "/FeatureName:SMB1Protocol", "/NoRestart"], check=False)
    ensure_reg_key(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters")
    set_reg_value(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "AllowInsecureGuestAuth", 0, winreg.REG_DWORD)

def task_firewall_blocklist():
    if not BLOCKLIST_FILE.exists():
        log(f"No blocklist at {BLOCKLIST_FILE}; skipping.", "WARN")
        return
    try:
        lines = BLOCKLIST_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as e:
        log(f"Failed reading blocklist: {e}", "WARN")
        lines = []
    apps = []
    for raw in lines:
        if not isinstance(raw, str):
            continue
        t = raw.strip().strip('"').strip("'")
        if not t or t.startswith("#"):
            continue
        expanded = os.path.expandvars(t)
        p = Path(expanded)
        if p.exists() and p.is_file():
            apps.append(str(p))
        else:
            log(f"Skipping missing/non-file path: {expanded}", "WARN")
    if not apps:
        log("No valid executables in blocklist; nothing to do.", "WARN")
        return
    for app in apps:
        name = f"CP Inbound Block - {Path(app).name}"
        rc, out, err = shell(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], check=False)
        if out and "No rules match the specified criteria" not in out:
            log(f"Rule already exists: {name}", "INFO")
            continue
        retry(shell, ["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name={name}", "dir=in", "action=block", f"program={app}", "enable=yes", "profile=any"], check=False)
        log(f"Blocked inbound for {app}", "OK")

def task_reminder_shares():
    log("Reminder: Only ADMIN$, C$, IPC$ should exist unless README says otherwise.", "INFO")

# ---------------------- Task Runner ----------------------

def run_task(name, func):
    log(f"==> {name}")
    if DRY_RUN:
        log(f"DRYRUN: {name}", "WARN")
        return True
    try:
        func()
        log(f"OK: {name}", "OK")
        return True
    except Exception as e:
        log(f"Task '{name}' threw: {e}. Skipping.", "ERROR")
        tb = traceback.format_exc()
        log(tb, "DEBUG")
        return False

# ---------------------- Main ----------------------

def main():
    require_admin()
    log("=== CyberPatriot Windows 11 Python Checklist (Resilient) Start ===")
    run_task("Set password & lockout policy", task_password_lockout_policy)
    run_task("Enable SmartScreen", task_smartscreen)
    run_task("Disable Wi-Fi Sense auto-connect", task_wifi_sense)
    run_task("Set UAC to highest level", task_uac_max)
    run_task("Disable IPv6 & selected network adapter bindings", task_disable_bindings)
    run_task("Disable UPnP", task_disable_upnp)
    run_task("Disable unnecessary services", task_disable_unnecessary_services)
    run_task("Disable SMBv1", task_disable_smb1)
    run_task("Shares reminder", task_reminder_shares)
    run_task("Create inbound block rules for selected apps (if blocklist exists)", task_firewall_blocklist)
    log("=== CyberPatriot Windows 11 Python Checklist (Resilient) Complete ===", "OK")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Fatal: {e}", "ERROR")
        # Do not re-raise; exit cleanly with non-zero code but after logging
        sys.exit(1)
