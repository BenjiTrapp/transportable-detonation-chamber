#!/usr/bin/env python3
"""Manage the UTM Windows VM's Web UI over WinRM (deploy / restart / logs / services).

The VM pulls files from a short-lived HTTP server on the host (UTM shared
network gateway is 192.168.64.1), mirroring the setup script's approach.
This avoids the ~8191-char WinRM command-line limit that base64 chunking hits.

Usage:
  python3 scripts/deploy-utm.py                 # deploy webui files + app.py
  python3 scripts/deploy-utm.py --restart       # deploy then restart the Web UI
  python3 scripts/deploy-utm.py --action restart # restart only (no deploy)
  python3 scripts/deploy-utm.py --action logs
  python3 scripts/deploy-utm.py --action services
  python3 scripts/deploy-utm.py --vm-ip 192.168.64.5 --vm-user me --vm-pass pw
"""
import argparse
import functools
import glob
import http.server
import os
import socketserver
import sys
import threading
import warnings

warnings.filterwarnings("ignore")

try:
    import winrm
except ImportError:
    sys.exit("pywinrm not installed: pip3 install pywinrm requests-ntlm")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_IP = "192.168.64.1"   # UTM shared-network gateway (host as seen by VM)
PORT = 8766

# repo-relative source -> remote runtime path used by the DetonationChamberUI task
WIKI_FILE = "webui/static/wiki.html"
FILES = {
    "webui/app.py": r"C:\DetonationChamberUI\app.py",
    "webui/memory_evidence.py": r"C:\DetonationChamberUI\memory_evidence.py",
    "webui/syscall_baseline.py": r"C:\DetonationChamberUI\syscall_baseline.py",
    "webui/syscall_scan.py": r"C:\DetonationChamberUI\syscall_scan.py",
    "webui/syscall_rules.py": r"C:\DetonationChamberUI\syscall_rules.py",
    "webui/syscall_signatures.json": r"C:\DetonationChamberUI\syscall_signatures.json",
    "webui/win32_to_nt.py": r"C:\DetonationChamberUI\win32_to_nt.py",
    "webui/win32_to_nt.json": r"C:\DetonationChamberUI\win32_to_nt.json",
    "webui/minidump_analysis.py": r"C:\DetonationChamberUI\minidump_analysis.py",
    "webui/pipe_analysis.py": r"C:\DetonationChamberUI\pipe_analysis.py",
    "webui/pipe_signatures.json": r"C:\DetonationChamberUI\pipe_signatures.json",
    "webui/pipe_backends.py": r"C:\DetonationChamberUI\pipe_backends.py",
    "webui/pipe_proxy.py": r"C:\DetonationChamberUI\pipe_proxy.py",
    "webui/log_search.py": r"C:\DetonationChamberUI\log_search.py",
    "webui/log_store.py": r"C:\DetonationChamberUI\log_store.py",
    "webui/dashboards.py": r"C:\DetonationChamberUI\dashboards.py",
    "webui/rizin_sessions.py": r"C:\DetonationChamberUI\rizin_sessions.py",
    "webui/tool_updates.py": r"C:\DetonationChamberUI\tool_updates.py",
    "webui/firewall.py": r"C:\DetonationChamberUI\firewall.py",
    "webui/firewall_fetch.py": r"C:\DetonationChamberUI\firewall_fetch.py",
    "webui/firewall_rules.py": r"C:\DetonationChamberUI\firewall_rules.py",
    "webui/firewall_rules.ps1": r"C:\DetonationChamberUI\firewall_rules.ps1",
    "webui/firewall_store.py": r"C:\DetonationChamberUI\firewall_store.py",
    "webui/geoip.py": r"C:\DetonationChamberUI\geoip.py",
    "webui/static/js/app.js": r"C:\DetonationChamberUI\static\js\app.js",
    "webui/static/css/style.css": r"C:\DetonationChamberUI\static\css\style.css",
    "webui/static/css/theme-layout.css": r"C:\DetonationChamberUI\static\css\theme-layout.css",
    "webui/static/css/theme-cyberpunk.css": r"C:\DetonationChamberUI\static\css\theme-cyberpunk.css",
    "webui/templates/index.html": r"C:\DetonationChamberUI\templates\index.html",
    "webui/static/icon.png": r"C:\DetonationChamberUI\static\icon.png",
    # The offline wiki, built on the host by `make docs` and git-ignored: the VM
    # has no network, so this one file is the documentation there. A fresh clone
    # has none, and the loop below skips what is not on disk.
    WIKI_FILE: r"C:\DetonationChamberUI\static\wiki.html",
}

# Data directories, shipped whole: the offline geo index (webui/data) and the world map (webui/static/data)
DATA_DIRS = {
    "webui/data": r"C:\DetonationChamberUI\data",
    "webui/static/data": r"C:\DetonationChamberUI\static\data",
}
DATA_FILES = {
    f"{local}/{name}": remote + "\\" + name
    for local, remote in DATA_DIRS.items()
    if os.path.isdir(os.path.join(REPO, local))
    for name in sorted(os.listdir(os.path.join(REPO, local)))
    if not name.startswith(".") and os.path.isfile(os.path.join(REPO, local, name))
}

# The install scripts the tool updates re-run, kept next to the provisioning copy
SCRIPTS_REMOTE_DIR = r"C:\tdc\scripts"
# (plus configure-logging.ps1, which an existing VM runs once to turn on the logs of the LOGS and FIREWALL tabs,
# and tdc-unisolate.ps1, the way out of ISOLATED when the web UI cannot be reached)
SCRIPT_FILES = {
    f"scripts/{os.path.basename(path)}": SCRIPTS_REMOTE_DIR + "\\" + os.path.basename(path)
    for path in sorted(glob.glob(os.path.join(REPO, "scripts", "install-*.ps1"))
                       + [os.path.join(REPO, "scripts", "configure-logging.ps1"),
                          os.path.join(REPO, "scripts", "tdc-unisolate.ps1")])
}

RESTART_PS = (
    "Get-Process -Name python* -EA SilentlyContinue | Stop-Process -Force;"
    "Start-Sleep 2; Start-ScheduledTask -TaskName DetonationChamberUI;"
    "Start-Sleep 4; (Get-ScheduledTask -TaskName DetonationChamberUI).State"
)

LOGS_PS = (
    "if (Test-Path C:\\DetonationChamberUI\\webui.log) "
    "{ Get-Content C:\\DetonationChamberUI\\webui.log -Tail 50 } "
    "else { Write-Host 'No log file'; "
    "Get-ScheduledTask -TaskName DetonationChamberUI | Format-List State,LastRunTime,LastTaskResult }"
)

SERVICES_PS = (
    "Write-Host ''; Write-Host '  SERVICE               STATE'; "
    "Write-Host '  -------               -----'; "
    "@('DetonationChamberUI','Rustinel','DetonatorAgent','LitterBox','Fibratus','theZoo-WebUI') | "
    "ForEach-Object { $st = Get-ScheduledTask -TaskName $_ -EA SilentlyContinue; "
    "if($st){Write-Host ('  '+$_.PadRight(22)+$st.State)}else{Write-Host ('  '+$_.PadRight(22)+'NOT FOUND')}}; "
    "$sysmon = Get-Service Sysmon64 -EA SilentlyContinue; "
    "if(-not $sysmon){$sysmon = Get-Service Sysmon64a -EA SilentlyContinue}; "
    "Write-Host ('  Sysmon'.PadRight(24)+$(if($sysmon){$sysmon.Status}else{'NOT FOUND'})); Write-Host ''"
)


def make_session(args):
    return winrm.Session(
        f"http://{args.vm_ip}:5985/wsman",
        auth=(args.vm_user, args.vm_pass),
        transport="ntlm",
    )


def run_ps(sess, ps, label=""):
    r = sess.run_ps(ps)
    out = r.std_out.decode(errors="replace").strip()
    err = r.std_err.decode(errors="replace").strip()
    if r.status_code != 0 and err:
        print(f"[!] {label} error: {err[:400]}")
    return out


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    # Assigning log_message on a functools.partial never reached the handler
    # instances, so every request was still logged.
    def log_message(self, *args, **kwargs):
        pass


class _ReusableServer(socketserver.TCPServer):
    # Re-running within the TIME_WAIT window otherwise fails to bind.
    allow_reuse_address = True


def serve():
    """Serve the repository to the VM for the duration of a deploy.

    Bound to the UTM host-only address rather than 0.0.0.0, so the repository
    (including .git) is not exposed on every network interface.
    """
    handler = functools.partial(_QuietHandler, directory=REPO)
    try:
        httpd = _ReusableServer((HOST_IP, PORT), handler)
    except OSError:
        # Host address not present (e.g. different network setup): fall back.
        httpd = _ReusableServer(("0.0.0.0", PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def stop(httpd):
    httpd.shutdown()
    httpd.server_close()


def do_deploy(sess, args):
    httpd = serve()
    print(f"[*] Host HTTP server on :{PORT}, deploying to {args.vm_ip} ...")
    try:
        dirs = ",".join(f'"{d}"' for d in [SCRIPTS_REMOTE_DIR, *DATA_DIRS.values()])
        ps = f'New-Item -ItemType Directory -Path {dirs} -Force | Out-Null'
        run_ps(sess, ps, label="directories")
        for local, remote in {**FILES, **DATA_FILES, **SCRIPT_FILES}.items():
            if not os.path.isfile(os.path.join(REPO, local)):
                hint = " - build the wiki with: make docs" if local == WIKI_FILE else ""
                print(f"  [-] skip {local} (not found){hint}")
                continue
            url = f"http://{HOST_IP}:{PORT}/{local}"
            # The copy keeps the date of the file it is a copy of - every file,
            # not only the wiki: a copy that carries its original's date tells
            # the truth about what is on the VM, and a download would otherwise
            # stamp all of them with the deploy's clock. One statement in the
            # same remote command; `vagrant upload` and `Copy-Item -ToSession`
            # (the other two deploy paths) have no equivalent, which is why the
            # help says the wiki's date is the date of the copy here, that a
            # deploy *can* renew it, and that the build stamp is in the wiki's
            # own footer.
            mtime = int(os.path.getmtime(os.path.join(REPO, local)))
            ps = (
                '$ErrorActionPreference="Stop"; $ProgressPreference="SilentlyContinue";'
                f'Invoke-WebRequest -Uri "{url}" -OutFile "{remote}" -UseBasicParsing;'
                f'(Get-Item "{remote}").LastWriteTimeUtc = '
                f'[datetimeoffset]::FromUnixTimeSeconds({mtime}).UtcDateTime;'
                f'(Get-Item "{remote}").Length'
            )
            out = run_ps(sess, ps, label=local)
            print(f"  [+] {local} -> {remote} ({out} bytes)")
    finally:
        stop(httpd)


def do_install(sess, args):
    """Push prebuilt artifacts, then run an installer script inside the VM.

    The VM pulls both from the host HTTP server, so this works the same way
    `do_deploy` does and stays clear of the WinRM command-length limit.
    """
    script = args.install
    local_script = os.path.join(REPO, "scripts", script)
    if not os.path.isfile(local_script):
        print(f"[!] No such script: scripts/{script}")
        return

    httpd = serve()
    try:
        # Host-built binaries first: install-aether.ps1 prefers them over
        # building inside the VM.
        prebuilt_dir = os.path.join(REPO, "prebuilt")
        if os.path.isdir(prebuilt_dir):
            print("[*] Pushing prebuilt/ ...")
            run_ps(sess, 'New-Item -ItemType Directory -Force -Path '
                         'C:\\vagrant\\prebuilt,C:\\vagrant\\prebuilt\\rules | Out-Null')
            for root, _dirs, files in os.walk(prebuilt_dir):
                for name in files:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, REPO).replace(os.sep, "/")
                    remote = "C:\\vagrant\\" + os.path.relpath(full, REPO).replace("/", "\\")
                    ps = (
                        '$ErrorActionPreference="Stop";'
                        f'Invoke-WebRequest -Uri "http://{HOST_IP}:{PORT}/{rel}" '
                        f'-OutFile "{remote}" -UseBasicParsing;'
                        f'(Get-Item "{remote}").Length'
                    )
                    out = run_ps(sess, ps, label=rel)
                    print(f"  [+] {rel} ({out} bytes)")

        print(f"[*] Running scripts/{script} in the VM ...")
        remote_script = f"C:\\Windows\\Temp\\{script}"
        run_ps(sess, (
            '$ErrorActionPreference="Stop";'
            f'Invoke-WebRequest -Uri "http://{HOST_IP}:{PORT}/scripts/{script}" '
            f'-OutFile "{remote_script}" -UseBasicParsing'
        ), label=script)

        # Installer scripts are chatty and can run for minutes; stream whatever
        # they printed once they finish.
        out = run_ps(sess, f'& powershell -ExecutionPolicy Bypass -File "{remote_script}"',
                     label=script)
        for line in out.splitlines():
            print(f"    {line}")
    finally:
        stop(httpd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm-ip", default="192.168.64.4")
    ap.add_argument("--vm-user", default="vagrant")
    ap.add_argument("--vm-pass", default="vagrant")
    ap.add_argument("--restart", action="store_true",
                    help="deploy, then restart the Web UI")
    ap.add_argument("--install", metavar="SCRIPT",
                    help="run scripts/SCRIPT in the VM (e.g. install-aether.ps1), "
                         "pushing prebuilt/ first")
    ap.add_argument("--action", choices=["deploy", "restart", "logs", "services"],
                    default="deploy",
                    help="restart/logs/services skip the file deploy")
    args = ap.parse_args()

    sess = make_session(args)

    if args.install:
        do_install(sess, args)
        print("[+] Done.")
        return

    if args.action == "restart":
        print("[*] Restarting DetonationChamberUI ...")
        print("    Task state:", run_ps(sess, RESTART_PS, "restart"))
        return
    if args.action == "logs":
        print(run_ps(sess, LOGS_PS, "logs"))
        return
    if args.action == "services":
        print(run_ps(sess, SERVICES_PS, "services"))
        return

    # default action: deploy (optionally followed by restart)
    do_deploy(sess, args)
    if args.restart:
        print("[*] Restarting DetonationChamberUI ...")
        print("    Task state:", run_ps(sess, RESTART_PS, "restart"))
    print("[+] Done.")


if __name__ == "__main__":
    main()
