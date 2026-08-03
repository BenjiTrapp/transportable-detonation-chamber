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
FILES = {
    "webui/app.py": r"C:\DetonationChamberUI\app.py",
    "webui/static/js/app.js": r"C:\DetonationChamberUI\static\js\app.js",
    "webui/static/css/style.css": r"C:\DetonationChamberUI\static\css\style.css",
    "webui/templates/index.html": r"C:\DetonationChamberUI\templates\index.html",
    "webui/static/icon.png": r"C:\DetonationChamberUI\static\icon.png",
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


def serve():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=REPO)
    handler.log_message = lambda *a, **k: None
    httpd = socketserver.TCPServer(("0.0.0.0", PORT), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def do_deploy(sess, args):
    httpd = serve()
    print(f"[*] Host HTTP server on :{PORT}, deploying to {args.vm_ip} ...")
    try:
        for local, remote in FILES.items():
            if not os.path.isfile(os.path.join(REPO, local)):
                print(f"  [-] skip {local} (not found)")
                continue
            url = f"http://{HOST_IP}:{PORT}/{local}"
            ps = (
                '$ErrorActionPreference="Stop";'
                f'Invoke-WebRequest -Uri "{url}" -OutFile "{remote}" -UseBasicParsing;'
                f'(Get-Item "{remote}").Length'
            )
            out = run_ps(sess, ps, label=local)
            print(f"  [+] {local} -> {remote} ({out} bytes)")
    finally:
        httpd.shutdown()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm-ip", default="192.168.64.4")
    ap.add_argument("--vm-user", default="vagrant")
    ap.add_argument("--vm-pass", default="vagrant")
    ap.add_argument("--restart", action="store_true",
                    help="deploy, then restart the Web UI")
    ap.add_argument("--action", choices=["deploy", "restart", "logs", "services"],
                    default="deploy",
                    help="restart/logs/services skip the file deploy")
    args = ap.parse_args()

    sess = make_session(args)

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
