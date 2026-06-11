# ============================================================================
# Transportable Detonation Chamber - Makefile
# Cross-platform management for the Vagrant VM and Web UI
#
# macOS/Linux: Use this Makefile directly (make <target>)
# Windows:     Use make.ps1 instead (.\make.ps1 <target>) or install GNU Make 4+
#
# Usage:
#   make help         Show all available targets
#   make install      Install dependencies locally (no VM needed)
#   make run          Run the Web UI locally
#   make up           Build and start the VM
#   make halt         Stop the VM gracefully
#   make destroy      Delete the VM completely
#   make ssh          SSH into the VM
#   make status       Show VM and service status
#   make deploy       Sync webui files to the running VM
#   make open         Open the Web UI in your browser
#   make restart      Restart the Web UI service
#   make logs         Tail Web UI logs from the VM
#   make test         Submit a test sample and verify pipeline
#   make clean        Destroy VM and remove local Vagrant artifacts
#
# Prerequisites:
#   macOS:  Vagrant + QEMU (brew install qemu; vagrant plugin install vagrant-qemu)
#   Linux:  Vagrant + Hyper-V or libvirt
# ============================================================================

.DEFAULT_GOAL := help

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    PLATFORM       := macos
    VAGRANT_FILE   := Vagrantfile.utm
    PROVIDER       := qemu
    OPEN_CMD       := open
else
    PLATFORM       := linux
    VAGRANT_FILE   := Vagrantfile
    PROVIDER       := hyperv
    OPEN_CMD       := xdg-open
endif

VM_IP          ?= 127.0.0.1
WEBUI_URL      := http://$(VM_IP):9000

export VAGRANT_VAGRANTFILE := $(VAGRANT_FILE)

# ============================================================================

.PHONY: help
help:
	@echo ""
	@echo "  Transportable Detonation Chamber"
	@echo "  ================================"
	@echo "  Platform: $(PLATFORM)  Provider: $(PROVIDER)  VM: $(VM_IP)"
	@echo ""
	@echo "  Local (no VM required):"
	@echo "    make install         Install Python venv + dependencies"
	@echo "    make run             Run the Web UI locally (port 9000)"
	@echo "    make uninstall       Remove local venv"
	@echo ""
	@echo "  VM Lifecycle:"
	@echo "    make up              Build and start the VM"
	@echo "    make halt            Stop the VM gracefully"
	@echo "    make destroy         Destroy the VM (irreversible)"
	@echo "    make reload          Restart the VM (halt + up)"
	@echo "    make provision       Re-run all provisioning scripts"
	@echo "    make provision-webui Re-run webui provisioner only"
	@echo ""
	@echo "  Development:"
	@echo "    make deploy          Sync webui files (HTML/CSS/JS) to VM"
	@echo "    make deploy-app      Sync Flask app.py backend to VM"
	@echo "    make restart         Restart the Web UI service"
	@echo "    make deploy-restart  Deploy files then restart (combo)"
	@echo "    make open            Open Web UI in browser"
	@echo "    make logs            Show recent Web UI logs"
	@echo ""
	@echo "  Interaction:"
	@echo "    make ssh             SSH into the VM"
	@echo "    make rdp             Connect via RDP"
	@echo "    make status          Show VM status + service health"
	@echo "    make services        List all service states"
	@echo "    make alerts          Show recent detection alerts"
	@echo "    make test            Submit test sample to verify pipeline"
	@echo "    make submit FILE=x   Submit a file for detonation"
	@echo ""
	@echo "  Cleanup:"
	@echo "    make clean           Destroy VM + remove .vagrant"
	@echo "    make clean-all       Also remove cached Vagrant boxes"
	@echo "    make uninstall       Remove local venv"
	@echo ""
	@echo "  Windows users: use .\\make.ps1 <target> instead"
	@echo ""

# --- Local Install (no VM required) ---

VENV_DIR := webui/.venv
PYTHON   := $(VENV_DIR)/bin/python
PIP      := $(VENV_DIR)/bin/pip

.PHONY: install
install: $(VENV_DIR)/bin/activate
	@echo ""
	@echo "[install] Done. Run 'make run' to start the Web UI locally."
	@echo "  The UI will be available at http://localhost:9000"
	@echo "  Note: Backend services (Rustinel, Fibratus, etc.) won't be available"
	@echo "  locally — the UI will show them as offline. Use 'make up' for full VM."
	@echo ""

$(VENV_DIR)/bin/activate: webui/requirements.txt
	@echo "[install] Creating Python virtual environment..."
	python3 -m venv $(VENV_DIR)
	@echo "[install] Installing dependencies..."
	$(PIP) install --upgrade pip -q
	$(PIP) install -r webui/requirements.txt -q
	@touch $(VENV_DIR)/bin/activate

.PHONY: run
run:
	@if [ ! -f "$(VENV_DIR)/bin/activate" ]; then \
		echo "Error: Virtual environment not found. Run 'make install' first."; \
		exit 1; \
	fi
	@echo "[run] Starting Detonation Chamber Web UI on http://localhost:9000"
	@echo "[run] Press Ctrl+C to stop"
	@echo ""
	cd webui && ../$(PYTHON) app.py

.PHONY: run-debug
run-debug:
	@if [ ! -f "$(VENV_DIR)/bin/activate" ]; then \
		echo "Error: Virtual environment not found. Run 'make install' first."; \
		exit 1; \
	fi
	@echo "[run-debug] Starting in debug mode (auto-reload on file changes)..."
	cd webui && FLASK_DEBUG=1 ../$(PYTHON) app.py

.PHONY: uninstall
uninstall:
	@echo "[uninstall] Removing virtual environment..."
	rm -rf $(VENV_DIR)
	@echo "[uninstall] Done."

# --- VM Lifecycle ---

.PHONY: up
up:
	vagrant up --provider=$(PROVIDER)

.PHONY: halt
halt:
	vagrant halt

.PHONY: destroy
destroy:
	vagrant destroy -f

.PHONY: reload
reload:
	vagrant reload

.PHONY: provision
provision:
	vagrant provision

.PHONY: provision-webui
provision-webui:
	vagrant provision --provision-with webui,configure

# --- Development ---

.PHONY: deploy
deploy:
	@echo "[deploy] Uploading webui files to VM..."
	vagrant upload webui/templates/index.html C:\\DetonationChamberUI\\templates\\index.html
	vagrant upload webui/static/css/style.css C:\\DetonationChamberUI\\static\\css\\style.css
	vagrant upload webui/static/js/app.js C:\\DetonationChamberUI\\static\\js\\app.js
	-vagrant upload webui/static/icon.png C:\\DetonationChamberUI\\static\\icon.png
	@echo "[deploy] Done."

.PHONY: deploy-app
deploy-app:
	vagrant upload webui/app.py C:\\DetonationChamberUI\\app.py
	@echo "[deploy-app] app.py synced."

.PHONY: restart
restart:
	vagrant winrm -c "Get-Process -Name python* -EA SilentlyContinue | Stop-Process -Force; Start-Sleep 2; Start-ScheduledTask -TaskName DetonationChamberUI; Start-Sleep 3; Write-Host ('Web UI: ' + (Get-ScheduledTask -TaskName DetonationChamberUI).State)"

.PHONY: deploy-restart
deploy-restart: deploy restart

.PHONY: open
open:
	$(OPEN_CMD) $(WEBUI_URL)

.PHONY: logs
logs:
	vagrant winrm -c "if (Test-Path C:\\DetonationChamberUI\\webui.log) { Get-Content C:\\DetonationChamberUI\\webui.log -Tail 50 } else { Write-Host 'No log file'; Get-ScheduledTask -TaskName DetonationChamberUI | Format-List State,LastRunTime,LastTaskResult }"

# --- Interaction ---

.PHONY: ssh
ssh:
	vagrant ssh

.PHONY: rdp
rdp:
	vagrant rdp

.PHONY: status
status:
	@echo "--- Vagrant VM ---"
	@vagrant status
	@echo ""
	@echo "--- Web UI Health ---"
	@curl -sf $(WEBUI_URL)/api/status | python3 -m json.tool && echo "Status: ONLINE" || echo "Status: OFFLINE"

.PHONY: services
services:
	vagrant winrm -c "Write-Host ''; Write-Host '  SERVICE               STATE'; Write-Host '  -------               -----'; @('DetonationChamberUI','Rustinel','DetonatorAgent','LitterBox','Fibratus','theZoo-WebUI') | ForEach-Object { $$st = Get-ScheduledTask -TaskName $$_ -EA SilentlyContinue; if($$st){Write-Host ('  '+$$_.PadRight(22)+$$st.State)}else{Write-Host ('  '+$$_.PadRight(22)+'NOT FOUND')}}; Write-Host ('  Sysmon'.PadRight(24)+(Get-Service Sysmon64 -EA SilentlyContinue).Status); Write-Host ''"

.PHONY: alerts
alerts:
	@curl -sf $(WEBUI_URL)/api/alerts | python3 -c "import json,sys;a=json.load(sys.stdin);print(f'Total: {len(a)} alerts');[print(f\"{x.get('timestamp','')} [{x.get('severity','')}] {x.get('rule_name','')}\") for x in a[-10:]]" 2>/dev/null || echo "Failed to fetch alerts (is VM running?)"

.PHONY: test
test:
	@echo "[test] Submitting test sample..."
	@echo "MZ_test_payload_data" > /tmp/_tdc_test_sample.exe
	@curl -sf -X POST $(WEBUI_URL)/api/submit -F "file=@/tmp/_tdc_test_sample.exe" -F "target=agent" | python3 -m json.tool && echo "[test] SUCCESS" || echo "[test] FAILED"
	@rm -f /tmp/_tdc_test_sample.exe

.PHONY: submit
submit:
ifndef FILE
	@echo "Usage: make submit FILE=path/to/sample.exe [TARGET=agent|litterbox|both]"
else
	@curl -sf -X POST $(WEBUI_URL)/api/submit -F "file=@$(FILE)" -F "target=$(or $(TARGET),both)" | python3 -m json.tool
endif

# --- Cleanup ---

.PHONY: clean
clean:
	@echo "[clean] Destroying VM..."
	-vagrant destroy -f
	rm -rf .vagrant
	@echo "[clean] Done."

.PHONY: clean-all
clean-all: clean
	@echo "[clean-all] Removing cached boxes..."
	-vagrant box remove gusztavvargadr/windows-11 --all --force 2>/dev/null
	-vagrant box remove win11-arm --all --force 2>/dev/null
	@echo "[clean-all] Done."
