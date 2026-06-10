# -*- mode: ruby -*-
# vi: set ft=ruby :

# Transportable Detonation Chamber
# Windows 11 VM with Detonator + DetonatorAgent + Fibratus + Rustinel + LitterBox
#
# Prerequisites:
#   - Vagrant >= 2.4
#   - Hyper-V enabled (run as Administrator)
#
# Usage:
#   vagrant up --provider=hyperv
#   vagrant rdp              # Connect via RDP
#   vagrant ssh              # SSH into the VM (if OpenSSH installed)
#   vagrant halt             # Stop the VM
#   vagrant destroy          # Delete the VM

Vagrant.configure("2") do |config|
  config.vm.box = "gusztavvargadr/windows-11"
  config.vm.hostname = "detonation-chamber"

  # Communicator settings for Windows
  config.vm.communicator = "winrm"
  config.winrm.username = "vagrant"
  config.winrm.password = "vagrant"
  config.winrm.timeout = 1800
  config.winrm.retry_limit = 30

  # Network: expose Detonator Web UI and API, DetonatorAgent API, LitterBox
  config.vm.network "forwarded_port", guest: 5000, host: 5000  # Detonator Web UI
  config.vm.network "forwarded_port", guest: 8000, host: 8000  # Detonator REST API
  config.vm.network "forwarded_port", guest: 8080, host: 8080  # DetonatorAgent API
  config.vm.network "forwarded_port", guest: 1337, host: 1337  # LitterBox Web UI
  config.vm.network "forwarded_port", guest: 9000, host: 9000  # Unified Web UI
  config.vm.network "forwarded_port", guest: 8888, host: 8888  # theZoo-WebUI

  # Hyper-V provider settings
  config.vm.provider "hyperv" do |hv|
    hv.vmname = "DetonationChamber"
    hv.memory = 4096
    hv.cpus = 4
    hv.maxmemory = 8192
    hv.enable_virtualization_extensions = false
    hv.linked_clone = true
    hv.auto_start_action = "Nothing"
    hv.auto_stop_action = "ShutDown"
  end

  # Increase boot timeout for Windows
  config.vm.boot_timeout = 900

  # Disable default synced folder (Hyper-V doesn't support vboxsf)
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # Copy config and webui into the VM via file provisioners (no SMB needed)
  config.vm.provision "file", source: "config", destination: "C:\\vagrant_config"
  config.vm.provision "file", source: "webui", destination: "C:\\vagrant\\webui"
  config.vm.provision "file", source: "rules", destination: "C:\\vagrant\\rules"

  # Provisioning: run scripts in order
  config.vm.provision "prerequisites",
    type: "shell",
    path: "scripts/install-prerequisites.ps1",
    privileged: true

  config.vm.provision "brave",
    type: "shell",
    path: "scripts/install-brave.ps1",
    privileged: true

  config.vm.provision "fibratus",
    type: "shell",
    path: "scripts/install-fibratus.ps1",
    privileged: true

  config.vm.provision "sysmon",
    type: "shell",
    path: "scripts/install-sysmon.ps1",
    privileged: true

  config.vm.provision "rustinel",
    type: "shell",
    path: "scripts/install-rustinel.ps1",
    privileged: true

  config.vm.provision "detection-rules",
    type: "shell",
    path: "scripts/install-detection-rules.ps1",
    privileged: true

  config.vm.provision "detonator",
    type: "shell",
    path: "scripts/install-detonator.ps1",
    privileged: true

  config.vm.provision "litterbox",
    type: "shell",
    path: "scripts/install-litterbox.ps1",
    privileged: true

  config.vm.provision "thezoo",
    type: "shell",
    path: "scripts/install-thezoo.ps1",
    privileged: true

  config.vm.provision "webui",
    type: "shell",
    path: "scripts/install-webui.ps1",
    privileged: true

  config.vm.provision "configure",
    type: "shell",
    path: "scripts/configure-services.ps1",
    privileged: true,
    run: "always"
end
