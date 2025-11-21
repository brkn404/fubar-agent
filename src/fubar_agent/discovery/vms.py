"""Virtual Machine discovery."""

import logging
import subprocess
import os
from typing import List
from pathlib import Path

from .base import DiscoveryResult, ApplicationInfo, ApplicationType

logger = logging.getLogger(__name__)


async def discover_vms() -> DiscoveryResult:
    """Discover virtual machines on the system."""
    result = DiscoveryResult()
    
    # Discover VMware VMs
    try:
        vmware_vms = await _discover_vmware()
        result.applications.extend(vmware_vms)
    except Exception as e:
        logger.warning(f"VMware discovery failed: {e}")
        result.errors.append(f"VMware discovery: {str(e)}")
    
    # Discover KVM/QEMU VMs
    try:
        kvm_vms = await _discover_kvm()
        result.applications.extend(kvm_vms)
    except Exception as e:
        logger.warning(f"KVM discovery failed: {e}")
        result.errors.append(f"KVM discovery: {str(e)}")
    
    # Discover VirtualBox VMs
    try:
        vbox_vms = await _discover_virtualbox()
        result.applications.extend(vbox_vms)
    except Exception as e:
        logger.warning(f"VirtualBox discovery failed: {e}")
        result.errors.append(f"VirtualBox discovery: {str(e)}")
    
    # Discover Hyper-V VMs (Windows)
    try:
        hyperv_vms = await _discover_hyperv()
        result.applications.extend(hyperv_vms)
    except Exception as e:
        logger.warning(f"Hyper-V discovery failed: {e}")
        result.errors.append(f"Hyper-V discovery: {str(e)}")
    
    return result


async def _discover_vmware() -> List[ApplicationInfo]:
    """Discover VMware VMs."""
    vms = []
    
    # Check for VMware Workstation/Server
    vmware_paths = [
        os.path.expanduser("~/Documents/Virtual Machines"),
        "/var/lib/vmware",
        "/vmfs/volumes",  # ESXi
    ]
    
    for vmware_path in vmware_paths:
        if os.path.exists(vmware_path):
            # Look for .vmx files
            for root, dirs, files in os.walk(vmware_path):
                for file in files:
                    if file.endswith(".vmx"):
                        vm_name = os.path.splitext(file)[0]
                        vm_dir = os.path.dirname(os.path.join(root, file))
                        
                        vm = ApplicationInfo(
                            application_type=ApplicationType.VM,
                            application_subtype="vmware",
                            name=vm_name,
                            paths=[vm_dir],
                            metadata={
                                "vmx_file": os.path.join(vm_dir, file),
                                "vm_type": "vmware",
                            },
                            requires_freeze=False,  # VMs can be snapshotted directly
                        )
                        vms.append(vm)
    
    return vms


async def _discover_kvm() -> List[ApplicationInfo]:
    """Discover KVM/QEMU VMs."""
    vms = []
    
    # Check for libvirt VMs
    libvirt_paths = [
        "/var/lib/libvirt/images",
        os.path.expanduser("~/libvirt/images"),
    ]
    
    try:
        # Use virsh to list VMs
        result = subprocess.run(
            ["virsh", "list", "--all", "--name"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for vm_name in result.stdout.strip().split("\n"):
                if vm_name:
                    # Get VM disk paths
                    disk_result = subprocess.run(
                        ["virsh", "domblklist", vm_name],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    disk_paths = []
                    if disk_result.returncode == 0:
                        for line in disk_result.stdout.split("\n")[2:]:  # Skip header
                            parts = line.split()
                            if len(parts) >= 2:
                                disk_paths.append(parts[1])
                    
                    vm = ApplicationInfo(
                        application_type=ApplicationType.VM,
                        application_subtype="kvm",
                        name=vm_name,
                        paths=disk_paths or libvirt_paths,
                        metadata={
                            "vm_type": "kvm",
                            "hypervisor": "qemu",
                        },
                        requires_freeze=False,
                    )
                    vms.append(vm)
    
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # KVM/libvirt not available
        pass
    except Exception as e:
        logger.error(f"KVM discovery error: {e}")
    
    return vms


async def _discover_virtualbox() -> List[ApplicationInfo]:
    """Discover VirtualBox VMs."""
    vms = []
    
    # Check for VirtualBox VMs
    vbox_paths = [
        os.path.expanduser("~/VirtualBox VMs"),
        "/var/lib/vbox",
    ]
    
    try:
        # Use VBoxManage to list VMs
        result = subprocess.run(
            ["VBoxManage", "list", "vms"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if line:
                    # Parse: "VM Name" {uuid}
                    match = line.split('"')
                    if len(match) >= 2:
                        vm_name = match[1]
                        
                        vm = ApplicationInfo(
                            application_type=ApplicationType.VM,
                            application_subtype="virtualbox",
                            name=vm_name,
                            paths=vbox_paths,
                            metadata={
                                "vm_type": "virtualbox",
                            },
                            requires_freeze=False,
                        )
                        vms.append(vm)
    
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # VirtualBox not installed
        pass
    except Exception as e:
        logger.error(f"VirtualBox discovery error: {e}")
    
    return vms


async def _discover_hyperv() -> List[ApplicationInfo]:
    """Discover Hyper-V VMs (Windows)."""
    vms = []
    
    try:
        # Use PowerShell to list Hyper-V VMs
        ps_cmd = "Get-VM | Select-Object Name, Path | ConvertTo-Json"
        result = subprocess.run(
            ["powershell", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            import json
            try:
                vm_data = json.loads(result.stdout)
                if isinstance(vm_data, list):
                    for vm_info in vm_data:
                        vm = ApplicationInfo(
                            application_type=ApplicationType.VM,
                            application_subtype="hyperv",
                            name=vm_info.get("Name", ""),
                            paths=[vm_info.get("Path", "")],
                            metadata={
                                "vm_type": "hyperv",
                            },
                            requires_freeze=False,
                        )
                        vms.append(vm)
            except json.JSONDecodeError:
                pass
    
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Hyper-V not available or not Windows
        pass
    except Exception as e:
        logger.error(f"Hyper-V discovery error: {e}")
    
    return vms

