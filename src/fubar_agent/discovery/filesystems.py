"""Filesystem and disk discovery (based on legacy unixagent)."""

import logging
import subprocess
import os
from typing import List
from pathlib import Path

from .base import DiscoveryResult, ApplicationInfo, ApplicationType

logger = logging.getLogger(__name__)


async def discover_filesystems() -> DiscoveryResult:
    """Discover filesystems and mount points."""
    result = DiscoveryResult()
    
    try:
        # Get mount points
        mounts = _get_mount_points()
        
        for mount in mounts:
            fs = ApplicationInfo(
                application_type=ApplicationType.FILESYSTEM,
                application_subtype=mount.get("fstype", "unknown"),
                name=mount.get("device", "unknown"),
                paths=[mount.get("mountpoint", "")],
                metadata={
                    "device": mount.get("device"),
                    "mountpoint": mount.get("mountpoint"),
                    "fstype": mount.get("fstype"),
                    "options": mount.get("options", ""),
                },
                requires_freeze=False,
            )
            result.applications.append(fs)
    
    except Exception as e:
        logger.error(f"Filesystem discovery error: {e}")
        result.errors.append(f"Filesystem discovery: {str(e)}")
    
    return result


def _get_mount_points() -> List[dict]:
    """Get mount points (cross-platform)."""
    mounts = []
    
    try:
        if os.name == "nt":  # Windows
            # Use wmic or PowerShell
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "name,drivetype,filesystem"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        device = parts[0]
                        fstype = parts[-1] if parts[-1] != "FileSystem" else "NTFS"
                        mounts.append({
                            "device": device,
                            "mountpoint": device,
                            "fstype": fstype,
                        })
        
        else:  # Unix-like
            # Parse /proc/mounts or use mount command
            if os.path.exists("/proc/mounts"):
                with open("/proc/mounts", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 3:
                            device = parts[0]
                            mountpoint = parts[1]
                            fstype = parts[2]
                            options = parts[3] if len(parts) > 3 else ""
                            
                            # Skip virtual filesystems
                            if fstype not in ["proc", "sysfs", "devtmpfs", "tmpfs", "cgroup"]:
                                mounts.append({
                                    "device": device,
                                    "mountpoint": mountpoint,
                                    "fstype": fstype,
                                    "options": options,
                                })
    
    except Exception as e:
        logger.error(f"Error getting mount points: {e}")
    
    return mounts

