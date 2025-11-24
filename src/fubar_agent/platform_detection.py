"""
Platform Detection

Detect OS platform and capabilities.
"""

import platform
import socket
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class PlatformInfo:
    """Platform information"""
    platform: str  # 'darwin', 'windows', 'linux'
    hostname: str
    version: str
    architecture: str
    processor: str


def detect_platform() -> PlatformInfo:
    """Detect current platform"""
    system = platform.system().lower()
    
    return PlatformInfo(
        platform=system,
        hostname=socket.gethostname(),
        version=platform.version(),
        architecture=platform.machine(),
        processor=platform.processor(),
    )


def get_platform_capabilities() -> Dict[str, bool]:
    """Get platform-specific capabilities"""
    system = platform.system().lower()
    
    capabilities = {
        "scan": True,
        "backup": True,
        "restore": True,
    }
    
    if system == "darwin":
        # macOS capabilities
        capabilities.update({
            "yara": False,  # Would need to check if installed
            "spotlight": True,
            "timemachine": True,
        })
    elif system == "windows":
        # Windows capabilities
        capabilities.update({
            "yara": False,
            "vss": True,
            "eventlog": True,
        })
    elif system == "linux":
        # Linux capabilities
        capabilities.update({
            "yara": False,  # Would need to check if installed
            "inotify": True,
            "systemd": True,
            "lvm": True,
            "zfs": True,
        })
    
    return capabilities

