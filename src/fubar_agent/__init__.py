"""
Host Agent

Lightweight agent that runs on Mac, Windows, and Linux systems.
Connects to central API server and executes jobs locally.
"""

from .base import BaseAgent
from .platform_detection import detect_platform, PlatformInfo
from .macos import MacOSAgent
from .windows import WindowsAgent
from .linux import LinuxAgent

__all__ = [
    "BaseAgent",
    "detect_platform",
    "PlatformInfo",
    "MacOSAgent",
    "WindowsAgent",
    "LinuxAgent",
]

