"""
Application Discovery Module

Discovers databases, VMs, and other applications on remote hosts.
Based on legacy code patterns from ecxcache, ecxiris, hanaagent, oracletools.
"""

from .base import DiscoveryResult, ApplicationInfo
from .databases import discover_databases
from .vms import discover_vms
from .filesystems import discover_filesystems

__all__ = [
    "DiscoveryResult",
    "ApplicationInfo",
    "discover_databases",
    "discover_vms",
    "discover_filesystems",
]

