"""Base classes for application discovery."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class ApplicationType(str, Enum):
    """Application types that can be discovered."""
    DATABASE = "database"
    VM = "vm"
    FILESYSTEM = "filesystem"
    APPLICATION = "application"


@dataclass
class ApplicationInfo:
    """Information about a discovered application."""
    application_type: ApplicationType
    application_subtype: str  # e.g., "oracle", "cache", "iris", "hana", "vmware", "kvm"
    name: str
    version: Optional[str] = None
    primary_key: Optional[str] = None
    paths: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    requires_freeze: bool = False  # Whether this app needs freeze/thaw for consistent snapshots


@dataclass
class DiscoveryResult:
    """Result of discovery operation."""
    applications: List[ApplicationInfo] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

