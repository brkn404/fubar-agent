"""Database discovery (Oracle, Cache/Iris, HANA)."""

import logging
import subprocess
import re
import os
from typing import List, Optional
from pathlib import Path

from .base import DiscoveryResult, ApplicationInfo, ApplicationType

logger = logging.getLogger(__name__)


async def discover_databases() -> DiscoveryResult:
    """Discover all databases on the system."""
    result = DiscoveryResult()
    
    # Discover Oracle
    try:
        oracle_apps = await _discover_oracle()
        result.applications.extend(oracle_apps)
    except Exception as e:
        logger.warning(f"Oracle discovery failed: {e}")
        result.errors.append(f"Oracle discovery: {str(e)}")
    
    # Discover Cache/Iris
    try:
        cache_apps = await _discover_cache_iris()
        result.applications.extend(cache_apps)
    except Exception as e:
        logger.warning(f"Cache/Iris discovery failed: {e}")
        result.errors.append(f"Cache/Iris discovery: {str(e)}")
    
    # Discover HANA
    try:
        hana_apps = await _discover_hana()
        result.applications.extend(hana_apps)
    except Exception as e:
        logger.warning(f"HANA discovery failed: {e}")
        result.errors.append(f"HANA discovery: {str(e)}")
    
    return result


async def _discover_oracle() -> List[ApplicationInfo]:
    """Discover Oracle instances (based on legacy oracletools)."""
    apps = []
    
    try:
        # Check for Oracle installation
        ora_homes = _find_oracle_homes()
        if not ora_homes:
            return apps
        
        for ora_home in ora_homes:
            # Get Oracle version
            version = _get_oracle_version(ora_home)
            
            # Discover databases
            databases = _discover_oracle_databases(ora_home)
            
            for db in databases:
                app = ApplicationInfo(
                    application_type=ApplicationType.DATABASE,
                    application_subtype="oracle",
                    name=db["name"],
                    version=version,
                    primary_key=db.get("primary_key"),
                    paths=db.get("paths", []),
                    metadata={
                        "ora_home": ora_home,
                        "sid": db.get("sid"),
                        "databases": db.get("databases", []),
                        "control_files": db.get("control_files", []),
                        "datafiles": db.get("datafiles", []),
                        "logfiles": db.get("logfiles", []),
                    },
                    requires_freeze=True,  # Oracle needs RMAN freeze
                )
                apps.append(app)
    
    except Exception as e:
        logger.error(f"Oracle discovery error: {e}")
    
    return apps


def _find_oracle_homes() -> List[str]:
    """Find Oracle installation homes."""
    homes = []
    
    # Check common Oracle home locations
    common_paths = [
        "/opt/oracle",
        "/u01/app/oracle",
        "/oracle",
        os.path.expanduser("~/oracle"),
    ]
    
    # Also check ORACLE_HOME env var
    if os.environ.get("ORACLE_HOME"):
        common_paths.insert(0, os.environ["ORACLE_HOME"])
    
    for path in common_paths:
        if os.path.exists(path) and os.path.isdir(path):
            # Look for bin/oracle or bin/sqlplus
            if os.path.exists(os.path.join(path, "bin", "oracle")) or \
               os.path.exists(os.path.join(path, "bin", "sqlplus")):
                homes.append(path)
    
    return homes


def _get_oracle_version(ora_home: str) -> Optional[str]:
    """Get Oracle version."""
    try:
        sqlplus = os.path.join(ora_home, "bin", "sqlplus")
        if os.path.exists(sqlplus):
            result = subprocess.run(
                [sqlplus, "-version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Parse version from output
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", result.stdout)
                if match:
                    return match.group(1)
    except Exception:
        pass
    
    return None


def _discover_oracle_databases(ora_home: str) -> List[dict]:
    """Discover Oracle databases."""
    databases = []
    
    try:
        # Check /etc/oratab for database entries
        oratab_path = "/etc/oratab"
        if not os.path.exists(oratab_path):
            return databases
        
        with open(oratab_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split(":")
                if len(parts) >= 2:
                    sid = parts[0]
                    ora_home_path = parts[1]
                    
                    # Get database paths
                    db_paths = _get_oracle_db_paths(sid, ora_home_path)
                    
                    databases.append({
                        "name": sid,
                        "sid": sid,
                        "ora_home": ora_home_path,
                        "paths": db_paths,
                        "primary_key": f"oracle:{sid}:{ora_home_path}",
                    })
    
    except Exception as e:
        logger.error(f"Error discovering Oracle databases: {e}")
    
    return databases


def _get_oracle_db_paths(sid: str, ora_home: str) -> List[str]:
    """Get paths for Oracle database."""
    paths = []
    
    # Common Oracle paths
    common_paths = [
        f"/oradata/{sid}",
        f"/u01/app/oracle/oradata/{sid}",
        f"/opt/oracle/oradata/{sid}",
        f"{ora_home}/oradata/{sid}",
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            paths.append(path)
    
    return paths


async def _discover_cache_iris() -> List[ApplicationInfo]:
    """Discover Cache/Iris instances (based on legacy ecxcache/ecxiris)."""
    apps = []
    
    try:
        # Try Cache first
        cache_instances = _discover_cache()
        for inst in cache_instances:
            app = ApplicationInfo(
                application_type=ApplicationType.DATABASE,
                application_subtype="cache",
                name=inst["name"],
                version=inst.get("version"),
                primary_key=inst.get("primary_key"),
                paths=inst.get("paths", []),
                metadata={
                    "install_dir": inst.get("install_dir"),
                    "databases": inst.get("databases", []),
                    "journal_dir": inst.get("journal_dir"),
                    "wij_dir": inst.get("wij_dir"),
                },
                requires_freeze=True,  # Cache needs freeze/thaw
            )
            apps.append(app)
        
        # Try Iris
        iris_instances = _discover_iris()
        for inst in iris_instances:
            app = ApplicationInfo(
                application_type=ApplicationType.DATABASE,
                application_subtype="iris",
                name=inst["name"],
                version=inst.get("version"),
                primary_key=inst.get("primary_key"),
                paths=inst.get("paths", []),
                metadata={
                    "install_dir": inst.get("install_dir"),
                    "databases": inst.get("databases", []),
                    "journal_dir": inst.get("journal_dir"),
                    "wij_dir": inst.get("wij_dir"),
                },
                requires_freeze=True,  # Iris needs freeze/thaw
            )
            apps.append(app)
    
    except Exception as e:
        logger.error(f"Cache/Iris discovery error: {e}")
    
    return apps


def _discover_cache() -> List[dict]:
    """Discover Cache instances."""
    instances = []
    
    try:
        # Check for ccontrol command
        result = subprocess.run(
            ["ccontrol", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Parse ccontrol output
            # Format: Configuration 'INSTANCE_NAME' ...
            pattern = re.compile(r"Configuration\s+'(\w+)'")
            for line in result.stdout.split("\n"):
                match = pattern.search(line)
                if match:
                    inst_name = match.group(1)
                    instances.append({
                        "name": inst_name,
                        "application_subtype": "cache",
                    })
    
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Cache not installed
        pass
    except Exception as e:
        logger.error(f"Cache discovery error: {e}")
    
    return instances


def _discover_iris() -> List[dict]:
    """Discover Iris instances."""
    instances = []
    
    try:
        # Check for iris command
        result = subprocess.run(
            ["iris", "list"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            # Parse iris output
            pattern = re.compile(r"Configuration\s+'(\w+)'")
            for line in result.stdout.split("\n"):
                match = pattern.search(line)
                if match:
                    inst_name = match.group(1)
                    instances.append({
                        "name": inst_name,
                        "application_subtype": "iris",
                    })
    
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Iris not installed
        pass
    except Exception as e:
        logger.error(f"Iris discovery error: {e}")
    
    return instances


async def _discover_hana() -> List[ApplicationInfo]:
    """Discover HANA instances (based on legacy hanaagent)."""
    apps = []
    
    try:
        # Check for HANA installation
        hana_paths = [
            "/usr/sap/HDB",
            "/hana/shared",
            "/opt/hana",
        ]
        
        for hana_path in hana_paths:
            if os.path.exists(hana_path):
                # Try to connect and discover
                # This would require HANA client libraries
                app = ApplicationInfo(
                    application_type=ApplicationType.DATABASE,
                    application_subtype="hana",
                    name="HANA",
                    paths=[hana_path],
                    metadata={
                        "hana_path": hana_path,
                    },
                    requires_freeze=False,  # HANA uses different mechanism
                )
                apps.append(app)
                break  # Only one HANA instance per system typically
    
    except Exception as e:
        logger.error(f"HANA discovery error: {e}")
    
    return apps

