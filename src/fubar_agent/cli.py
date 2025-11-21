"""
Agent CLI

Command-line interface for the host agent.
"""

import asyncio
import logging
import sys
import tempfile
import zipfile
import shutil
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import click
import yaml
import aiohttp

from .base import BaseAgent
from .platform import detect_platform
from .macos import MacOSAgent
from .windows import WindowsAgent
from .linux import LinuxAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_agent_class():
    """Get platform-specific agent class"""
    platform_info = detect_platform()
    
    if platform_info.platform == "darwin":
        return MacOSAgent
    elif platform_info.platform == "windows":
        return WindowsAgent
    elif platform_info.platform == "linux":
        return LinuxAgent
    else:
        raise RuntimeError(f"Unsupported platform: {platform_info.platform}")


@click.group()
def cli():
    """Unified Pipeline Host Agent"""
    pass


@cli.command()
@click.option("--server-url", prompt="Server URL", help="Central server URL")
@click.option("--api-key", prompt="API Key", default="", help="API key for authentication (optional)")
@click.option("--registration-token", prompt="Registration Token", default="", help="Registration token from host registration (optional)")
@click.option("--max-concurrent-streams", default=3, help="Maximum concurrent upload streams")
@click.option("--max-connections", default=10, help="Maximum HTTP connections in pool")
@click.option("--bandwidth-limit", default=None, type=int, help="Bandwidth limit in bytes per second (e.g., 10485760 for 10MB/s)")
@click.option("--chunk-size", default=1048576, help="Chunk size in bytes (default: 1MB)")
@click.option("--config-file", default="agent_config.yaml", help="Config file path")
def configure(server_url: str, api_key: str, registration_token: str, max_concurrent_streams: int, max_connections: int, bandwidth_limit: Optional[int], chunk_size: int, config_file: str):
    """Configure the agent"""
    config = {
        "server": {
            "url": server_url,
            "api_key": api_key if api_key else None,
            "registration_token": registration_token if registration_token else None,
            "reconnect_interval": 30,
        },
        "agent": {
            "hostname": "auto",
            "poll_interval": 5,
            "heartbeat_interval": 30,
            "max_concurrent_jobs": 2,
            "max_concurrent_streams": max_concurrent_streams,
            "max_connections": max_connections,
            "bandwidth_limit": bandwidth_limit,
            "chunk_size": chunk_size,
        },
        "capabilities": {
            "scan": True,
            "backup": True,
            "restore": True,
            "yara": False,
            "virustotal": False,
        },
        "logging": {
            "level": "info",
            "file": "/var/log/unified-agent.log",
        },
    }
    
    config_path = Path(config_file)
    with config_path.open("w") as f:
        yaml.dump(config, f)
    
    click.echo(f"Configuration saved to {config_path}")


@cli.command()
@click.option("--config-file", default="agent_config.yaml", help="Config file path")
def start(config_file: str):
    """Start the agent"""
    config_path = Path(config_file)
    
    if not config_path.exists():
        click.echo(f"Config file not found: {config_path}")
        click.echo("Run 'unified-agent configure' first")
        sys.exit(1)
    
    with config_path.open() as f:
        config = yaml.safe_load(f)
    
    server_config = config.get("server", {})
    agent_config = config.get("agent", {})
    
    # Get platform-specific agent
    AgentClass = get_agent_class()
    
    agent = AgentClass(
        server_url=server_config.get("url"),
        api_key=server_config.get("api_key"),
        registration_token=server_config.get("registration_token"),
        agent_id=agent_config.get("agent_id"),  # Load saved agent_id for reconnection
        poll_interval=agent_config.get("poll_interval", 5),
        heartbeat_interval=agent_config.get("heartbeat_interval", 30),
        max_concurrent_jobs=agent_config.get("max_concurrent_jobs", 2),
        max_concurrent_streams=agent_config.get("max_concurrent_streams", 3),
        max_connections=agent_config.get("max_connections", 10),
        bandwidth_limit=agent_config.get("bandwidth_limit"),
        chunk_size=agent_config.get("chunk_size", 1048576),
    )
    
    # Store config path so agent can save agent_id after registration
    agent.config_path = str(config_path.absolute())
    
    async def run():
        await agent.start()
        try:
            # Keep running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await agent.stop()
    
    asyncio.run(run())


@cli.command()
@click.option("--config-file", default="agent_config.yaml", help="Config file path")
@click.option("--service-name", default="unified-agent", help="Service name")
def install_service(config_file: str, service_name: str):
    """Install agent as a system service"""
    platform_info = detect_platform()
    
    if platform_info.platform == "darwin":
        _install_macos_service(config_file, service_name)
    elif platform_info.platform == "windows":
        _install_windows_service(config_file, service_name)
    elif platform_info.platform == "linux":
        _install_linux_service(config_file, service_name)
    else:
        click.echo(f"Unsupported platform: {platform_info.platform}")
        sys.exit(1)


def _install_macos_service(config_file: str, service_name: str):
    """Install macOS LaunchDaemon"""
    import subprocess
    import shutil
    
    # Get Python executable
    python_exe = sys.executable
    
    # Get agent script path
    import fubar_agent.cli as agent_cli_module
    agent_script = Path(agent_cli_module.__file__)
    
    # Create plist file
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.unified.{service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>
        <string>{agent_script}</string>
        <string>start</string>
        <string>--config-file</string>
        <string>{Path(config_file).absolute()}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/unified-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/unified-agent.error.log</string>
</dict>
</plist>
"""
    
    plist_path = Path(f"/Library/LaunchDaemons/com.unified.{service_name}.plist")
    
    if not plist_path.parent.exists():
        click.echo("Creating LaunchDaemons directory...")
        plist_path.parent.mkdir(parents=True, exist_ok=True)
    
    with plist_path.open("w") as f:
        f.write(plist_content)
    
    click.echo(f"LaunchDaemon installed: {plist_path}")
    click.echo(f"To start: sudo launchctl load {plist_path}")
    click.echo(f"To stop: sudo launchctl unload {plist_path}")


def _install_windows_service(config_file: str, service_name: str):
    """Install Windows Service"""
    try:
        import win32serviceutil
        import win32service
        import servicemanager
        
        # This would require a proper Windows service class
        click.echo("Windows service installation requires additional setup")
        click.echo("See docs/AGENT_ARCHITECTURE.md for details")
    except ImportError:
        click.echo("Windows service support requires pywin32")
        click.echo("Install with: pip install pywin32")


def _install_linux_service(config_file: str, service_name: str):
    """Install Linux systemd service"""
    import subprocess
    
    # Get Python executable
    python_exe = sys.executable
    
    # Get agent script path
    import fubar_agent.cli as agent_cli_module
    agent_script = Path(agent_cli_module.__file__)
    
    # Create systemd service file
    service_content = f"""[Unit]
Description=Unified Pipeline Host Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart={python_exe} {agent_script} start --config-file {Path(config_file).absolute()}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    
    service_path = Path(f"/etc/systemd/system/{service_name}.service")
    
    if not service_path.parent.exists():
        click.echo("Creating systemd directory...")
        service_path.parent.mkdir(parents=True, exist_ok=True)
    
    with service_path.open("w") as f:
        f.write(service_content)
    
    click.echo(f"Systemd service installed: {service_path}")
    click.echo(f"To start: sudo systemctl start {service_name}")
    click.echo(f"To enable: sudo systemctl enable {service_name}")


@cli.command()
@click.option("--service-name", default="unified-agent", help="Service name")
def uninstall_service(service_name: str):
    """Uninstall agent service"""
    platform_info = detect_platform()
    
    if platform_info.platform == "darwin":
        plist_path = Path(f"/Library/LaunchDaemons/com.unified.{service_name}.plist")
        if plist_path.exists():
            plist_path.unlink()
            click.echo(f"LaunchDaemon removed: {plist_path}")
    elif platform_info.platform == "linux":
        service_path = Path(f"/etc/systemd/system/{service_name}.service")
        if service_path.exists():
            service_path.unlink()
            click.echo(f"Systemd service removed: {service_path}")
            click.echo("Run: sudo systemctl daemon-reload")
    else:
        click.echo(f"Unsupported platform: {platform_info.platform}")


@cli.command()
@click.option("--config-file", default="agent_config.yaml", help="Config file path")
def sync(config_file: str):
    """Sync agent code from server"""
    import asyncio
    import aiohttp
    import zipfile
    import shutil
    from pathlib import Path
    
    config_path = Path(config_file)
    if not config_path.exists():
        click.echo(f"Config file not found: {config_path}")
        click.echo("Run 'unified-agent configure' first")
        sys.exit(1)
    
    with config_path.open() as f:
        config = yaml.safe_load(f)
    
    server_url = config.get("server", {}).get("url")
    if not server_url:
        click.echo("Server URL not configured")
        sys.exit(1)
    
    agent_id = config.get("agent", {}).get("agent_id")
    if not agent_id:
        click.echo("Agent not registered. Run 'unified-agent start' first to register.")
        sys.exit(1)
    
    async def sync_code():
        async with aiohttp.ClientSession() as session:
            # Check current version
            try:
                from .version import __version__
                current_version = __version__
            except ImportError:
                current_version = "unknown"
            
            # Get git commit if available
            try:
                import subprocess
                repo_path = Path(__file__).parent.parent.parent.parent
                if (repo_path / ".git").exists():
                    current_version = subprocess.check_output(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()[:8]
            except Exception:
                pass
            
            click.echo(f"Current agent version: {current_version}")
            
            # Check for updates
            async with session.get(
                f"{server_url}/api/v1/agents/sync/check",
                params={"agent_id": agent_id, "current_version": current_version}
            ) as resp:
                if resp.status != 200:
                    click.echo(f"Failed to check for updates: {resp.status}")
                    return
                
                update_info = await resp.json()
                if not update_info.get("update_needed"):
                    click.echo("✅ Agent is up to date!")
                    return
                
                click.echo(f"Update available: {update_info['latest_version']}")
                click.echo("Downloading latest code...")
            
            # Download code
            async with session.get(
                f"{server_url}/api/v1/agents/sync/download",
                params={"agent_id": agent_id}
            ) as resp:
                if resp.status != 200:
                    click.echo(f"Failed to download code: {resp.status}")
                    return
                
                # Get version from headers
                server_version = resp.headers.get("X-Agent-Version", "unknown")
                
                # Save to temporary file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_file:
                    zip_path = Path(tmp_file.name)
                    async for chunk in resp.content.iter_chunked(8192):
                        tmp_file.write(chunk)
                
                click.echo(f"Downloaded version {server_version}")
                click.echo("Extracting code...")
                
                # Extract to agent directory
                agent_path = Path(__file__).parent
                backup_path = agent_path.parent / f"agent_backup_{current_version}"
                
                # Backup current code
                if agent_path.exists():
                    if backup_path.exists():
                        shutil.rmtree(backup_path)
                    shutil.copytree(agent_path, backup_path)
                    click.echo(f"Backed up current code to {backup_path}")
                
                # Extract new code
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(agent_path.parent)
                
                # Clean up
                zip_path.unlink()
                
                click.echo("✅ Agent code updated successfully!")
                click.echo(f"New version: {server_version}")
                click.echo(f"Backup saved to: {backup_path}")
                
                # Report version update to server
                try:
                    async with session.post(
                        f"{server_url}/api/v1/agents/{agent_id}/heartbeat",
                        json={
                            "status": "online",
                            "active_jobs": 0,
                            "version": server_version,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    ) as resp:
                        if resp.status == 200:
                            click.echo("✅ Version reported to server")
                        else:
                            click.echo(f"⚠️  Failed to report version to server: {resp.status}")
                except Exception as e:
                    click.echo(f"⚠️  Failed to report version to server: {e}")
                
                click.echo("")
                click.echo("Restart the agent to use the new code:")
                click.echo(f"  python3 -m fubar_agent.cli start --config-file {config_file}")
    
    asyncio.run(sync_code())


@cli.command()
def version():
    """Show agent version and system information"""
    import sys
    import platform as platform_module
    from pathlib import Path
    
    # Get package version
    try:
        from unified_pipeline import __version__
        package_version = __version__
    except ImportError:
        package_version = "unknown"
    
    # Try to get git commit hash
    git_commit = "unknown"
    git_branch = "unknown"
    try:
        import subprocess
        # Use git to find the repo root (more reliable than walking directories)
        current_path = Path(__file__).resolve()
        # Try to find git repo root using git command
        try:
            repo_path = subprocess.check_output(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=current_path.parent,
                stderr=subprocess.DEVNULL
            ).decode().strip()
            repo_path = Path(repo_path)
            
            if repo_path.exists() and (repo_path / ".git").exists():
                try:
                    git_commit = subprocess.check_output(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()[:8]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
                
                try:
                    git_branch = subprocess.check_output(
                        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: try walking up directories
            repo_path = current_path.parent.parent.parent.parent.parent
            if not (repo_path / ".git").exists():
                repo_path = repo_path.parent
            if (repo_path / ".git").exists():
                try:
                    git_commit = subprocess.check_output(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()[:8]
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
                
                try:
                    git_branch = subprocess.check_output(
                        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                        cwd=repo_path,
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
    except Exception as e:
        logger.debug(f"Could not get git info: {e}")
    
    # Get platform info
    platform_info = detect_platform()
    
    # Check discovery module
    discovery_status = "unknown"
    discovery_path = None
    try:
        base_file = Path(__file__).parent / "base.py"
        if base_file.exists():
            discovery_path = base_file.parent / "discovery"
            if discovery_path.exists() and (discovery_path / "__init__.py").exists():
                # Try to import
                try:
                    from .discovery import discover_databases
                    discovery_status = "available"
                except (ImportError, ModuleNotFoundError):
                    discovery_status = "directory exists but import failed"
            else:
                discovery_status = "directory not found"
    except Exception as e:
        discovery_status = f"error checking: {e}"
    
    # Get Python path info
    python_path = sys.executable
    python_version = sys.version.split()[0]
    python_path_env = sys.path[:3]  # First few entries
    
    click.echo("Unified Pipeline Agent")
    click.echo("=" * 50)
    click.echo(f"Package Version: {package_version}")
    click.echo(f"Git Commit: {git_commit}")
    click.echo(f"Git Branch: {git_branch}")
    click.echo("")
    click.echo("Platform Information:")
    click.echo(f"  Platform: {platform_info.platform}")
    click.echo(f"  Hostname: {platform_info.hostname}")
    click.echo(f"  OS Version: {platform_info.version}")
    click.echo("")
    click.echo("Python Information:")
    click.echo(f"  Python: {python_version}")
    click.echo(f"  Executable: {python_path}")
    click.echo(f"  Path (first 3 entries):")
    for i, path in enumerate(python_path_env, 1):
        click.echo(f"    {i}. {path}")
    click.echo("")
    click.echo("Discovery Module:")
    click.echo(f"  Status: {discovery_status}")
    if discovery_path:
        click.echo(f"  Path: {discovery_path}")
        if discovery_path.exists():
            required_files = ["__init__.py", "base.py", "databases.py", "vms.py", "filesystems.py"]
            missing = [f for f in required_files if not (discovery_path / f).exists()]
            if missing:
                click.echo(f"  Missing files: {', '.join(missing)}")
            else:
                click.echo(f"  All required files present")
    click.echo("")


if __name__ == "__main__":
    cli()

