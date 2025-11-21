# Fubar Agent Installation Guide

This guide covers installation of the Fubar Unified Pipeline Agent on Linux, macOS, and Windows.

## Prerequisites

- **Python 3.8 or higher** (required)
- **Network access** to the Fubar server (default port: 5848)
- **Appropriate permissions** for file operations (backup, restore, scanning)

## Quick Installation

### Option 1: Pre-built Bundle (Recommended)

Download the appropriate bundle for your platform:

- **Linux**: `fubar-agent-VERSION-linux-ARCH.tar.gz`
- **macOS**: `fubar-agent-VERSION-macos-ARCH.tar.gz` or `.dmg`
- **Windows**: `fubar-agent-VERSION-windows-ARCH.zip`

Extract and run the included `install.sh` (Linux/macOS) or `install.bat` (Windows).

### Option 2: Single Executable

For systems without Python installed, use the standalone executable:

- **Linux**: `fubar-agent-VERSION-linux-ARCH` (executable)
- **macOS**: `fubar-agent-VERSION-macos-ARCH` (executable)
- **Windows**: `fubar-agent-VERSION-windows-ARCH.exe`

No installation required - just run the executable.

### Option 3: Python Package (pip)

```bash
# Install from source
git clone https://github.com/brkn404/fubar-agent.git
cd fubar-agent
pip install --user .

# Or install dependencies manually
pip install --user aiohttp aiofiles click pyyaml psutil
# macOS: pip install --user xattr
# Windows: pip install --user pywin32
```

## Platform-Specific Installation

### Linux

#### Using Bundle

```bash
# Extract bundle
tar -xzf fubar-agent-VERSION-linux-ARCH.tar.gz
cd fubar-agent-VERSION

# Run installer
./install.sh
```

#### Manual Installation

```bash
# Install dependencies
python3 -m pip install --user aiohttp aiofiles click pyyaml psutil

# Install agent
python3 -m pip install --user .

# Configure
python3 -m fubar_agent.cli configure

# Start
python3 -m fubar_agent.cli start
```

#### Systemd Service (Optional)

The installer can create a systemd service file. This requires:

1. A dedicated `fubar` user account
2. Configuration file at `/etc/fubar/agent_config.yaml`
3. Root/sudo access

```bash
# Create fubar user
sudo useradd -r -s /bin/false -d /var/lib/fubar fubar
sudo mkdir -p /var/lib/fubar /etc/fubar
sudo chown fubar:fubar /var/lib/fubar

# Configure agent (as fubar user)
sudo -u fubar python3 -m fubar_agent.cli configure

# Enable and start service
sudo systemctl enable fubar-agent
sudo systemctl start fubar-agent
```

### macOS

#### Using Bundle

```bash
# Extract bundle
tar -xzf fubar-agent-VERSION-macos-ARCH.tar.gz
cd fubar-agent-VERSION

# Run installer
./install.sh
```

Or use the DMG installer (double-click to mount, then drag to Applications).

#### Manual Installation

```bash
# Install dependencies
python3 -m pip install --user aiohttp aiofiles click pyyaml psutil xattr

# Install agent
python3 -m pip install --user .

# Configure
python3 -m fubar_agent.cli configure

# Start
python3 -m fubar_agent.cli start
```

#### Launchd Service (Optional)

The installer can create a launchd plist for automatic startup:

```bash
# After installation, the plist will be at:
# ~/Library/LaunchAgents/com.fubar.agent.plist

# Load service
launchctl load ~/Library/LaunchAgents/com.fubar.agent.plist

# Unload service
launchctl unload ~/Library/LaunchAgents/com.fubar.agent.plist
```

**Note**: macOS may require Full Disk Access permissions for the agent to access all files.

### Windows

#### Using Bundle

1. Extract `fubar-agent-VERSION-windows-ARCH.zip`
2. Right-click `install.bat` → Run as Administrator
3. Follow the prompts

#### Manual Installation

```powershell
# Install dependencies
python -m pip install --user aiohttp aiofiles click pyyaml psutil pywin32

# Install agent
python -m pip install --user .

# Configure
python -m fubar_agent.cli configure

# Start
python -m fubar_agent.cli start
```

#### Windows Service (Optional)

Use NSSM (Non-Sucking Service Manager) to run as a Windows Service:

1. Download NSSM from https://nssm.cc/download
2. Extract and run `nssm.exe install fubar-agent`
3. Configure:
   - **Path**: `python.exe`
   - **Startup directory**: `C:\Program Files\fubar-agent`
   - **Arguments**: `-m fubar_agent.cli start --config-file C:\ProgramData\fubar\agent_config.yaml`
4. Start service: `nssm start fubar-agent`

## Configuration

### Initial Configuration

```bash
python3 -m fubar_agent.cli configure
```

You'll be prompted for:
- **Server URL**: `http://your-server-ip:5848` (default: `http://localhost:5848`)
- **API Key**: (optional, if server requires authentication)
- **Registration Token**: (optional, from host registration)
- **Max Concurrent Streams**: (default: 3)
- **Bandwidth Limit**: (optional, bytes per second)

Configuration is saved to `agent_config.yaml` in the current directory.

### Configuration File Location

- **Linux**: `~/.fubar/agent_config.yaml` or `/etc/fubar/agent_config.yaml`
- **macOS**: `~/.fubar/agent_config.yaml`
- **Windows**: `%APPDATA%\fubar\agent_config.yaml` or `C:\ProgramData\fubar\agent_config.yaml`

## Running the Agent

### Start Agent

```bash
python3 -m fubar_agent.cli start
```

Or with a specific config file:

```bash
python3 -m fubar_agent.cli start --config-file /path/to/agent_config.yaml
```

### Check Status

```bash
python3 -m fubar_agent.cli status
```

### Stop Agent

Press `Ctrl+C` or kill the process.

## Troubleshooting

### Connection Issues

- Verify server is running: `curl http://your-server:5848/health`
- Check firewall rules allow port 5848
- Verify server URL in `agent_config.yaml`

### Permission Issues

- **Linux/macOS**: Ensure user has read/write permissions for source/target directories
- **Windows**: Run as Administrator if accessing protected directories

### Python Not Found

- Ensure Python 3.8+ is installed and in PATH
- Use `python3` on Linux/macOS, `python` on Windows
- Verify: `python3 --version` or `python --version`

### Missing Dependencies

```bash
# Linux/macOS
python3 -m pip install --user aiohttp aiofiles click pyyaml psutil

# macOS (for extended attributes)
python3 -m pip install --user xattr

# Windows (for Windows-specific features)
python -m pip install --user pywin32
```

## Updating the Agent

### From Bundle

1. Stop the current agent
2. Extract new bundle
3. Run `install.sh` / `install.bat` again
4. Restart agent

### From Git

```bash
cd fubar-agent
git pull
python3 -m pip install --user --upgrade .
```

### Auto-Update

The agent can auto-update from the server if enabled. Check agent logs for update notifications.

## Uninstallation

### Remove Python Package

```bash
python3 -m pip uninstall fubar-agent
```

### Remove Service

- **Linux (systemd)**: `sudo systemctl disable fubar-agent && sudo systemctl stop fubar-agent`
- **macOS (launchd)**: `launchctl unload ~/Library/LaunchAgents/com.fubar.agent.plist`
- **Windows (NSSM)**: `nssm remove fubar-agent`

### Remove Configuration

Delete `agent_config.yaml` and any log files.

## Support

For issues and questions:
- Check logs: `~/.fubar/agent.log` or `logs/agent.log`
- See main README.md
- Check server logs for connection issues

