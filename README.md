# fubar-agent

Standalone agent code for the Fubar Unified Pipeline system.

## Installation

### Quick Start (Pre-built Bundle)

Download the appropriate bundle for your platform and follow the installation guide:

- **Linux**: Extract `.tar.gz` and run `./install.sh`
- **macOS**: Extract `.tar.gz` or mount `.dmg` and run `./install.sh`
- **Windows**: Extract `.zip` and run `install.bat` as Administrator

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for detailed instructions.

### From Source

```bash
# Clone repository
git clone https://github.com/brkn404/fubar-agent.git
cd fubar-agent

# Install dependencies
pip install --user aiohttp click pyyaml

# Install agent
pip install --user .
```

### Windows: Set Up Service Account First

On Windows, set up the service account before installing:

```powershell
# Clone the repository
git clone https://github.com/brkn404/fubar-agent.git
cd fubar-agent

# Run setup script as Administrator
.\scripts\setup-fubar-user-windows.ps1

# Then proceed with installation
```

### Single Executable

For systems without Python, use the standalone executable built with PyInstaller or Nuitka:

```bash
# Build executable
./scripts/build-executable.sh

# Run directly (no Python required)
./dist/fubar-agent-VERSION-PLATFORM-ARCH
```

## Configuration

### Default Server Port

The agent connects to the API server on port **5848** by default (changed from 8000).

When configuring the agent, use:
```
http://localhost:5848
```

Or if the server is on a different host:
```
http://your-server-ip:5848
```

### Quick Start

1. **Configure the agent:**
   ```bash
   python3 -m fubar_agent.cli configure
   ```
   
   When prompted for Server URL, use: `http://localhost:5848` (or your server's IP)

2. **Start the agent:**
   ```bash
   python3 -m fubar_agent.cli start
   ```

3. **Check agent status:**
   ```bash
   python3 -m fubar_agent.cli status
   ```

## Building from Source

### Prerequisites

- Python 3.8+
- Build tools (make, gcc, etc.)
- Platform-specific tools:
  - **Linux**: Standard build tools
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)
  - **Windows**: Visual Studio Build Tools or MinGW

### Build All Platforms

```bash
# Build source distribution
./build.sh

# Build platform-specific bundle (on target platform)
./scripts/build-linux.sh    # Linux
./scripts/build-macos.sh    # macOS
./scripts/build-windows.ps1 # Windows (PowerShell)
```

### Build Single Executable

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
./scripts/build-executable.sh
```

### Version Management

```bash
# Bump version (patch/minor/major)
./scripts/bump-version.sh patch

# Create release
./scripts/release.sh
```

## Port Information

- **API Server**: 5848 (default)
- **App Server**: 5847 (for UI, not used by agent)
- **WebSocket**: 5847 (same as app server)

These ports were chosen to avoid conflicts with common services.

## Development

### Project Structure

```
fubar-agent/
├── src/fubar_agent/    # Agent source code
├── rules-master/       # YARA rules
├── scripts/            # Build and utility scripts
├── docs/               # Documentation
└── build.sh           # Main build script
```

### Running Tests

```bash
# Run agent tests (when available)
python -m pytest tests/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test on target platform(s)
5. Submit a pull request

## License

See LICENSE file for details.
