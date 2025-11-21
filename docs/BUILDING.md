# Building fubar-agent

This guide covers building fubar-agent from source, including platform-specific bundles and standalone executables.

## Prerequisites

- **Python 3.8+** with pip
- **Git** (for cloning repository)
- **Build tools** (platform-specific)

### Platform-Specific Requirements

#### Linux
- Standard build tools: `gcc`, `make`, `tar`, `gzip`
- Optional: `systemd` (for service file generation)

#### macOS
- Xcode Command Line Tools: `xcode-select --install`
- Optional: `create-dmg` (for DMG creation): `brew install create-dmg`
- Or use built-in `hdiutil` for DMG creation

#### Windows
- PowerShell 5.1+ (for build scripts)
- Optional: WiX Toolset (for MSI installers): https://wixtoolset.org/
- Optional: NSSM (for Windows Service): https://nssm.cc/

## Quick Build

### Source Distribution

```bash
# Clone repository
git clone https://github.com/brkn404/fubar-agent.git
cd fubar-agent

# Build source distribution
./build.sh
```

This creates a source distribution (`.tar.gz`) in the `dist/` directory.

### Platform-Specific Bundle

Build on the target platform:

```bash
# Linux
./scripts/build-linux.sh

# macOS
./scripts/build-macos.sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File scripts/build-windows.ps1
```

## Building Standalone Executables

### Using PyInstaller (Recommended)

```bash
# Install PyInstaller
pip install pyinstaller

# Build executable
./scripts/build-executable.sh
```

The executable will be in `dist/fubar-agent-VERSION-PLATFORM-ARCH`.

**Note**: PyInstaller creates large executables (~50-100MB) but includes all dependencies.

### Using Nuitka

```bash
# Install Nuitka
pip install nuitka

# Build executable
python3 -m nuitka \
    --standalone \
    --onefile \
    --include-data-dir=rules-master=rules-master \
    --output-dir=dist \
    src/fubar_agent/cli.py
```

**Note**: Nuitka compiles to native code, resulting in smaller executables but longer build times.

## Build Scripts

### Main Build Script (`build.sh`)

Detects platform and builds appropriate bundle:

```bash
./build.sh
```

### Platform-Specific Scripts

- **`scripts/build-linux.sh`**: Creates `.tar.gz` bundle with install script
- **`scripts/build-macos.sh`**: Creates `.tar.gz` or `.dmg` bundle
- **`scripts/build-windows.ps1`**: Creates `.zip` bundle (and `.msi` if WiX available)
- **`scripts/build-executable.sh`**: Creates standalone executable using PyInstaller/Nuitka

### Release Script (`scripts/release.sh`)

Creates a versioned release:

```bash
./scripts/release.sh
```

This will:
1. Build all distributions
2. Create git tag (if confirmed)
3. Generate release notes
4. Prepare artifacts for upload

## Version Management

### Bump Version

```bash
# Patch version (0.1.0 -> 0.1.1)
./scripts/bump-version.sh patch

# Minor version (0.1.0 -> 0.2.0)
./scripts/bump-version.sh minor

# Major version (0.1.0 -> 1.0.0)
./scripts/bump-version.sh major
```

Version is stored in `src/fubar_agent/version.py`.

### Manual Version Update

Edit `src/fubar_agent/version.py`:

```python
__version__ = '0.1.0'
```

## Build Artifacts

### Source Distribution

- **Location**: `dist/fubar-agent-VERSION.tar.gz`
- **Contents**: Source code, setup.py, README
- **Install**: `pip install fubar-agent-VERSION.tar.gz`

### Platform Bundles

#### Linux
- **File**: `dist/fubar-agent-VERSION-linux-ARCH.tar.gz`
- **Contents**: Source code, install.sh, INSTALL.txt
- **Size**: ~5-10 MB

#### macOS
- **File**: `dist/fubar-agent-VERSION-macos-ARCH.tar.gz` or `.dmg`
- **Contents**: Source code, install.sh, INSTALL.txt
- **Size**: ~5-10 MB

#### Windows
- **File**: `dist/fubar-agent-VERSION-windows-ARCH.zip`
- **Contents**: Source code, install.bat, INSTALL.txt
- **Size**: ~5-10 MB

### Standalone Executables

- **File**: `dist/fubar-agent-VERSION-PLATFORM-ARCH`
- **Contents**: Single executable with all dependencies
- **Size**: ~50-100 MB (PyInstaller) or ~10-20 MB (Nuitka)
- **No Python required**: Can run on systems without Python installed

## CI/CD Integration

### GitHub Actions

A workflow file is included at `.github/workflows/build.yml` that:

1. Builds bundles for Linux, macOS, and Windows
2. Creates release artifacts on tag push
3. Uploads to GitHub Releases

To use:

1. Push tag: `git tag v0.1.0 && git push origin v0.1.0`
2. GitHub Actions will automatically build and create release

### Custom CI/CD

Example for custom CI:

```bash
# Install dependencies
pip install aiohttp click pyyaml

# Build
./build.sh

# Upload artifacts
# (platform-specific upload commands)
```

## Troubleshooting

### Build Fails: Missing Dependencies

```bash
# Install all dependencies
pip install aiohttp click pyyaml

# Platform-specific
pip install xattr  # macOS
pip install pywin32  # Windows
```

### PyInstaller: Module Not Found

Add missing modules to `pyinstaller.spec`:

```python
hiddenimports=[
    'missing_module',
    # ...
]
```

### Executable Too Large

- Use Nuitka instead of PyInstaller
- Exclude unnecessary modules in spec file
- Use `--exclude-module` flag

### Windows: PowerShell Execution Policy

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Or run with bypass:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-windows.ps1
```

## Advanced Configuration

### PyInstaller Spec File

Customize `pyinstaller.spec` for:
- Additional data files
- Hidden imports
- Binary dependencies
- Code signing (macOS/Windows)

### Custom Build Options

Edit build scripts to:
- Include/exclude YARA rules
- Add custom data files
- Modify install scripts
- Change bundle structure

## Distribution

### Testing Builds

Before distributing:

1. **Test on clean system**: Install on VM without Python
2. **Verify functionality**: Run agent, test backup/restore/scan
3. **Check permissions**: Ensure install scripts work correctly
4. **Test services**: Verify systemd/launchd/NSSM integration

### Release Checklist

- [ ] Version bumped
- [ ] Changelog updated
- [ ] All platforms built
- [ ] Executables tested
- [ ] Installation tested
- [ ] Git tag created
- [ ] Release notes prepared
- [ ] Artifacts uploaded

## Support

For build issues:
- Check platform-specific requirements
- Review build script logs
- Test on clean system
- Check CI/CD logs (if using)

