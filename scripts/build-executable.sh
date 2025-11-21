#!/bin/bash
# Build single executable using PyInstaller or Nuitka

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/executable"
DIST_DIR="$PROJECT_ROOT/dist"
VERSION=$(python3 -c "from src.fubar_agent.version import __version__; print(__version__)")

echo "📦 Building single executable (v${VERSION})..."
echo ""

# Detect platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Check for PyInstaller or Nuitka
USE_PYINSTALLER=false
USE_NUITKA=false

if command -v pyinstaller &> /dev/null || python3 -m pip show pyinstaller &> /dev/null; then
    USE_PYINSTALLER=true
    echo "✅ PyInstaller found"
elif python3 -m pip show nuitka &> /dev/null; then
    USE_NUITKA=true
    echo "✅ Nuitka found"
else
    echo "⚠️  Neither PyInstaller nor Nuitka found"
    echo "   Installing PyInstaller..."
    python3 -m pip install --user pyinstaller
    USE_PYINSTALLER=true
fi

# Clean build directories
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

if [ "$USE_PYINSTALLER" = true ]; then
    echo ""
    echo "🔨 Building with PyInstaller..."
    
    # Create PyInstaller spec file
    cat > "$BUILD_DIR/fubar-agent.spec" << SPEC_EOF
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['$PROJECT_ROOT/src/fubar_agent/cli.py'],
    pathex=['$PROJECT_ROOT/src'],
    binaries=[],
    datas=[
        ('$PROJECT_ROOT/rules-master', 'rules-master'),
    ],
    hiddenimports=[
        'fubar_agent.base',
        'fubar_agent.linux',
        'fubar_agent.macos',
        'fubar_agent.windows',
        'fubar_agent.platform',
        'fubar_agent.streaming',
        'fubar_agent.file_attributes',
        'fubar_agent.format_analyzers',
        'fubar_agent.bandwidth',
        'fubar_agent.discovery',
        'click',
        'aiohttp',
        'yaml',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='fubar-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
SPEC_EOF
    
    cd "$BUILD_DIR"
    pyinstaller --clean fubar-agent.spec
    
    # Copy executable to dist
    if [ "$PLATFORM" = "darwin" ]; then
        cp -r "$BUILD_DIR/dist/fubar-agent" "$DIST_DIR/fubar-agent-${VERSION}-macos-${ARCH}"
        echo "✅ Executable created: fubar-agent-${VERSION}-macos-${ARCH}"
    elif [ "$PLATFORM" = "linux" ]; then
        cp "$BUILD_DIR/dist/fubar-agent" "$DIST_DIR/fubar-agent-${VERSION}-linux-${ARCH}"
        echo "✅ Executable created: fubar-agent-${VERSION}-linux-${ARCH}"
    else
        cp "$BUILD_DIR/dist/fubar-agent" "$DIST_DIR/fubar-agent-${VERSION}-${PLATFORM}-${ARCH}"
        echo "✅ Executable created: fubar-agent-${VERSION}-${PLATFORM}-${ARCH}"
    fi

elif [ "$USE_NUITKA" = true ]; then
    echo ""
    echo "🔨 Building with Nuitka..."
    
    cd "$PROJECT_ROOT"
    python3 -m nuitka \
        --standalone \
        --onefile \
        --include-data-dir=rules-master=rules-master \
        --include-module=fubar_agent \
        --output-dir="$DIST_DIR" \
        --output-filename="fubar-agent-${VERSION}-${PLATFORM}-${ARCH}" \
        src/fubar_agent/cli.py
    
    echo "✅ Executable created with Nuitka"
fi

echo ""
echo "✅ Build complete!"

