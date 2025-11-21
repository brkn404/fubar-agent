#!/bin/bash
# Build macOS bundle (.dmg or .pkg)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/macos"
DIST_DIR="$PROJECT_ROOT/dist"
VERSION=$(python3 -c "from src.fubar_agent.version import __version__; print(__version__)")
ARCH=$(uname -m)

echo "🍎 Building macOS bundle (v${VERSION})..."
echo ""

# Check for required tools
if ! command -v create-dmg &> /dev/null && ! command -v hdiutil &> /dev/null; then
    echo "⚠️  create-dmg not found, creating .tar.gz instead of .dmg"
    USE_DMG=false
else
    USE_DMG=true
fi

# Create build directory
mkdir -p "$BUILD_DIR/fubar-agent-${VERSION}"

# Copy source files
echo "📋 Copying source files..."
cp -r "$PROJECT_ROOT/src" "$BUILD_DIR/fubar-agent-${VERSION}/"
cp -r "$PROJECT_ROOT/rules-master" "$BUILD_DIR/fubar-agent-${VERSION}/"
cp "$PROJECT_ROOT/setup.py" "$BUILD_DIR/fubar-agent-${VERSION}/"
cp "$PROJECT_ROOT/README.md" "$BUILD_DIR/fubar-agent-${VERSION}/"

# Create install script
cat > "$BUILD_DIR/fubar-agent-${VERSION}/install.sh" << 'INSTALL_EOF'
#!/bin/bash
# Installation script for fubar-agent (macOS)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Installing fubar-agent..."
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    echo "   Install from: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
if [ "$(printf '%s\n' "3.8" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.8" ]; then
    echo "❌ Python 3.8 or higher is required (found: $PYTHON_VERSION)"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
python3 -m pip install --user --upgrade pip
python3 -m pip install --user aiohttp click pyyaml

# Optional: Install xattr for macOS extended attributes
if ! python3 -c "import xattr" 2>/dev/null; then
    echo "📦 Installing xattr (for macOS extended attributes support)..."
    python3 -m pip install --user xattr || echo "⚠️  xattr installation failed (optional)"
fi

# Install agent
echo "📦 Installing fubar-agent..."
cd "$SCRIPT_DIR"
python3 -m pip install --user .

# Create launchd plist (optional)
echo ""
read -p "Create launchd service for auto-start? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    PLIST_FILE="$HOME/Library/LaunchAgents/com.fubar.agent.plist"
    CONFIG_FILE="$HOME/.fubar/agent_config.yaml"
    
    mkdir -p "$HOME/.fubar"
    mkdir -p "$HOME/Library/LaunchAgents"
    
    cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fubar.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>-m</string>
        <string>fubar_agent.cli</string>
        <string>start</string>
        <string>--config-file</string>
        <string>$CONFIG_FILE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME/.fubar/agent.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME/.fubar/agent.error.log</string>
</dict>
</plist>
EOF
    
    echo "✅ Launchd plist created: $PLIST_FILE"
    echo "   To start: launchctl load $PLIST_FILE"
    echo "   To stop: launchctl unload $PLIST_FILE"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Configure agent: python3 -m fubar_agent.cli configure"
echo "  2. Start agent: python3 -m fubar_agent.cli start"
INSTALL_EOF

chmod +x "$BUILD_DIR/fubar-agent-${VERSION}/install.sh"

# Create README for bundle
cat > "$BUILD_DIR/fubar-agent-${VERSION}/INSTALL.txt" << EOF
Fubar Agent Installation Guide (macOS)
======================================

Version: ${VERSION}
Platform: macOS (${ARCH})

Quick Install:
--------------
1. Extract this archive:
   tar -xzf fubar-agent-${VERSION}-macos-${ARCH}.tar.gz
   cd fubar-agent-${VERSION}

2. Run install script:
   ./install.sh

3. Configure agent:
   python3 -m fubar_agent.cli configure

4. Start agent:
   python3 -m fubar_agent.cli start

Manual Install:
---------------
1. Install dependencies:
   python3 -m pip install --user aiohttp click pyyaml xattr

2. Install agent:
   python3 -m pip install --user .

3. Configure and start (see Quick Install steps 3-4)

Launchd Service:
---------------
The install script can create a launchd plist for automatic startup.
This will run the agent as your user account.

For more information, see the main README.md
EOF

# Create tarball
echo "📦 Creating tarball..."
cd "$BUILD_DIR"
tar -czf "$DIST_DIR/fubar-agent-${VERSION}-macos-${ARCH}.tar.gz" "fubar-agent-${VERSION}"

# Create DMG if possible
if [ "$USE_DMG" = true ]; then
    echo "💿 Creating DMG..."
    DMG_NAME="fubar-agent-${VERSION}-macos-${ARCH}.dmg"
    
    if command -v create-dmg &> /dev/null; then
        create-dmg \
            --volname "Fubar Agent ${VERSION}" \
            --window-pos 200 120 \
            --window-size 600 400 \
            --icon-size 100 \
            --icon "fubar-agent-${VERSION}" 150 200 \
            --hide-extension "fubar-agent-${VERSION}" \
            --app-drop-link 450 200 \
            "$DIST_DIR/$DMG_NAME" \
            "$BUILD_DIR/fubar-agent-${VERSION}"
    else
        # Use hdiutil (built-in macOS tool)
        hdiutil create -volname "Fubar Agent ${VERSION}" \
            -srcfolder "$BUILD_DIR/fubar-agent-${VERSION}" \
            -ov -format UDZO \
            "$DIST_DIR/$DMG_NAME"
    fi
    
    echo "✅ DMG created: $DMG_NAME"
fi

echo "✅ macOS bundle created: fubar-agent-${VERSION}-macos-${ARCH}.tar.gz"

