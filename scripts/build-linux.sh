#!/bin/bash
# Build Linux bundle (.tar.gz)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/linux"
DIST_DIR="$PROJECT_ROOT/dist"
VERSION=$(python3 -c "from src.fubar_agent.version import __version__; print(__version__)")
ARCH=$(uname -m)

echo "🐧 Building Linux bundle (v${VERSION})..."
echo ""

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
# Installation script for fubar-agent

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🚀 Installing fubar-agent..."
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
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

# Install agent
echo "📦 Installing fubar-agent..."
cd "$SCRIPT_DIR"
python3 -m pip install --user .

# Create systemd service file (optional)
if command -v systemctl &> /dev/null; then
    echo ""
    read -p "Create systemd service? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        SERVICE_FILE="/etc/systemd/system/fubar-agent.service"
        AGENT_PATH=$(python3 -m pip show fubar-agent | grep Location | cut -d' ' -f2)
        CONFIG_FILE="/etc/fubar/agent_config.yaml"
        
        sudo mkdir -p /etc/fubar
        
        sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=Fubar Unified Pipeline Agent
After=network.target

[Service]
Type=simple
User=fubar
Group=fubar
WorkingDirectory=/var/lib/fubar
ExecStart=/usr/bin/python3 -m fubar_agent.cli start --config-file $CONFIG_FILE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        echo "✅ Systemd service file created: $SERVICE_FILE"
        echo "   Edit $CONFIG_FILE and run: sudo systemctl enable fubar-agent"
    fi
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
Fubar Agent Installation Guide
==============================

Version: ${VERSION}
Platform: Linux (${ARCH})

Quick Install:
--------------
1. Extract this archive:
   tar -xzf fubar-agent-${VERSION}-linux-${ARCH}.tar.gz
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
   python3 -m pip install --user aiohttp click pyyaml

2. Install agent:
   python3 -m pip install --user .

3. Configure and start (see Quick Install steps 3-4)

Systemd Service:
---------------
The install script can create a systemd service file for automatic startup.
This requires:
- Root/sudo access
- A 'fubar' user account (or modify the service file)

For more information, see the main README.md
EOF

# Create tarball
echo "📦 Creating tarball..."
cd "$BUILD_DIR"
tar -czf "$DIST_DIR/fubar-agent-${VERSION}-linux-${ARCH}.tar.gz" "fubar-agent-${VERSION}"

echo "✅ Linux bundle created: fubar-agent-${VERSION}-linux-${ARCH}.tar.gz"

