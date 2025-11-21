#!/bin/bash
# Build script for fubar-agent
# Creates platform-specific bundles and installers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_ROOT/build"
DIST_DIR="$PROJECT_ROOT/dist"
VERSION=$(python3 -c "from src.fubar_agent.version import __version__; print(__version__)")

echo "🔨 Building fubar-agent v${VERSION}"
echo ""

# Detect platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

echo "Platform: $PLATFORM"
echo "Architecture: $ARCH"
echo ""

# Clean build directories
echo "🧹 Cleaning build directories..."
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

# Create source distribution
echo "📦 Creating source distribution..."
cd "$PROJECT_ROOT"
python3 setup.py sdist --dist-dir "$DIST_DIR"

# Platform-specific builds
if [ "$PLATFORM" = "linux" ]; then
    echo ""
    echo "🐧 Building Linux bundle..."
    "$SCRIPT_DIR/scripts/build-linux.sh"
elif [ "$PLATFORM" = "darwin" ]; then
    echo ""
    echo "🍎 Building macOS bundle..."
    "$SCRIPT_DIR/scripts/build-macos.sh"
else
    echo ""
    echo "⚠️  Platform-specific build not available for $PLATFORM"
    echo "   Only source distribution created"
fi

echo ""
echo "✅ Build complete!"
echo "   Distributions: $DIST_DIR"
ls -lh "$DIST_DIR"

