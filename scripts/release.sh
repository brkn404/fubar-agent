#!/bin/bash
# Release script for fubar-agent
# Creates versioned release with git tags

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Get current version
CURRENT_VERSION=$(python3 -c "from src.fubar_agent.version import __version__; print(__version__)")

echo "🚀 Creating release for fubar-agent v${CURRENT_VERSION}"
echo ""

# Check if we're on main branch
CURRENT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")
if [ "$CURRENT_BRANCH" != "main" ] && [ "$CURRENT_BRANCH" != "master" ]; then
    echo "⚠️  Warning: Not on main/master branch (current: $CURRENT_BRANCH)"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo "⚠️  Warning: Uncommitted changes detected"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Build all distributions
echo "🔨 Building distributions..."
cd "$PROJECT_ROOT"
./build.sh

# Create git tag
echo ""
read -p "Create git tag v${CURRENT_VERSION}? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git tag -a "v${CURRENT_VERSION}" -m "Release v${CURRENT_VERSION}"
    echo "✅ Tag created: v${CURRENT_VERSION}"
    
    read -p "Push tag to remote? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git push origin "v${CURRENT_VERSION}"
        echo "✅ Tag pushed to remote"
    fi
fi

# Create release notes
RELEASE_NOTES="$PROJECT_ROOT/dist/RELEASE_NOTES_v${CURRENT_VERSION}.md"
cat > "$RELEASE_NOTES" << EOF
# Fubar Agent Release v${CURRENT_VERSION}

## Installation

### Linux
\`\`\`bash
tar -xzf fubar-agent-${CURRENT_VERSION}-linux-*.tar.gz
cd fubar-agent-${CURRENT_VERSION}
./install.sh
\`\`\`

### macOS
\`\`\`bash
tar -xzf fubar-agent-${CURRENT_VERSION}-macos-*.tar.gz
cd fubar-agent-${CURRENT_VERSION}
./install.sh
\`\`\`

Or use the DMG installer if available.

### Windows
1. Extract \`fubar-agent-${CURRENT_VERSION}-windows-*.zip\`
2. Run \`install.bat\` as Administrator

## Single Executable

For a standalone executable (no Python installation required), see:
- \`fubar-agent-${CURRENT_VERSION}-*-executable\`

## Configuration

After installation, configure the agent:
\`\`\`bash
python3 -m fubar_agent.cli configure
\`\`\`

Use server URL: \`http://your-server-ip:5848\`

## Documentation

See README.md and INSTALL.txt in the bundle for detailed instructions.

## Changes

See git log for changes in this release:
\`\`\`bash
git log v${CURRENT_VERSION}...vPREVIOUS_VERSION
\`\`\`
EOF

echo ""
echo "✅ Release created!"
echo "   Distributions: $PROJECT_ROOT/dist"
echo "   Release notes: $RELEASE_NOTES"
echo ""
ls -lh "$PROJECT_ROOT/dist"

