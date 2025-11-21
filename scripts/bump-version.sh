#!/bin/bash
# Version bump script for fubar-agent
# Usage: ./scripts/bump-version.sh [major|minor|patch]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION_FILE="$PROJECT_ROOT/src/fubar_agent/version.py"

# Get current version
CURRENT_VERSION=$(python3 -c "from src.fubar_agent.version import __version__; print(__version__)")

# Parse version components
IFS='.' read -ra VERSION_PARTS <<< "$CURRENT_VERSION"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

# Determine bump type
BUMP_TYPE=${1:-patch}

case $BUMP_TYPE in
    major)
        MAJOR=$((MAJOR + 1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        MINOR=$((MINOR + 1))
        PATCH=0
        ;;
    patch)
        PATCH=$((PATCH + 1))
        ;;
    *)
        echo "❌ Invalid bump type: $BUMP_TYPE"
        echo "Usage: $0 [major|minor|patch]"
        exit 1
        ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"

echo "📦 Bumping version:"
echo "   Current: $CURRENT_VERSION"
echo "   New:     $NEW_VERSION"
echo ""

# Update version file
cat > "$VERSION_FILE" << EOF
__version__ = '$NEW_VERSION'
EOF

echo "✅ Version updated in $VERSION_FILE"

# Update setup.py if it has hardcoded version (it should use version.py now)
if grep -q "version=\"$CURRENT_VERSION\"" "$PROJECT_ROOT/setup.py" 2>/dev/null; then
    sed -i.bak "s/version=\"$CURRENT_VERSION\"/version=__version__/" "$PROJECT_ROOT/setup.py"
    rm -f "$PROJECT_ROOT/setup.py.bak"
    echo "✅ Version updated in setup.py"
fi

echo ""
echo "📝 Next steps:"
echo "   1. Review changes: git diff"
echo "   2. Commit: git commit -am \"Bump version to $NEW_VERSION\""
echo "   3. Tag: git tag -a v$NEW_VERSION -m \"Release v$NEW_VERSION\""
echo "   4. Build: ./build.sh"
echo "   5. Release: ./scripts/release.sh"

