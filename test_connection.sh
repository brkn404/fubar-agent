#!/bin/bash
# Test agent connection to server
#
# Usage: ./test_connection.sh [server_url]
#
# Tests:
# - Server is reachable
# - API health endpoint responds
# - Agent can connect

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_URL="${1:-http://localhost:5848}"

echo "🧪 Testing FUBAR Agent Connection"
echo "   Server URL: $SERVER_URL"
echo ""

# Test 1: Server is reachable
echo "1️⃣  Testing server reachability..."
if curl -s -f --max-time 5 "$SERVER_URL/health" > /dev/null 2>&1; then
    echo "   ✅ Server is reachable"
elif curl -s -f --max-time 5 "$SERVER_URL/api/v1/system/health" > /dev/null 2>&1; then
    echo "   ✅ Server is reachable (via /api/v1/system/health)"
else
    echo "   ❌ Server is not reachable"
    echo "      Make sure the API server is running on $SERVER_URL"
    exit 1
fi

# Test 2: Health endpoint
echo ""
echo "2️⃣  Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s "$SERVER_URL/health" 2>/dev/null || curl -s "$SERVER_URL/api/v1/system/health" 2>/dev/null)
if [ -n "$HEALTH_RESPONSE" ]; then
    echo "   ✅ Health endpoint responds"
    echo "   Response: $HEALTH_RESPONSE"
else
    echo "   ⚠️  Health endpoint did not respond"
fi

# Test 3: API root
echo ""
echo "3️⃣  Testing API root..."
API_ROOT=$(curl -s "$SERVER_URL/api" 2>/dev/null || curl -s "$SERVER_URL/" 2>/dev/null)
if [ -n "$API_ROOT" ]; then
    echo "   ✅ API root responds"
else
    echo "   ⚠️  API root did not respond"
fi

# Test 4: Agent registration endpoint (should exist even if auth required)
echo ""
echo "4️⃣  Testing agent registration endpoint..."
REGISTER_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$SERVER_URL/api/v1/agents/register" -X POST -H "Content-Type: application/json" -d '{}' 2>/dev/null)
if [ "$REGISTER_RESPONSE" = "200" ] || [ "$REGISTER_RESPONSE" = "400" ] || [ "$REGISTER_RESPONSE" = "422" ]; then
    echo "   ✅ Agent registration endpoint exists (HTTP $REGISTER_RESPONSE)"
else
    echo "   ⚠️  Agent registration endpoint returned HTTP $REGISTER_RESPONSE"
fi

# Test 5: Check if agent config exists
echo ""
echo "5️⃣  Checking agent configuration..."
if [ -f "agent_config.yaml" ]; then
    echo "   ✅ Agent config file exists"
    CONFIG_URL=$(grep -E "^[[:space:]]*url:" agent_config.yaml | head -n 1 | awk '{print $2}' | tr -d '"' | tr -d "'")
    if [ -n "$CONFIG_URL" ]; then
        echo "   Configured URL: $CONFIG_URL"
        if [ "$CONFIG_URL" = "$SERVER_URL" ]; then
            echo "   ✅ Config URL matches test URL"
        else
            echo "   ⚠️  Config URL ($CONFIG_URL) differs from test URL ($SERVER_URL)"
        fi
    fi
else
    echo "   ⚠️  Agent config file not found (run 'configure' first)"
fi

echo ""
echo "✅ Connection test complete!"
echo ""
echo "Next steps:"
echo "  1. If server is not running, start it: ./scripts/start-api-server.sh"
echo "  2. Configure agent: python3 -m fubar_agent.cli configure"
echo "  3. Start agent: python3 -m fubar_agent.cli start"

