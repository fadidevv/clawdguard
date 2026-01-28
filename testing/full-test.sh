#!/bin/bash
#
# ClawdGuard Test Suite
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASSED=0
FAILED=0

print_header() {
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
}

print_test() {
    echo -e "${YELLOW}▶ $1${NC}"
}

print_pass() {
    echo -e "${GREEN}  ✓ $1${NC}"
    PASSED=$((PASSED + 1))
}

print_fail() {
    echo -e "${RED}  ✗ $1${NC}"
    FAILED=$((FAILED + 1))
}

print_info() {
    echo -e "  $1"
}

cleanup() {
    pkill -f "node /mock-gateway/server.js" 2>/dev/null || true
    rm -rf ~/.moltbot ~/.clawdbot 2>/dev/null || true
}

start_gateway() {
    node /mock-gateway/server.js &
    GATEWAY_PID=$!
    sleep 2
}

stop_gateway() {
    pkill -f "node /mock-gateway/server.js" 2>/dev/null || true
    sleep 1
}

check_port_open() {
    nc -z -w2 $1 $2 2>/dev/null
    return $?
}

check_auth_required() {
    local response=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18789/ 2>/dev/null)
    [ "$response" == "401" ] || [ "$response" == "403" ]
    return $?
}

print_header "ClawdGuard Test Suite"
cleanup

# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Vulnerable Moltbot
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 1: Vulnerable Moltbot (~/.moltbot/)"

print_test "Setup"
mkdir -p ~/.moltbot
cp /test-configs/vulnerable-moltbot.json ~/.moltbot/moltbot.json
chmod 666 ~/.moltbot/moltbot.json
chmod 777 ~/.moltbot

print_test "Start gateway"
start_gateway

print_test "Verify exposed"
if check_port_open 0.0.0.0 18789; then
    print_pass "Gateway on 0.0.0.0:18789"
else
    print_fail "Gateway not listening"
fi

print_test "Verify no auth"
if ! check_auth_required; then
    print_pass "No auth required"
else
    print_fail "Auth unexpectedly required"
fi

print_test "Run clawdguard --scan-only"
echo ""
clawdguard --scan-only --verbose || true
echo ""

print_test "Run clawdguard --auto"
echo ""
clawdguard --auto --verbose || true
echo ""

print_test "Verify config patched"
if grep -q '"bind".*"loopback"' ~/.moltbot/moltbot.json; then
    print_pass "bind = loopback"
else
    print_fail "bind not changed"
fi

if grep -q '"mode".*"token"' ~/.moltbot/moltbot.json; then
    print_pass "auth.mode = token"
else
    print_fail "auth.mode not changed"
fi

if grep -q '"token".*"clwd_' ~/.moltbot/moltbot.json; then
    print_pass "token generated"
else
    print_fail "token not generated"
fi

print_test "Verify backup"
if ls ~/.moltbot/moltbot.json.backup.* 1>/dev/null 2>&1; then
    print_pass "Backup created"
else
    print_fail "No backup"
fi

print_test "Verify permissions"
PERMS=$(stat -c %a ~/.moltbot/moltbot.json 2>/dev/null || stat -f %Lp ~/.moltbot/moltbot.json)
if [ "$PERMS" == "600" ]; then
    print_pass "Config: 600"
else
    print_fail "Config: $PERMS (expected 600)"
fi

DIR_PERMS=$(stat -c %a ~/.moltbot 2>/dev/null || stat -f %Lp ~/.moltbot)
if [ "$DIR_PERMS" == "700" ]; then
    print_pass "Directory: 700"
else
    print_fail "Directory: $DIR_PERMS (expected 700)"
fi

print_test "Restart gateway"
stop_gateway
start_gateway

print_test "Verify auth required"
sleep 1
if check_auth_required; then
    print_pass "Auth required (401/403)"
else
    print_fail "Auth not required"
fi

stop_gateway
cleanup

# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: Vulnerable Clawdbot (Legacy)
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 2: Vulnerable Clawdbot (~/.clawdbot/)"

print_test "Setup"
mkdir -p ~/.clawdbot
cp /test-configs/vulnerable-clawdbot.json ~/.clawdbot/clawdbot.json
chmod 644 ~/.clawdbot/clawdbot.json

print_test "Start gateway"
start_gateway

print_test "Run clawdguard --auto"
echo ""
clawdguard --auto --verbose || true
echo ""

print_test "Verify config patched"
if grep -q '"bind".*"loopback"' ~/.clawdbot/clawdbot.json; then
    print_pass "bind = loopback"
else
    print_fail "bind not changed"
fi

if grep -q '"mode".*"token"' ~/.clawdbot/clawdbot.json; then
    print_pass "auth.mode = token"
else
    print_fail "auth.mode not changed"
fi

stop_gateway
cleanup

# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Already Secure
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 3: Already Secure"

print_test "Setup"
mkdir -p ~/.moltbot
cp /test-configs/secure-moltbot.json ~/.moltbot/moltbot.json
chmod 600 ~/.moltbot/moltbot.json
chmod 700 ~/.moltbot

print_test "Start gateway"
start_gateway

print_test "Run clawdguard"
echo ""
OUTPUT=$(clawdguard --verbose 2>&1) || true
echo "$OUTPUT"
echo ""

print_test "Verify detected as secure"
if echo "$OUTPUT" | grep -qi "secure\|no.*changes\|no.*issues"; then
    print_pass "Detected as secure"
else
    print_fail "Not detected as secure"
fi

stop_gateway
cleanup

# ─────────────────────────────────────────────────────────────────────────────
# TEST 4: No Installation
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 4: No Installation"

print_test "Ensure no config"
rm -rf ~/.moltbot ~/.clawdbot

print_test "Run clawdguard"
echo ""
OUTPUT=$(clawdguard --verbose 2>&1) || true
echo "$OUTPUT"
echo ""

print_test "Verify not found message"
if echo "$OUTPUT" | grep -qi "not found\|no.*installation"; then
    print_pass "Shows not found"
else
    print_fail "Missing not found message"
fi

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5: JSON Output
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 5: JSON Output"

print_test "Setup"
mkdir -p ~/.moltbot
cp /test-configs/vulnerable-moltbot.json ~/.moltbot/moltbot.json

print_test "Start gateway"
start_gateway

print_test "Run clawdguard --json"
echo ""
JSON_OUTPUT=$(clawdguard --auto --json 2>/dev/null) || true
echo "$JSON_OUTPUT"
echo ""

print_test "Verify valid JSON"
if echo "$JSON_OUTPUT" | jq . >/dev/null 2>&1; then
    print_pass "Valid JSON"
else
    print_fail "Invalid JSON"
fi

print_test "Verify JSON fields"
if echo "$JSON_OUTPUT" | jq -e '.status' >/dev/null 2>&1; then
    print_pass "Has status field"
else
    print_fail "Missing status field"
fi

stop_gateway
cleanup

# ─────────────────────────────────────────────────────────────────────────────
# TEST 6: mDNS Fix
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 6: mDNS Mode"

print_test "Setup with mdns=full"
mkdir -p ~/.moltbot
cp /test-configs/vulnerable-moltbot.json ~/.moltbot/moltbot.json

print_test "Run clawdguard --auto"
echo ""
clawdguard --auto --verbose || true
echo ""

print_test "Verify mdns=minimal"
if grep -q '"mode".*"minimal"' ~/.moltbot/moltbot.json; then
    print_pass "mdns.mode = minimal"
else
    print_fail "mdns.mode not changed"
fi

cleanup

# ─────────────────────────────────────────────────────────────────────────────
# TEST 7: Idempotency
# ─────────────────────────────────────────────────────────────────────────────

print_header "Test 7: Idempotency"

print_test "Setup"
mkdir -p ~/.moltbot
cp /test-configs/vulnerable-moltbot.json ~/.moltbot/moltbot.json

print_test "First run"
clawdguard --auto >/dev/null 2>&1 || true

print_test "Save hash"
HASH1=$(md5sum ~/.moltbot/moltbot.json | cut -d' ' -f1)

print_test "Second run"
clawdguard --auto >/dev/null 2>&1 || true

print_test "Compare hash"
HASH2=$(md5sum ~/.moltbot/moltbot.json | cut -d' ' -f1)

if [ "$HASH1" == "$HASH2" ]; then
    print_pass "Config unchanged on second run"
else
    print_fail "Config changed on second run"
fi

cleanup

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────────────────────────────────

print_header "Results"

echo ""
echo -e "  ${GREEN}Passed: $PASSED${NC}"
echo -e "  ${RED}Failed: $FAILED${NC}"
echo ""

TOTAL=$((PASSED + FAILED))

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}  $PASSED/$TOTAL passed${NC}"
    echo -e "${GREEN}────────────────────────────────────────────────────────────────${NC}"
    exit 0
else
    echo -e "${RED}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${RED}  $FAILED/$TOTAL failed${NC}"
    echo -e "${RED}────────────────────────────────────────────────────────────────${NC}"
    exit 1
fi
