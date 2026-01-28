# ClawdGuard Test Suite

End-to-end testing with mock gateway.

## Run Tests

```bash
git clone https://github.com/fadidevv/clawdguard.git
cd clawdguard

# Build
docker build --no-cache -f testing/Dockerfile.fulltest -t clawdguard-fulltest .

# Run
docker run --rm clawdguard-fulltest
```

## Tests

| # | Test | Verifies |
|---|------|----------|
| 1 | Vulnerable Moltbot | ~/.moltbot/ detection, config fix, permissions |
| 2 | Vulnerable Clawdbot | ~/.clawdbot/ legacy path |
| 3 | Already Secure | No changes when secure |
| 4 | No Installation | Error handling |
| 5 | JSON Output | Valid JSON format |
| 6 | mDNS Fix | mdns.mode → minimal |
| 7 | Idempotency | Multiple runs safe |

## Interactive

```bash
docker run --rm -it clawdguard-fulltest bash
```

Inside container:
```bash
mkdir -p ~/.moltbot
cp /test-configs/vulnerable-moltbot.json ~/.moltbot/moltbot.json
node /mock-gateway/server.js &
clawdguard --verbose
cat ~/.moltbot/moltbot.json
```

## macOS Testing

Test natively:
```bash
cargo build --release
mkdir -p ~/.moltbot
echo '{"gateway":{"bind":"0.0.0.0","auth":{}}}' > ~/.moltbot/moltbot.json
./target/release/clawdguard --verbose
cat ~/.moltbot/moltbot.json

# Cleanup
rm -rf ~/.moltbot
```
