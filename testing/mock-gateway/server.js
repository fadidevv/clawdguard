#!/usr/bin/env node
/**
 * Mock Moltbot/Clawdbot Gateway Server
 *
 * Simulates the real gateway for testing ClawdGuard.
 * Behavior matches actual Moltbot gateway:
 * - Listens on port 18789
 * - Binds to configured address (0.0.0.0 or 127.0.0.1)
 * - Enforces authentication if configured
 * - Responds with appropriate HTTP status codes
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// Configuration paths (same as real Moltbot)
const CONFIG_PATHS = [
    path.join(process.env.HOME, '.moltbot', 'moltbot.json'),
    path.join(process.env.HOME, '.clawdbot', 'clawdbot.json'),
];

const DEFAULT_PORT = 18789;

// Load configuration
function loadConfig() {
    for (const configPath of CONFIG_PATHS) {
        try {
            if (fs.existsSync(configPath)) {
                const content = fs.readFileSync(configPath, 'utf8');
                const config = JSON.parse(content);
                console.log(`[Gateway] Loaded config from: ${configPath}`);
                return { config, path: configPath };
            }
        } catch (e) {
            console.error(`[Gateway] Error loading ${configPath}:`, e.message);
        }
    }
    console.log('[Gateway] No config found, using defaults');
    return { config: {}, path: null };
}

// Determine bind address from config
function getBindAddress(config) {
    const bind = config?.gateway?.bind || 'loopback';
    switch (bind.toLowerCase()) {
        case '0.0.0.0':
        case 'all':
        case 'lan':
            return '0.0.0.0';
        case 'loopback':
        case '127.0.0.1':
        case 'localhost':
            return '127.0.0.1';
        default:
            // Unknown = treat as dangerous (0.0.0.0)
            if (bind.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                return bind;
            }
            return '0.0.0.0';
    }
}

// Check if request is authenticated
function isAuthenticated(req, config) {
    const authConfig = config?.gateway?.auth || {};
    const authMode = authConfig.mode || 'none';

    // No auth required
    if (authMode === 'none' || (!authConfig.token && !authConfig.password)) {
        return true;
    }

    // Check for token in header
    const authHeader = req.headers['authorization'] || '';
    const token = authConfig.token;
    const password = authConfig.password;

    if (token && authHeader === `Bearer ${token}`) {
        return true;
    }

    if (password && authHeader === `Bearer ${password}`) {
        return true;
    }

    // Check localhost bypass (real Moltbot does this)
    const remoteAddr = req.socket.remoteAddress || '';
    if (remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1') {
        // Localhost bypass only if explicitly checking from localhost
        // For testing, we don't bypass to properly test auth
    }

    return false;
}

// Check if auth is configured
function isAuthConfigured(config) {
    const authConfig = config?.gateway?.auth || {};
    const authMode = authConfig.mode || 'none';
    return authMode !== 'none' && (authConfig.token || authConfig.password);
}

// Create and start server
function startServer() {
    const { config, path: configPath } = loadConfig();
    const bindAddress = getBindAddress(config);
    const port = config?.gateway?.port || DEFAULT_PORT;

    console.log('[Gateway] Configuration:');
    console.log(`  - Config path: ${configPath || 'none'}`);
    console.log(`  - Bind address: ${bindAddress}`);
    console.log(`  - Port: ${port}`);
    console.log(`  - Auth mode: ${config?.gateway?.auth?.mode || 'none'}`);
    console.log(`  - Auth configured: ${isAuthConfigured(config)}`);

    const server = http.createServer((req, res) => {
        // Reload config on each request (to pick up changes)
        const { config: currentConfig } = loadConfig();

        console.log(`[Gateway] ${req.method} ${req.url} from ${req.socket.remoteAddress}`);

        // Check authentication
        if (!isAuthenticated(req, currentConfig)) {
            console.log('[Gateway] -> 401 Unauthorized');
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Unauthorized', message: 'Authentication required' }));
            return;
        }

        // Health check endpoint
        if (req.url === '/health' || req.url === '/') {
            console.log('[Gateway] -> 200 OK');
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: 'ok',
                gateway: 'mock-moltbot',
                version: '1.0.0',
                bind: bindAddress,
                port: port,
                auth: isAuthConfigured(currentConfig) ? 'enabled' : 'disabled'
            }));
            return;
        }

        // Default response
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
    });

    server.listen(port, bindAddress, () => {
        console.log(`[Gateway] Listening on ${bindAddress}:${port}`);
    });

    // Handle config file changes (watch for ClawdGuard patches)
    if (configPath) {
        fs.watch(path.dirname(configPath), (eventType, filename) => {
            if (filename && filename.endsWith('.json')) {
                console.log(`[Gateway] Config changed: ${filename}`);
                // Server will reload config on next request
            }
        });
    }

    // Graceful shutdown
    process.on('SIGTERM', () => {
        console.log('[Gateway] Shutting down...');
        server.close(() => {
            console.log('[Gateway] Stopped.');
            process.exit(0);
        });
    });

    process.on('SIGINT', () => {
        console.log('[Gateway] Interrupted, shutting down...');
        server.close(() => {
            process.exit(0);
        });
    });
}

// Start the server
startServer();
