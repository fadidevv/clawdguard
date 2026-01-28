//! Configuration risk analysis.
//!
//! Analyzes Clawdbot/Moltbot configuration files to identify security vulnerabilities
//! in gateway binding, authentication, and service discovery settings.
//!
//! ## Security Checks
//!
//! | Setting | Safe Values | Dangerous Values |
//! |---------|-------------|------------------|
//! | `gateway.bind` | loopback, 127.0.0.1, localhost | 0.0.0.0, all, lan, tailnet |
//! | `gateway.auth.mode` | token, password | none, (missing) |
//! | `discovery.mdns.mode` | minimal, off | full |

use serde_json::Value;

/// Bind values that restrict access to localhost only.
/// These are considered safe as they prevent network exposure.
const SAFE_BIND_VALUES: &[&str] = &["loopback", "127.0.0.1", "localhost"];

/// Bind values that expose the gateway to the network.
/// Any of these values creates a critical security vulnerability.
const DANGEROUS_BIND_VALUES: &[&str] = &["0.0.0.0", "all", "lan", "tailnet", "custom"];

/// Authentication modes that provide security.
/// Token-based auth is preferred; password auth is acceptable.
const SECURE_AUTH_MODES: &[&str] = &["token", "password"];

/// Results of configuration security analysis.
///
/// Contains flags indicating which security issues were found
/// and the current values of analyzed settings.
#[derive(Debug, Clone, Default)]
pub struct ConfigRisk {
    /// Whether the gateway bind address exposes the service to the network.
    /// True if bound to 0.0.0.0, lan, all, or any non-loopback address.
    pub bind_exposed: bool,

    /// The current gateway bind value (e.g., "0.0.0.0", "loopback").
    pub bind_value: Option<String>,

    /// Whether authentication is missing or improperly configured.
    /// True if auth mode is not "token" or "password", or if no credential is set.
    pub auth_missing: bool,

    /// The current authentication mode (e.g., "none", "token").
    pub auth_mode: Option<String>,

    /// Whether a valid authentication credential (token or password) exists.
    pub has_auth_credential: bool,

    /// Whether mDNS is broadcasting sensitive system information.
    /// True if mDNS mode is "full" which leaks system details.
    pub mdns_leaking: bool,

    /// The current mDNS broadcast mode (e.g., "full", "minimal", "off").
    pub mdns_mode: Option<String>,
}

/// Analyzes a configuration file for security vulnerabilities.
///
/// Performs comprehensive security analysis on gateway binding,
/// authentication, and mDNS discovery settings.
///
/// # Arguments
///
/// * `config` - Parsed JSON configuration to analyze.
/// * `verbose` - When true, prints detailed diagnostic information to stderr.
///
/// # Returns
///
/// A [`ConfigRisk`] struct containing all identified vulnerabilities.
///
/// # Example
///
/// ```rust,ignore
/// let config: serde_json::Value = serde_json::from_str(&config_str)?;
/// let risks = analyze_config(&config, false);
/// if risks.bind_exposed {
///     println!("Gateway is exposed to network!");
/// }
/// ```
pub fn analyze_config(config: &Value, verbose: bool) -> ConfigRisk {
    let mut risk = ConfigRisk::default();

    // Analyze each security-critical setting
    analyze_bind_setting(config, &mut risk, verbose);
    analyze_auth_setting(config, &mut risk, verbose);
    analyze_mdns_setting(config, &mut risk, verbose);

    risk
}

/// Analyzes the gateway bind setting for network exposure.
///
/// Checks `gateway.bind` in the configuration and determines if it
/// exposes the service to the network or restricts it to localhost.
///
/// # Arguments
///
/// * `config` - The configuration JSON to analyze.
/// * `risk` - Mutable reference to populate with findings.
/// * `verbose` - Enable diagnostic output.
fn analyze_bind_setting(config: &Value, risk: &mut ConfigRisk, verbose: bool) {
    // Extract gateway.bind value, converting to lowercase for comparison
    let bind_value = config
        .get("gateway")
        .and_then(|g| g.get("bind"))
        .and_then(|b| b.as_str())
        .map(|s| s.to_lowercase());

    if verbose {
        eprintln!("Analyzing bind setting: {:?}", bind_value);
    }

    match &bind_value {
        Some(bind) => {
            risk.bind_value = Some(bind.clone());

            // Check if the bind value is in the safe list
            let is_safe = SAFE_BIND_VALUES
                .iter()
                .any(|safe| bind.eq_ignore_ascii_case(safe));

            // Check if the bind value is explicitly dangerous
            let is_dangerous = DANGEROUS_BIND_VALUES
                .iter()
                .any(|dangerous| bind.eq_ignore_ascii_case(dangerous));

            // Mark as exposed if dangerous OR not explicitly safe
            risk.bind_exposed = is_dangerous || !is_safe;

            if verbose && risk.bind_exposed {
                eprintln!("  -> EXPOSED: bind='{}' is not a safe value", bind);
            }
        }
        None => {
            // No bind setting means default (loopback) which is safe
            risk.bind_value = Some("loopback (default)".to_string());
            risk.bind_exposed = false;

            if verbose {
                eprintln!("  -> SAFE: no bind setting, using default (loopback)");
            }
        }
    }
}

/// Analyzes authentication configuration for security.
///
/// Checks `gateway.auth.mode` and verifies that a valid credential
/// (token or password) is configured when using secure auth modes.
///
/// # Arguments
///
/// * `config` - The configuration JSON to analyze.
/// * `risk` - Mutable reference to populate with findings.
/// * `verbose` - Enable diagnostic output.
fn analyze_auth_setting(config: &Value, risk: &mut ConfigRisk, verbose: bool) {
    let auth = config.get("gateway").and_then(|g| g.get("auth"));

    if verbose {
        eprintln!("Analyzing auth setting: {:?}", auth);
    }

    match auth {
        Some(auth_config) => {
            // Extract authentication mode
            let mode = auth_config
                .get("mode")
                .and_then(|m| m.as_str())
                .map(|s| s.to_lowercase());

            risk.auth_mode = mode.clone();

            // Check if mode is one of the secure options
            let mode_is_secure = mode
                .as_ref()
                .map(|m| SECURE_AUTH_MODES.iter().any(|s| m.eq_ignore_ascii_case(s)))
                .unwrap_or(false);

            // Check for token credential (non-empty string)
            let has_token = auth_config
                .get("token")
                .and_then(|t| t.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            // Check for password credential (non-empty string)
            let has_password = auth_config
                .get("password")
                .and_then(|p| p.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or(false);

            risk.has_auth_credential = has_token || has_password;

            // Auth is missing if mode is insecure OR no credential is set
            risk.auth_missing = !mode_is_secure || !risk.has_auth_credential;

            if verbose {
                if risk.auth_missing {
                    eprintln!(
                        "  -> MISSING AUTH: mode={:?}, has_credential={}",
                        mode, risk.has_auth_credential
                    );
                } else {
                    eprintln!("  -> AUTH OK: mode={:?}", mode);
                }
            }
        }
        None => {
            // No auth configuration at all - definitely insecure
            risk.auth_mode = None;
            risk.auth_missing = true;
            risk.has_auth_credential = false;

            if verbose {
                eprintln!("  -> NO AUTH CONFIG: treating as potentially insecure");
            }
        }
    }
}

/// Analyzes mDNS discovery settings for information leakage.
///
/// Checks `discovery.mdns.mode` to determine if sensitive system
/// information is being broadcast on the local network.
///
/// # Arguments
///
/// * `config` - The configuration JSON to analyze.
/// * `risk` - Mutable reference to populate with findings.
/// * `verbose` - Enable diagnostic output.
fn analyze_mdns_setting(config: &Value, risk: &mut ConfigRisk, verbose: bool) {
    // Navigate to discovery.mdns.mode
    let mdns_mode = config
        .get("discovery")
        .and_then(|d| d.get("mdns"))
        .and_then(|m| m.get("mode"))
        .and_then(|m| m.as_str())
        .map(|s| s.to_lowercase());

    if verbose {
        eprintln!("Analyzing mDNS setting: {:?}", mdns_mode);
    }

    risk.mdns_mode = mdns_mode.clone();

    // Determine if mDNS is leaking information
    risk.mdns_leaking = match mdns_mode.as_deref() {
        Some("full") => true,           // Full broadcast leaks system info
        Some("minimal") | Some("off") => false, // Safe modes
        None => false,                  // No mDNS config is safe
        Some(_) => true,                // Unknown modes treated as risky
    };

    if verbose {
        if risk.mdns_leaking {
            eprintln!("  -> LEAKING: mDNS mode broadcasts sensitive info");
        } else {
            eprintln!("  -> OK: mDNS mode is safe");
        }
    }
}

/// Checks if a configuration value at a given path matches an expected value.
///
/// Navigates through nested JSON objects using a dot-separated path
/// and performs a case-insensitive string comparison.
///
/// # Arguments
///
/// * `config` - The root configuration JSON.
/// * `path` - Dot-separated path to the value (e.g., "gateway.auth.mode").
/// * `expected` - The expected value to compare against.
///
/// # Returns
///
/// `true` if the value exists and matches (case-insensitive), `false` otherwise.
#[allow(dead_code)]
pub fn config_value_matches(config: &Value, path: &str, expected: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = config;

    // Navigate through nested objects
    for part in parts {
        match current.get(part) {
            Some(v) => current = v,
            None => return false,
        }
    }

    // Compare string value (case-insensitive)
    current
        .as_str()
        .map(|s| s.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}
