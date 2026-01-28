//! Network exposure analysis.
//!
//! Provides functionality to detect if the gateway port is accessible from
//! external networks, indicating a potential security vulnerability.
//!
//! ## Detection Method
//!
//! Tests connectivity by attempting to connect to the gateway port from
//! the machine's LAN IP address. If successful, the port is considered
//! externally reachable and vulnerable to attack.
//!
//! ## Limitations
//!
//! - Only tests from the local machine's perspective
//! - Cannot detect exposure through NAT/port forwarding
//! - Requires the gateway to be running for accurate results

use std::net::TcpStream;
use std::time::Duration;

/// Results of external network exposure analysis.
///
/// Contains information about whether the gateway port is reachable
/// from external network addresses.
#[derive(Debug, Clone, Default)]
pub struct ExposureResult {
    /// Whether the gateway port is reachable from the LAN IP.
    /// True indicates a security vulnerability.
    pub is_reachable: bool,

    /// The external/LAN IP address used for testing.
    /// This is the machine's IP on the local network.
    pub external_ip: Option<String>,
}

/// Checks if the gateway port is accessible from external networks.
///
/// Determines the machine's LAN IP address and attempts to connect
/// to the gateway port. If the connection succeeds, the gateway is
/// exposed and vulnerable to network attacks.
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// An [`ExposureResult`] indicating whether the port is reachable
/// and the IP address used for testing.
///
/// # Example
///
/// ```rust,ignore
/// let exposure = check_external_exposure(false).await;
/// if exposure.is_reachable {
///     println!("WARNING: Gateway is exposed on {}", exposure.external_ip.unwrap());
/// }
/// ```
pub async fn check_external_exposure(verbose: bool) -> ExposureResult {
    let mut result = ExposureResult::default();

    // Determine the machine's LAN IP address
    let lan_ip = match local_ip_address::local_ip() {
        Ok(ip) => {
            result.external_ip = Some(ip.to_string());
            ip.to_string()
        }
        Err(e) => {
            if verbose {
                eprintln!("Could not determine LAN IP: {}", e);
            }
            // Cannot test exposure without knowing LAN IP
            return result;
        }
    };

    if verbose {
        eprintln!("Checking external exposure from LAN IP: {}", lan_ip);
    }

    // Attempt to connect to the gateway port from the LAN IP
    let addr = format!("{}:{}", lan_ip, crate::DEFAULT_PORT);

    result.is_reachable =
        TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2)).is_ok();

    if verbose {
        if result.is_reachable {
            eprintln!(
                "  -> Port {} is REACHABLE from {}",
                crate::DEFAULT_PORT,
                lan_ip
            );
        } else {
            eprintln!(
                "  -> Port {} is NOT reachable from {}",
                crate::DEFAULT_PORT,
                lan_ip
            );
        }
    }

    result
}

/// Checks if the gateway is responding on localhost.
///
/// Attempts to establish a TCP connection to the gateway on 127.0.0.1.
/// Used to verify the gateway is running before other checks.
///
/// # Returns
///
/// `true` if the gateway accepts connections on localhost, `false` otherwise.
#[allow(dead_code)]
pub fn check_localhost_responsive() -> bool {
    let addr = format!("127.0.0.1:{}", crate::DEFAULT_PORT);
    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2)).is_ok()
}

/// Checks if the gateway is enforcing authentication.
///
/// Sends an unauthenticated HTTP request to the gateway and checks
/// if it responds with a 401 (Unauthorized) or 403 (Forbidden) status.
///
/// # Returns
///
/// `true` if authentication is being enforced (401/403 response),
/// `false` if the gateway accepts unauthenticated requests or is unreachable.
#[allow(dead_code)]
pub async fn check_auth_enforced() -> bool {
    let url = format!("http://127.0.0.1:{}/", crate::DEFAULT_PORT);

    // Build HTTP client with timeout
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Send unauthenticated request and check response status
    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            // 401 Unauthorized or 403 Forbidden indicates auth is enforced
            status == 401 || status == 403
        }
        Err(_) => false,
    }
}
