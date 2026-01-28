//! Port accessibility verification.
//!
//! Tests network connectivity to verify that security fixes are effective.
//! Checks both external accessibility (should be blocked) and localhost
//! accessibility (should still work).
//!
//! ## Verification Strategy
//!
//! 1. Determine machine's LAN IP address
//! 2. Attempt TCP connection from LAN IP to gateway port
//! 3. If connection fails, port is properly secured
//! 4. Verify localhost still accepts connections

use std::net::TcpStream;
use std::time::Duration;

/// Verifies that the gateway port is closed to external access.
///
/// Attempts to connect to the gateway from the machine's LAN IP.
/// If the connection fails (timeout or refused), the port is considered
/// properly secured against external access.
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// `true` if the port is closed (connection fails),
/// `false` if the port is still accessible.
///
/// # Note
///
/// Returns `true` if LAN IP cannot be determined, assuming the port
/// is inaccessible without a valid external address.
pub async fn verify_port_closed(verbose: bool) -> bool {
    // Determine machine's LAN IP address
    let lan_ip = match local_ip_address::local_ip() {
        Ok(ip) => ip.to_string(),
        Err(e) => {
            if verbose {
                eprintln!("Could not determine LAN IP: {}", e);
            }
            // Assume closed if we can't determine LAN IP
            return true;
        }
    };

    let addr = format!("{}:{}", lan_ip, crate::DEFAULT_PORT);

    if verbose {
        eprintln!(
            "Checking if port {} is closed on {}",
            crate::DEFAULT_PORT,
            lan_ip
        );
    }

    // Attempt connection - failure indicates port is secured
    let is_closed =
        TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2)).is_err();

    if verbose {
        if is_closed {
            eprintln!("  -> Port is CLOSED (good)");
        } else {
            eprintln!("  -> Port is still OPEN (may need firewall)");
        }
    }

    is_closed
}

/// Verifies that the gateway is still accessible on localhost.
///
/// Attempts to connect to the gateway on 127.0.0.1 to ensure local
/// access still works after applying security fixes.
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// `true` if localhost is accessible (connection succeeds),
/// `false` if the gateway is not responding locally.
pub fn verify_localhost_access(verbose: bool) -> bool {
    let addr = format!("127.0.0.1:{}", crate::DEFAULT_PORT);

    if verbose {
        eprintln!("Checking localhost access on port {}", crate::DEFAULT_PORT);
    }

    // Attempt connection - success indicates gateway is running
    let is_accessible =
        TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(2)).is_ok();

    if verbose {
        if is_accessible {
            eprintln!("  -> Localhost is accessible (good)");
        } else {
            eprintln!("  -> Localhost is NOT accessible (gateway may need restart)");
        }
    }

    is_accessible
}

/// Waits for the gateway to become available on localhost.
///
/// Repeatedly attempts to connect to the gateway until successful
/// or the timeout is reached. Useful after restarting the service.
///
/// # Arguments
///
/// * `timeout_secs` - Maximum seconds to wait for the gateway.
///
/// # Returns
///
/// `true` if the gateway became available within the timeout,
/// `false` if the timeout was reached without success.
///
/// # Example
///
/// ```rust,ignore
/// // Wait up to 10 seconds for gateway to start
/// if wait_for_gateway(10) {
///     println!("Gateway is ready");
/// } else {
///     println!("Gateway did not start in time");
/// }
/// ```
#[allow(dead_code)]
pub fn wait_for_gateway(timeout_secs: u64) -> bool {
    let addr = format!("127.0.0.1:{}", crate::DEFAULT_PORT);
    let start = std::time::Instant::now();

    // Poll until gateway responds or timeout
    while start.elapsed().as_secs() < timeout_secs {
        if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_ok() {
            return true;
        }
        // Brief pause between attempts
        std::thread::sleep(Duration::from_millis(500));
    }

    false
}
