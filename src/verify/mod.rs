//! Fix verification module.
//!
//! Verifies that applied security patches are effective by testing
//! network accessibility, localhost connectivity, and authentication
//! enforcement.
//!
//! ## Verification Checks
//!
//! | Check | Pass Condition | Failure Meaning |
//! |-------|----------------|-----------------|
//! | Port closed | Cannot connect from LAN IP | Gateway still exposed |
//! | Localhost works | Can connect to 127.0.0.1 | Gateway not running |
//! | Auth required | HTTP 401/403 response | Auth not enforced |

mod port_check;
mod service;

pub use port_check::{verify_localhost_access, verify_port_closed};
pub use service::restart_service;

use crate::detect::Installation;

/// Results of security fix verification.
///
/// Contains the outcome of each verification check performed
/// after applying security patches.
#[derive(Debug, Clone, Default)]
pub struct VerificationResult {
    /// Whether the port is no longer accessible from external networks.
    /// True indicates the bind fix is working correctly.
    pub port_closed: bool,

    /// Whether the gateway responds on localhost (127.0.0.1).
    /// True indicates the gateway is running and accessible locally.
    pub localhost_works: bool,

    /// Whether authentication is being enforced.
    /// True indicates unauthenticated requests are rejected.
    pub auth_required: bool,
}

/// Verifies that applied security fixes are effective.
///
/// Performs a series of tests to confirm:
/// 1. The gateway port is not accessible from external networks
/// 2. The gateway is still accessible on localhost
/// 3. Authentication is being enforced (401/403 responses)
///
/// # Arguments
///
/// * `_installation` - The installation being verified (currently unused).
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// A [`VerificationResult`] containing the outcome of all checks.
///
/// # Errors
///
/// This function does not currently return errors; all failures are
/// captured in the result struct.
///
/// # Example
///
/// ```rust,ignore
/// let result = verify_fixes(&installation, false).await?;
/// if result.port_closed && result.auth_required {
///     println!("All security fixes verified!");
/// }
/// ```
pub async fn verify_fixes(
    _installation: &Installation,
    verbose: bool,
) -> Result<VerificationResult, String> {
    let mut result = VerificationResult::default();

    // Check 1: Verify port is closed to external access
    result.port_closed = verify_port_closed(verbose).await;

    // Check 2: Verify localhost access still works
    result.localhost_works = verify_localhost_access(verbose);

    // Check 3: Verify authentication is enforced
    result.auth_required = verify_auth_required(verbose).await;

    Ok(result)
}

/// Verifies that authentication is being enforced by the gateway.
///
/// Sends an unauthenticated HTTP request and checks if the gateway
/// responds with 401 Unauthorized or 403 Forbidden.
///
/// # Arguments
///
/// * `verbose` - Enable diagnostic output.
///
/// # Returns
///
/// `true` if authentication is enforced (401/403 response),
/// `false` if unauthenticated access is allowed or gateway is unreachable.
async fn verify_auth_required(verbose: bool) -> bool {
    let url = format!("http://127.0.0.1:{}/", crate::DEFAULT_PORT);

    // Build HTTP client with timeout
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Send unauthenticated request
    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let auth_required = status == 401 || status == 403;

            if verbose {
                eprintln!(
                    "Auth check: status={}, auth_required={}",
                    status, auth_required
                );
            }

            auth_required
        }
        Err(e) => {
            if verbose {
                eprintln!("Auth check failed: {}", e);
            }
            false
        }
    }
}
