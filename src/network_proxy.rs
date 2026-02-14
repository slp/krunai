// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::unix::net::UnixStream;
use std::process::Child;

/// Common configuration for network proxies
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Name of the VM
    #[allow(dead_code)]
    pub vm_name: String,
    /// SSH port to forward (if any)
    pub ssh_port: Option<u16>,
    /// Socket path for communication
    pub socket_path: String,
}

impl ProxyConfig {
    /// Create a new proxy configuration for a VM
    pub fn new(vm_name: &str, ssh_port: Option<u16>) -> io::Result<Self> {
        let socket_path = crate::config::get_vm_socket_path(vm_name)?
            .to_string_lossy()
            .to_string();

        Ok(ProxyConfig {
            vm_name: vm_name.to_string(),
            ssh_port,
            socket_path,
        })
    }
}

pub struct ProxyPair {
    pub parent: UnixStream,
    pub _child: UnixStream,
}

/// Result of starting a network proxy
pub struct ProxyHandle {
    /// The child process
    #[allow(dead_code)]
    pub child: Child,
    /// The socket path
    pub socket_path: String,
    /// The socket fd
    pub socket_pair: Option<ProxyPair>,
    /// Type of proxy for logging
    pub proxy_type: &'static str,
}

/// Trait for network proxy implementations
pub trait NetworkProxy {
    /// Start the network proxy
    fn start(config: &ProxyConfig) -> io::Result<ProxyHandle>;

    /// Get the name of the proxy implementation
    #[allow(dead_code)]
    fn name() -> &'static str;
}

/// Start the appropriate network proxy for the current platform
pub fn start_network_proxy(config: &ProxyConfig) -> io::Result<ProxyHandle> {
    #[cfg(target_os = "macos")]
    {
        crate::gvproxy::GvproxyImpl::start(config)
    }

    #[cfg(target_os = "linux")]
    {
        crate::passt::PasstImpl::start(config)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Network proxy not supported on this platform",
        ))
    }
}

/// Stop a network proxy process
#[allow(dead_code)]
pub fn stop_network_proxy(handle: ProxyHandle) -> io::Result<()> {
    let mut child = handle.child;

    // Try to kill gracefully
    let _ = child.kill();
    let _ = child.wait();

    // Clean up socket
    let _ = std::fs::remove_file(&handle.socket_path);

    Ok(())
}
