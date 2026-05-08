// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufRead, BufReader, ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::{ChildStderr, Command, Stdio};
use std::time::Duration;

use nix::unistd::dup;

use crate::config;
use crate::network_proxy::{NetworkProxy, ProxyConfig, ProxyHandle, ProxyPair};

/// passt implementation for Linux
pub struct PasstImpl;

/// Convert dotted decimal netmask to prefix length (e.g. 255.255.255.0 -> 24)
fn netmask_to_prefix(mask: &str) -> Option<u8> {
    let octets: Vec<&str> = mask.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let parts: Result<Vec<u32>, _> = octets.iter().map(|o| o.parse::<u32>()).collect();
    let parts = parts.ok()?;
    let mask_val = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    let ones = mask_val.count_ones();
    if (mask_val >> 31).count_ones() != 0 && mask_val.trailing_zeros() != 0 {
        return None; // Not a contiguous mask
    }
    Some(ones as u8)
}

/// Parse DHCP information from passt's stdout
/// Returns (guest_ip, router_ip, netmask) with fallback to hardcoded values if parsing fails
fn parse_passt_dhcp_info(
    child_stderr: ChildStderr,
    mut log_file: std::fs::File,
) -> io::Result<(String, String, u8)> {
    let reader = BufReader::new(child_stderr);
    let mut guest_ip: Option<String> = None;
    let mut router_ip: Option<String> = None;
    let mut netmask: Option<u8> = None;
    let mut in_dhcp_section = false;

    // Set up timeout using a separate thread
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(5));
        let _ = tx.send(());
    });

    for line_result in reader.lines() {
        // Check for timeout
        if rx.try_recv().is_ok() {
            break;
        }

        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        // Write line to log file
        let _ = writeln!(log_file, "{}", line);

        // Parse DHCP information
        if line.contains("DHCP:") {
            in_dhcp_section = true;
        } else if in_dhcp_section {
            let trimmed = line.trim();
            if trimmed.starts_with("assign:") {
                if let Some(ip) = trimmed.split(':').nth(1) {
                    guest_ip = Some(ip.trim().to_string());
                }
            } else if trimmed.starts_with("router:") {
                if let Some(ip) = trimmed.split(':').nth(1) {
                    router_ip = Some(ip.trim().to_string());
                }
            } else if trimmed.starts_with("mask:") {
                if let Some(mask) = trimmed.split(':').nth(1) {
                    let mask_str = mask.trim();
                    netmask = netmask_to_prefix(mask_str);
                }
            }

            // If we have both IPs, we're done
            if guest_ip.is_some() && router_ip.is_some() {
                break;
            }

            // If we hit a blank line or non-DHCP content, exit DHCP section
            if trimmed.is_empty()
                || (!trimmed.starts_with("assign:")
                    && !trimmed.starts_with("router:")
                    && !trimmed.starts_with("mask:")
                    && !trimmed.starts_with("search:")
                    && !trimmed.starts_with("dns:"))
            {
                in_dhcp_section = false;
            }
        }
    }

    // Return parsed IPs or error if not found
    match (guest_ip, router_ip, netmask) {
        (Some(guest), Some(router), Some(mask)) => Ok((guest, router, mask)),
        (Some(guest), Some(router), None) => Ok((guest, router, 24)),
        (None, _, _) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to parse guest IP from passt DHCP output",
        )),
        (_, None, _) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to parse router IP from passt DHCP output",
        )),
    }
}

impl NetworkProxy for PasstImpl {
    fn start(config: &ProxyConfig) -> io::Result<ProxyHandle> {
        // Remove existing socket if it exists

        let mut cmd = Command::new("passt");

        let (parent_socket, child_socket) = UnixStream::pair().unwrap();
        let parent_fd = dup(parent_socket.as_raw_fd())?;
        let child_fd = dup(child_socket.as_raw_fd())?;

        cmd.arg("--fd").arg(format!("{}", child_fd.as_raw_fd()));

        // Configure in foreground mode (so we can manage the process)
        cmd.arg("--foreground");

        // Tell passt to only use IPv4 to speed up readiness.
        cmd.arg("-4");

        // Configure port forwarding if SSH port is specified
        if let Some(ssh_port) = config.ssh_port {
            // passt uses different format: -t <host_port>:<guest_port>
            cmd.arg("-t").arg(format!("{}:22", ssh_port));
        }

        // Redirect stderr to VM-specific log file, but pipe stdout for parsing
        let log_path = config::get_vm_network_log_path(&config.vm_name)?;
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        // Use piped stdout to parse DHCP info
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                io::Error::new(
                    ErrorKind::NotFound,
                    "passt not found in PATH. Please install passt.",
                )
            } else {
                e
            }
        })?;

        // Take stdout for parsing
        let child_stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("Failed to capture passt stdout"))?;

        // Parse DHCP info (also writes to log)
        let (guest_ip, router_ip, netmask) = parse_passt_dhcp_info(child_stderr, log_file)?;

        Ok(ProxyHandle {
            child,
            socket_path: "".to_string(),
            socket_pair: Some(ProxyPair {
                parent: parent_fd,
                _child: child_fd,
            }),
            proxy_type: "passt",
            guest_ip,
            router_ip,
            netmask,
        })
    }

    fn name() -> &'static str {
        "passt"
    }
}
