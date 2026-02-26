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

/// Parse DHCP information from passt's stdout
/// Returns (guest_ip, router_ip) with fallback to hardcoded values if parsing fails
fn parse_passt_dhcp_info(
    child_stderr: ChildStderr,
    mut log_file: std::fs::File,
) -> io::Result<(String, String)> {
    let reader = BufReader::new(child_stderr);
    let mut guest_ip: Option<String> = None;
    let mut router_ip: Option<String> = None;
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
    match (guest_ip, router_ip) {
        (Some(guest), Some(router)) => Ok((guest, router)),
        (None, _) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to parse guest IP from passt DHCP output",
        )),
        (_, None) => Err(io::Error::new(
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
        let (guest_ip, router_ip) = parse_passt_dhcp_info(child_stderr, log_file)?;

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
        })
    }

    fn name() -> &'static str {
        "passt"
    }
}
