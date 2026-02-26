// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, ErrorKind};
use std::process::{Command, Stdio};

use crate::config;
use crate::network_proxy::{NetworkProxy, ProxyConfig, ProxyHandle};

/// gvproxy implementation for macOS
pub struct GvproxyImpl;

impl NetworkProxy for GvproxyImpl {
    fn start(config: &ProxyConfig) -> io::Result<ProxyHandle> {
        // Check for existing gvproxy processes using this socket and kill them
        if let Ok(output) = Command::new("ps").arg("aux").output() {
            if output.status.success() {
                let ps_output = String::from_utf8_lossy(&output.stdout);
                for line in ps_output.lines() {
                    // Look for gvproxy processes with our socket path
                    if line.contains("gvproxy") && line.contains(&config.socket_path) {
                        // Extract PID (second column in ps aux output)
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 1 {
                            if let Ok(pid) = parts[1].parse::<i32>() {
                                // Force kill the process
                                unsafe {
                                    libc::kill(pid, libc::SIGKILL);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Remove existing socket if it exists
        let _ = std::fs::remove_file(&config.socket_path);

        let mut cmd = Command::new("gvproxy");

        // Set the Unix socket for communication
        cmd.arg("-listen-qemu")
            .arg(format!("unix://{}", config.socket_path));

        // Configure SSH port forwarding if specified
        if let Some(ssh_port) = config.ssh_port {
            cmd.arg("-ssh-port").arg(ssh_port.to_string());
        }

        // Redirect stdout/stderr to VM-specific log file
        let log_path = config::get_vm_network_log_path(&config.vm_name)?;
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        cmd.stdout(Stdio::from(log_file.try_clone()?))
            .stderr(Stdio::from(log_file));

        // Spawn the process
        let child = cmd.spawn().map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                io::Error::new(
                    ErrorKind::NotFound,
                    "gvproxy not found in PATH. Please install gvproxy.",
                )
            } else {
                e
            }
        })?;

        // Wait a bit for the socket to be created
        for _ in 0..50 {
            if std::path::Path::new(&config.socket_path).exists() {
                return Ok(ProxyHandle {
                    child,
                    socket_path: config.socket_path.clone(),
                    socket_pair: None,
                    proxy_type: "gvproxy",
                    guest_ip: "192.168.127.2".to_string(),
                    router_ip: "192.168.127.1".to_string(),
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Err(io::Error::new(
            ErrorKind::TimedOut,
            "gvproxy socket was not created in time",
        ))
    }

    fn name() -> &'static str {
        "gvproxy"
    }
}
