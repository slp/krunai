// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

use crate::config;
use crate::network_proxy::{NetworkProxy, ProxyConfig, ProxyHandle, ProxyPair};

/// passt implementation for Linux
pub struct PasstImpl;

impl NetworkProxy for PasstImpl {
    fn start(config: &ProxyConfig) -> io::Result<ProxyHandle> {
        // Remove existing socket if it exists

        let _ = std::fs::remove_file(&config.socket_path);

        let mut cmd = Command::new("passt");

        let (parent_socket, child_socket) = UnixStream::pair().unwrap();

        cmd.arg("--fd").arg(format!("{}", child_socket.as_raw_fd()));

        // Configure in foreground mode (so we can manage the process)
        cmd.arg("--foreground");

        // Configure port forwarding if SSH port is specified
        if let Some(ssh_port) = config.ssh_port {
            // passt uses different format: -t <host_port>:<guest_port>
            cmd.arg("-t").arg(format!("{}:22", ssh_port));
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
                    "passt not found in PATH. Please install passt.",
                )
            } else {
                e
            }
        })?;

        Ok(ProxyHandle {
            child,
            socket_path: config.socket_path.clone(),
            socket_pair: Some(ProxyPair {
                parent: parent_socket,
                _child: child_socket,
            }),
            proxy_type: "passt",
        })
    }

    fn name() -> &'static str {
        "passt"
    }
}
