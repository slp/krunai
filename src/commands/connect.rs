// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::process::Command;

use crate::config;
use crate::utils;
use crate::KrunaiConfig;

/// Connect to a VM via SSH
#[derive(Args, Debug)]
pub struct ConnectCmd {
    /// Name of the VM to connect to
    name: String,

    /// User to connect as (default: agent)
    #[arg(short, long, default_value = "agent")]
    user: String,

    /// Additional SSH options to pass through
    #[arg(short = 'o', long = "option")]
    ssh_options: Vec<String>,

    /// Command to execute on the remote VM (optional)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

impl ConnectCmd {
    pub fn run(self, cfg: &KrunaiConfig) {
        let name = self.name;

        // Check if VM exists
        let vmcfg = match cfg.vmconfig_map.get(&name) {
            Some(vm) => vm,
            None => {
                eprintln!("VM '{}' not found", name);
                std::process::exit(-1);
            }
        };

        // Check if VM is running
        if !utils::is_vm_running(&name) {
            eprintln!(
                "Error: Cannot connect to VM '{}' because it is not running",
                name
            );
            eprintln!("Start the VM first with: krunai start {}", name);
            std::process::exit(-1);
        }

        // Find SSH port
        let ssh_port = match vmcfg
            .mapped_ports
            .iter()
            .find(|(_, guest_port)| guest_port.as_str() == "22")
        {
            Some((host_port, _)) => host_port,
            None => {
                eprintln!("VM '{}' does not have SSH port (22) mapped", name);
                eprintln!("Use 'krunai list -v' to see port mappings");
                std::process::exit(-1);
            }
        };

        // Get SSH key path
        let ssh_key_path = match config::get_vm_ssh_key_path(&name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error getting SSH key path: {}", e);
                std::process::exit(-1);
            }
        };

        // Check if SSH key exists
        if !ssh_key_path.exists() {
            eprintln!("SSH key not found: {}", ssh_key_path.display());
            eprintln!("The VM may have been created before SSH key generation was implemented.");
            std::process::exit(-1);
        }

        // Build SSH command
        let mut cmd = Command::new("ssh");

        // Add identity file
        cmd.arg("-i").arg(&ssh_key_path);

        // Add port
        cmd.arg("-p").arg(ssh_port);

        // Add common options for better UX
        cmd.arg("-o").arg("StrictHostKeyChecking=no");
        cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
        cmd.arg("-o").arg("LogLevel=ERROR");

        // Add user-provided SSH options
        for option in &self.ssh_options {
            cmd.arg("-o").arg(option);
        }

        // Add user@host
        cmd.arg(format!("{}@localhost", self.user));

        // Add optional command
        if !self.command.is_empty() {
            cmd.args(&self.command);
        }

        // Execute SSH
        let status = cmd.status();

        match status {
            Ok(exit_status) => {
                if let Some(code) = exit_status.code() {
                    std::process::exit(code);
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    eprintln!("Error: ssh command not found. Please install OpenSSH client.");
                } else {
                    eprintln!("Error executing ssh: {}", e);
                }
                std::process::exit(-1);
            }
        }
    }
}
