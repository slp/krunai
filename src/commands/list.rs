// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;

use crate::config;
use crate::utils;
use crate::{KrunaiConfig, VmConfig};

/// List all microVMs
#[derive(Args, Debug)]
pub struct ListCmd {
    /// Show detailed information
    #[arg(short, long)]
    verbose: bool,
}

impl ListCmd {
    pub fn run(self, cfg: &KrunaiConfig) {
        if cfg.vmconfig_map.is_empty() {
            println!("No VMs found");
            println!("\nUse 'krunai create <name>' to create a new VM");
            return;
        }

        // Collect VM info
        let mut vms: Vec<(&String, &VmConfig, VmStatus)> = cfg
            .vmconfig_map
            .iter()
            .map(|(name, vm)| {
                let status = get_vm_status(name);
                (name, vm, status)
            })
            .collect();

        // Sort by name
        vms.sort_by(|a, b| a.0.cmp(b.0));

        // Print header
        if self.verbose {
            println!(
                "\n{:<20} {:<15} {:<10} SSH PORT",
                "NAME", "STATUS", "PID"
            );
            println!("{}", "-".repeat(70));
        } else {
            println!("\n{:<20} {:<15} SSH PORT", "NAME", "STATUS");
            println!("{}", "-".repeat(50));
        }

        // Print each VM
        for (name, vm, status) in &vms {
            print_vm(name, vm, status, self.verbose);
        }

        // Print summary
        let running_count = vms.iter().filter(|(_, _, s)| s.is_running()).count();
        let total_count = vms.len();

        println!("\n{} VM(s) total, {} running", total_count, running_count);
    }
}

#[derive(Debug)]
enum VmStatus {
    Running(i32), // PID
    Stopped,
}

impl VmStatus {
    fn is_running(&self) -> bool {
        matches!(self, VmStatus::Running(_))
    }

    fn display(&self) -> String {
        match self {
            VmStatus::Running(pid) => format!("Running ({})", pid),
            VmStatus::Stopped => "Stopped".to_string(),
        }
    }

    fn pid(&self) -> Option<i32> {
        match self {
            VmStatus::Running(pid) => Some(*pid),
            VmStatus::Stopped => None,
        }
    }
}

fn get_vm_status(vm_name: &str) -> VmStatus {
    if let Some(pid) = utils::get_vm_pid(vm_name) {
        if utils::is_process_running(pid) {
            return VmStatus::Running(pid);
        }
    }
    VmStatus::Stopped
}

fn print_vm(name: &str, vm: &VmConfig, status: &VmStatus, verbose: bool) {
    // Find SSH port
    let ssh_port = vm
        .mapped_ports
        .iter()
        .find(|(_, guest_port)| guest_port.as_str() == "22")
        .map(|(host_port, _)| host_port.as_str())
        .unwrap_or("-");

    if verbose {
        println!(
            "{:<20} {:<15} {:<10} {}",
            name,
            status.display(),
            status
                .pid()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            ssh_port
        );

        // Print additional details
        println!("  Disk: {}", vm.disk_path);

        // Show SSH key if it exists
        if let Ok(ssh_key_path) = config::get_vm_ssh_key_path(name) {
            if ssh_key_path.exists() {
                println!("  SSH key: {}", ssh_key_path.display());
            }
        }

        if !vm.mapped_ports.is_empty() && vm.mapped_ports.len() > 1 {
            println!("  Ports:");
            for (host_port, guest_port) in &vm.mapped_ports {
                println!("    {} -> {}", host_port, guest_port);
            }
        }
    } else {
        println!("{:<20} {:<15} {}", name, status.display(), ssh_port);
    }
}
