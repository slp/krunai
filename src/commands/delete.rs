// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::fs;
use std::path::Path;

use crate::config;
use crate::utils;
use crate::KrunaiConfig;

/// Delete an existing microVM
#[derive(Args, Debug)]
pub struct DeleteCmd {
    /// Name of the VM to delete
    name: String,

    /// Force deletion without confirmation
    #[arg(short, long)]
    force: bool,
}

impl DeleteCmd {
    pub fn run(self, cfg: &mut KrunaiConfig, verbose: bool) {
        let name = self.name;

        // Check if VM exists
        let vmcfg = match cfg.vmconfig_map.get(&name) {
            Some(vm) => vm.clone(),
            None => {
                eprintln!("VM '{}' not found", name);
                std::process::exit(-1);
            }
        };

        // Check if VM is running
        if utils::is_vm_running(&name) {
            eprintln!("Error: Cannot delete VM '{}' while it is running", name);
            eprintln!("Stop the VM first with: krunai stop {}", name);
            std::process::exit(-1);
        }

        // Ask for confirmation unless --force is used
        if !self.force {
            crate::vprintln!(
                verbose,
                "Are you sure you want to delete VM '{}'? (y/N)",
                name
            );
            use std::io::{self, BufRead};
            let stdin = io::stdin();
            let mut lines = stdin.lock().lines();

            if let Some(Ok(line)) = lines.next() {
                let response = line.trim().to_lowercase();
                if response != "y" && response != "yes" {
                    crate::vprintln!(verbose, "Deletion cancelled");
                    return;
                }
            } else {
                crate::vprintln!(verbose, "Deletion cancelled");
                return;
            }
        }

        crate::vprintln!(verbose, "Deleting VM '{}'...", name);

        // Delete the entire VM directory
        if let Ok(vm_dir) = config::get_vm_dir(&name) {
            if vm_dir.exists() {
                match fs::remove_dir_all(&vm_dir) {
                    Ok(_) => {
                        crate::vprintln!(verbose, "Deleted VM directory: {}", vm_dir.display())
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to delete VM directory: {}", e);
                        eprintln!("Attempting to clean up individual files...");

                        // Try to delete files individually if directory removal failed
                        let disk_path = Path::new(&vmcfg.disk_path);
                        if disk_path.exists() {
                            if let Err(e) = fs::remove_file(disk_path) {
                                eprintln!("Warning: Failed to delete disk: {}", e);
                            }
                        }

                        if let Ok(socket_path) = config::get_vm_socket_path(&name) {
                            if socket_path.exists() {
                                if let Err(e) = fs::remove_file(&socket_path) {
                                    eprintln!("Warning: Failed to delete socket: {}", e);
                                }
                            }
                        }
                    }
                }
            } else {
                eprintln!("Warning: VM directory not found: {}", vm_dir.display());
            }
        }

        // Remove from configuration
        cfg.vmconfig_map.remove(&name);

        // Save updated configuration
        config::save_config(cfg).unwrap_or_else(|e| {
            eprintln!("Error saving configuration: {}", e);
            std::process::exit(-1);
        });

        crate::vprintln!(verbose, "\nVM '{}' successfully deleted", name);
    }
}
