// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config;
use crate::utils;
use crate::KrunaiConfig;

/// Export a VM to a tarball
#[derive(Args, Debug)]
pub struct ExportCmd {
    /// Name of the VM to export
    name: String,

    /// Output tarball file path
    output: String,
}

impl ExportCmd {
    pub fn run(self, cfg: &KrunaiConfig) {
        let name = self.name;
        let output_path = self.output;

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
            eprintln!("Error: Cannot export VM '{}' while it is running", name);
            eprintln!("Stop the VM first with: krunai stop {}", name);
            std::process::exit(-1);
        }

        println!("Exporting VM '{}' to '{}'...", name, output_path);

        // Create a temporary directory for staging the export
        let temp_dir = match std::env::temp_dir().join(format!("krunai-export-{}", name)).to_str()
        {
            Some(path) => path.to_string(),
            None => {
                eprintln!("Error: Failed to create temporary directory path");
                std::process::exit(-1);
            }
        };

        // Clean up any existing temp directory
        let _ = fs::remove_dir_all(&temp_dir);

        // Create temp directory
        if let Err(e) = fs::create_dir_all(&temp_dir) {
            eprintln!("Error creating temporary directory: {}", e);
            std::process::exit(-1);
        }

        // Serialize VmConfig to JSON
        let config_json = match serde_json::to_string_pretty(&vmcfg) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("Error serializing VM configuration: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        // Write config to temp directory
        let config_path = Path::new(&temp_dir).join("config.json");
        if let Err(e) = fs::write(&config_path, config_json) {
            eprintln!("Error writing configuration file: {}", e);
            let _ = fs::remove_dir_all(&temp_dir);
            std::process::exit(-1);
        }

        // Copy disk file to temp directory
        let disk_path = Path::new(&vmcfg.disk_path);
        if !disk_path.exists() {
            eprintln!("Error: Disk file not found at {}", disk_path.display());
            let _ = fs::remove_dir_all(&temp_dir);
            std::process::exit(-1);
        }

        let disk_filename = disk_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("disk.qcow2");
        let temp_disk_path = Path::new(&temp_dir).join(disk_filename);

        println!("Copying disk file...");
        if let Err(e) = fs::copy(disk_path, &temp_disk_path) {
            eprintln!("Error copying disk file: {}", e);
            let _ = fs::remove_dir_all(&temp_dir);
            std::process::exit(-1);
        }

        // Copy SSH private key
        let ssh_key_path = match config::get_vm_ssh_key_path(&name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error getting SSH key path: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        if ssh_key_path.exists() {
            let temp_ssh_key_path = Path::new(&temp_dir).join("id_ed25519");
            if let Err(e) = fs::copy(&ssh_key_path, &temp_ssh_key_path) {
                eprintln!("Error copying SSH private key: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        } else {
            eprintln!("Warning: SSH private key not found");
        }

        // Copy SSH public key
        let ssh_pubkey_path = match config::get_vm_ssh_pubkey_path(&name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error getting SSH public key path: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        if ssh_pubkey_path.exists() {
            let temp_ssh_pubkey_path = Path::new(&temp_dir).join("id_ed25519.pub");
            if let Err(e) = fs::copy(&ssh_pubkey_path, &temp_ssh_pubkey_path) {
                eprintln!("Error copying SSH public key: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        } else {
            eprintln!("Warning: SSH public key not found");
        }

        // Create tarball
        println!("Creating tarball...");
        let tar_result = Command::new("tar")
            .arg("-czf")
            .arg(&output_path)
            .arg("-C")
            .arg(&temp_dir)
            .arg(".")
            .status();

        // Clean up temporary directory
        let _ = fs::remove_dir_all(&temp_dir);

        match tar_result {
            Ok(status) => {
                if status.success() {
                    println!("VM '{}' successfully exported to '{}'", name, output_path);
                } else {
                    eprintln!("Error: tar command failed");
                    std::process::exit(-1);
                }
            }
            Err(e) => {
                eprintln!("Error executing tar command: {}", e);
                std::process::exit(-1);
            }
        }
    }
}
