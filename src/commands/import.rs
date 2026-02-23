// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config;
use crate::utils;
use crate::KrunaiConfig;
use crate::VmConfig;

/// Import a VM from a tarball
#[derive(Args, Debug)]
pub struct ImportCmd {
    /// Input tarball file path
    input: String,

    /// Name for the imported VM
    name: String,
}

impl ImportCmd {
    pub fn run(self, cfg: &mut KrunaiConfig) {
        let input_path = self.input;
        let name = self.name;

        // Check if destination VM already exists
        if cfg.vmconfig_map.contains_key(&name) {
            eprintln!("VM '{}' already exists", name);
            std::process::exit(-1);
        }

        // Check if input tarball exists
        if !Path::new(&input_path).exists() {
            eprintln!("Error: Input file '{}' not found", input_path);
            std::process::exit(-1);
        }

        println!("Importing VM from '{}' as '{}'...", input_path, name);

        // Create a temporary directory for extracting the tarball
        let temp_dir = match std::env::temp_dir().join(format!("krunai-import-{}", name)).to_str()
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

        // Extract tarball
        println!("Extracting tarball...");
        let tar_result = Command::new("tar")
            .arg("-xzf")
            .arg(&input_path)
            .arg("-C")
            .arg(&temp_dir)
            .status();

        match tar_result {
            Ok(status) => {
                if !status.success() {
                    eprintln!("Error: tar command failed");
                    let _ = fs::remove_dir_all(&temp_dir);
                    std::process::exit(-1);
                }
            }
            Err(e) => {
                eprintln!("Error executing tar command: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        }

        // Read config.json
        let config_path = Path::new(&temp_dir).join("config.json");
        if !config_path.exists() {
            eprintln!("Error: config.json not found in tarball");
            let _ = fs::remove_dir_all(&temp_dir);
            std::process::exit(-1);
        }

        let config_json = match fs::read_to_string(&config_path) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Error reading config.json: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        let mut vmcfg: VmConfig = match serde_json::from_str(&config_json) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error parsing config.json: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        // Ensure VM directory structure exists
        if let Err(e) = config::ensure_vm_dir_exists(&name) {
            eprintln!("Error creating VM directory: {}", e);
            let _ = fs::remove_dir_all(&temp_dir);
            std::process::exit(-1);
        }

        // Find disk file in temp directory (look for .qcow2 file)
        let disk_file = match fs::read_dir(&temp_dir) {
            Ok(entries) => {
                let mut found_disk = None;
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "qcow2" {
                            found_disk = Some(path);
                            break;
                        }
                    }
                }
                found_disk
            }
            Err(e) => {
                eprintln!("Error reading temporary directory: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        let disk_file = match disk_file {
            Some(file) => file,
            None => {
                eprintln!("Error: No disk file (.qcow2) found in tarball");
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        // Copy disk file to new VM location
        let dest_disk_path = match config::get_vm_disk_path(&name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error getting VM disk path: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        };

        println!("Copying disk file...");
        if let Err(e) = fs::copy(&disk_file, &dest_disk_path) {
            eprintln!("Error copying disk file: {}", e);
            let _ = fs::remove_dir_all(&temp_dir);
            std::process::exit(-1);
        }

        // Copy SSH private key
        let temp_ssh_key = Path::new(&temp_dir).join("id_ed25519");
        if temp_ssh_key.exists() {
            let dest_ssh_key = match config::get_vm_ssh_key_path(&name) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("Error getting SSH key path: {}", e);
                    let _ = fs::remove_dir_all(&temp_dir);
                    std::process::exit(-1);
                }
            };

            if let Err(e) = fs::copy(&temp_ssh_key, &dest_ssh_key) {
                eprintln!("Error copying SSH private key: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }

            // Set correct permissions (0600)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = fs::set_permissions(&dest_ssh_key, fs::Permissions::from_mode(0o600))
                {
                    eprintln!("Warning: Failed to set SSH key permissions: {}", e);
                }
            }
        } else {
            eprintln!("Warning: SSH private key not found in tarball");
        }

        // Copy SSH public key
        let temp_ssh_pubkey = Path::new(&temp_dir).join("id_ed25519.pub");
        if temp_ssh_pubkey.exists() {
            let dest_ssh_pubkey = match config::get_vm_ssh_pubkey_path(&name) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("Error getting SSH public key path: {}", e);
                    let _ = fs::remove_dir_all(&temp_dir);
                    std::process::exit(-1);
                }
            };

            if let Err(e) = fs::copy(&temp_ssh_pubkey, &dest_ssh_pubkey) {
                eprintln!("Error copying SSH public key: {}", e);
                let _ = fs::remove_dir_all(&temp_dir);
                std::process::exit(-1);
            }
        } else {
            eprintln!("Warning: SSH public key not found in tarball");
        }

        // Clean up temporary directory
        let _ = fs::remove_dir_all(&temp_dir);

        // Update VmConfig with new name and disk path
        vmcfg.name = name.clone();
        vmcfg.disk_path = dest_disk_path.to_str().unwrap_or("").to_string();

        // Clone the mapped ports from imported config (excluding SSH port 22)
        let mut new_mapped_ports = vmcfg
            .mapped_ports
            .iter()
            .filter(|(_, guest_port)| guest_port.as_str() != "22")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<String, String>>();

        // Find a new available SSH port for the imported VM
        let new_ssh_port = match utils::find_available_ssh_port(cfg) {
            Some(port) => {
                println!("Assigning new SSH port: {} -> 22", port);
                port
            }
            None => {
                eprintln!("Error: No available SSH ports in range 30000-40000");
                // Clean up on error
                let _ = config::get_vm_dir(&name).and_then(|dir| fs::remove_dir_all(&dir));
                std::process::exit(-1);
            }
        };

        // Add the new SSH port mapping
        new_mapped_ports.insert(new_ssh_port.to_string(), "22".to_string());
        vmcfg.mapped_ports = new_mapped_ports;

        // Save configuration
        cfg.vmconfig_map.insert(name.clone(), vmcfg);
        if let Err(e) = config::save_config(cfg) {
            eprintln!("Error saving configuration: {}", e);
            std::process::exit(-1);
        }

        println!("VM '{}' successfully imported", name);
    }
}
