// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::Command;

use crate::commands::start;
use crate::config;
use crate::krun::exec_vm;
use crate::utils;
use crate::KrunaiConfig;

/// Clone an existing microVM
#[derive(Args, Debug)]
pub struct CloneCmd {
    /// Name of the source VM to clone from
    source: String,

    /// Name of the destination VM to create
    destination: String,
}

impl CloneCmd {
    pub fn run(self, cfg: &mut KrunaiConfig, verbose: bool) {
        let source_name = self.source;
        let dest_name = self.destination;

        // Check if source VM exists
        let source_vmcfg = match cfg.vmconfig_map.get(&source_name) {
            Some(vm) => vm.clone(),
            None => {
                eprintln!("Source VM '{}' not found", source_name);
                std::process::exit(-1);
            }
        };

        // Check if destination VM already exists
        if cfg.vmconfig_map.contains_key(&dest_name) {
            eprintln!("Destination VM '{}' already exists", dest_name);
            std::process::exit(-1);
        }

        // Check if source VM is running
        if utils::is_vm_running(&source_name) {
            eprintln!(
                "Error: Cannot clone VM '{}' while it is running",
                source_name
            );
            eprintln!("Stop the VM first with: krunai stop {}", source_name);
            std::process::exit(-1);
        }

        crate::vprintln!(
            verbose,
            "Cloning VM '{}' to '{}'...",
            source_name,
            dest_name
        );

        // Ensure destination VM directory structure exists
        if let Err(e) = config::ensure_vm_dir_exists(&dest_name) {
            eprintln!("Error creating VM directory: {}", e);
            std::process::exit(-1);
        }

        // Copy disk file
        let source_disk_path = match config::get_vm_disk_path(&source_name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error getting source disk path: {}", e);
                std::process::exit(-1);
            }
        };

        if !source_disk_path.exists() {
            eprintln!("Source disk not found at: {}", source_disk_path.display());
            std::process::exit(-1);
        }

        let dest_disk_path = match config::get_vm_disk_path(&dest_name) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error getting destination disk path: {}", e);
                std::process::exit(-1);
            }
        };

        crate::vprintln!(
            verbose,
            "Copying disk from {} to {}...",
            source_disk_path.display(),
            dest_disk_path.display()
        );

        if let Err(e) = fs::copy(&source_disk_path, &dest_disk_path) {
            eprintln!("Error copying disk: {}", e);
            std::process::exit(-1);
        }

        // Generate SSH keys for the new VM
        if let Err(e) = generate_ssh_keys(&dest_name, verbose) {
            eprintln!("Error generating SSH keys: {}", e);
            // Clean up on error
            let _ = config::get_vm_dir(&dest_name).and_then(|dir| fs::remove_dir_all(&dir));
            std::process::exit(-1);
        }

        // Create new VmConfig for destination
        let dest_disk_path_str = match dest_disk_path.to_str() {
            Some(s) => s.to_string(),
            None => {
                eprintln!("Invalid disk path encoding");
                std::process::exit(-1);
            }
        };

        // Clone the mapped ports from source (excluding SSH port 22)
        let mut dest_mapped_ports = source_vmcfg
            .mapped_ports
            .iter()
            .filter(|(_, guest_port)| guest_port.as_str() != "22")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<String, String>>();

        // Find a new available SSH port for the cloned VM
        let new_ssh_port = match utils::find_available_ssh_port(cfg) {
            Some(port) => {
                crate::vprintln!(verbose, "Assigning new SSH port: {} -> 22", port);
                port
            }
            None => {
                eprintln!("Error: No available SSH ports in range 30000-40000");
                // Clean up on error
                let _ = config::get_vm_dir(&dest_name).and_then(|dir| fs::remove_dir_all(&dir));
                std::process::exit(-1);
            }
        };

        // Add the new SSH port mapping
        dest_mapped_ports.insert(new_ssh_port.to_string(), "22".to_string());

        let dest_vmcfg = crate::VmConfig {
            name: dest_name.clone(),
            disk_path: dest_disk_path_str,
            mapped_ports: dest_mapped_ports,
            cpus: source_vmcfg.cpus,
            mem: source_vmcfg.mem,
        };

        // Save configuration
        cfg.vmconfig_map
            .insert(dest_name.clone(), dest_vmcfg.clone());
        if let Err(e) = config::save_config(cfg) {
            eprintln!("Error saving configuration: {}", e);
            std::process::exit(-1);
        }

        // Update SSH keys in the cloned VM
        if let Err(e) = update_vm_ssh_keys(&source_name, &dest_name, &dest_vmcfg, verbose) {
            eprintln!("Error updating SSH keys in cloned VM: {}", e);
            eprintln!("The VM was cloned but you may need to manually update the SSH keys");
            std::process::exit(-1);
        }

        crate::vprintln!(
            verbose,
            "VM '{}' successfully cloned to '{}'",
            source_name,
            dest_name
        );
    }
}

/// Generate SSH key pair for a VM
fn generate_ssh_keys(vm_name: &str, verbose: bool) -> std::io::Result<()> {
    let ssh_key_path = config::get_vm_ssh_key_path(vm_name)?;

    // Check if key already exists
    if ssh_key_path.exists() {
        return Ok(());
    }

    crate::vprintln!(verbose, "Generating SSH key pair for '{}'...", vm_name);

    // Generate SSH key pair using ssh-keygen
    let output = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(&ssh_key_path)
        .arg("-N")
        .arg("") // Empty passphrase
        .arg("-C")
        .arg(format!("krunai-{}", vm_name))
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(())
}

/// Update SSH keys in the cloned VM by starting it, updating authorized_keys, and stopping it
fn update_vm_ssh_keys(
    source_name: &str,
    dest_name: &str,
    dest_vmcfg: &crate::VmConfig,
    verbose: bool,
) -> std::io::Result<()> {
    crate::vprintln!(verbose, "Updating SSH keys in cloned VM...");

    // Get SSH port
    let ssh_port = dest_vmcfg
        .mapped_ports
        .iter()
        .find(|(_, guest_port)| guest_port.as_str() == "22")
        .map(|(host_port, _)| host_port.as_str())
        .ok_or_else(|| std::io::Error::other("No SSH port mapping found"))?;

    // Get source (old) SSH key path
    let source_ssh_key = config::get_vm_ssh_key_path(source_name)?;

    // Get destination (new) SSH private and public key path
    let dest_ssh_key = config::get_vm_ssh_key_path(dest_name)?;
    let dest_ssh_pubkey = config::get_vm_ssh_pubkey_path(dest_name)?;

    // Read the new public key
    let new_pubkey = fs::read_to_string(&dest_ssh_pubkey)?;

    // Check and create lockfile for the VM
    if let Err(e) = start::check_and_create_lockfile(dest_name) {
        return Err(std::io::Error::other(format!(
            "Failed to create lockfile: {}",
            e
        )));
    }

    crate::vprintln!(verbose, "Starting VM '{}'...", dest_name);

    // Generate startup script
    start::generate_startup_script(dest_name)?;

    let cwd = env::current_dir()?;
    let workdir = cwd.to_str();

    // Clone data for VM execution
    let name_for_vm = dest_name.to_string();
    let vmcfg_for_vm = dest_vmcfg.clone();

    // Fork to start the VM in a child process
    let vm_pid = unsafe { libc::fork() };
    if vm_pid < 0 {
        let _ = utils::remove_lockfile(dest_name);
        return Err(std::io::Error::other("Failed to fork for VM process"));
    }

    if vm_pid == 0 {
        // Child process - will start the VM

        // Daemonize the VM process
        if let Err(e) = start::daemonize(&name_for_vm, false) {
            eprintln!("Failed to daemonize: {}", e);
            std::process::exit(-1);
        }

        start::set_rlimits();

        // Execute the VM
        unsafe {
            exec_vm(
                &vmcfg_for_vm,
                false,
                "startup.sh",
                workdir,
                Vec::new(),
                Vec::new(),
            )
        };

        // Clean up lockfile if exec_vm returns (shouldn't happen)
        let _ = utils::remove_lockfile(&name_for_vm);
        std::process::exit(0);
    }

    // Parent process continues - wait for SSH and update keys

    // Wait for SSH to be ready
    crate::vprintln!(verbose, "Waiting for SSH to be ready...");
    if !start::wait_for_ssh_connectivity(dest_name, ssh_port, &source_ssh_key) {
        // SSH not ready, kill the VM and clean up
        unsafe {
            libc::kill(vm_pid, libc::SIGKILL);
        }
        let _ = utils::remove_lockfile(dest_name);
        return Err(std::io::Error::other("SSH connection to cloned VM failed"));
    }

    // Update authorized_keys with the new public key
    crate::vprintln!(verbose, "Updating authorized_keys with new SSH key...");
    let update_result = Command::new("ssh")
        .arg("-i")
        .arg(&source_ssh_key)
        .arg("-p")
        .arg(ssh_port)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("agent@localhost")
        .arg(format!(
            "echo '{}' > /home/agent/.ssh/authorized_keys",
            new_pubkey.trim()
        ))
        .status()?;

    if !update_result.success() {
        // Kill the VM and clean up
        unsafe {
            libc::kill(vm_pid, libc::SIGKILL);
        }
        let _ = utils::remove_lockfile(dest_name);
        return Err(std::io::Error::other(
            "Failed to update authorized_keys in cloned VM",
        ));
    }

    // Stop the VM gracefully via SSH
    crate::vprintln!(verbose, "Stopping VM '{}'...", dest_name);
    match utils::poweroff_vm_via_ssh(&dest_ssh_key, ssh_port, vm_pid, 10) {
        Ok(true) => {
            // VM stopped gracefully
            let _ = utils::remove_lockfile(dest_name);
        }
        Ok(false) => {
            // VM didn't stop within timeout, force kill
            crate::vprintln!(verbose, "VM did not stop gracefully, force killing...");
            unsafe {
                libc::kill(vm_pid, libc::SIGKILL);
            }
            let _ = utils::remove_lockfile(dest_name);
        }
        Err(_) => {
            // SSH command failed, force kill
            crate::vprintln!(verbose, "SSH poweroff failed, force killing...");
            unsafe {
                libc::kill(vm_pid, libc::SIGKILL);
            }
            let _ = utils::remove_lockfile(dest_name);
        }
    }

    crate::vprintln!(verbose, "SSH keys updated successfully");
    Ok(())
}
