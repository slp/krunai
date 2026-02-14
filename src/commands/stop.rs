// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::config;
use crate::utils;
use crate::KrunaiConfig;

/// Stop a running microVM
#[derive(Args, Debug)]
pub struct StopCmd {
    /// Name of the VM to stop
    name: String,

    /// Force kill if graceful shutdown fails
    #[arg(short, long)]
    force: bool,

    /// Timeout in seconds for graceful shutdown (default: 10)
    #[arg(short, long, default_value = "10")]
    timeout: u64,
}

impl StopCmd {
    pub fn run(self, cfg: &KrunaiConfig) {
        let name = self.name;

        // Check if VM exists in configuration
        let vmcfg = match cfg.vmconfig_map.get(&name) {
            Some(vm) => vm,
            None => {
                eprintln!("VM '{}' not found", name);
                std::process::exit(-1);
            }
        };

        // Get VM's lockfile path
        let lockfile_path = match config::get_vm_dir(&name) {
            Ok(dir) => dir.join("vm.lock"),
            Err(e) => {
                eprintln!("Error accessing VM directory: {}", e);
                std::process::exit(-1);
            }
        };

        // Check if VM is running
        if !lockfile_path.exists() {
            println!("VM '{}' is not running", name);
            return;
        }

        // Read PID from lockfile
        let pid = match fs::read_to_string(&lockfile_path) {
            Ok(content) => match content.trim().parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => {
                    eprintln!("Error: Invalid PID in lockfile");
                    std::process::exit(-1);
                }
            },
            Err(e) => {
                eprintln!("Error reading lockfile: {}", e);
                std::process::exit(-1);
            }
        };

        // Check if process is actually running
        if !utils::is_process_running(pid) {
            println!("VM '{}' process is not running (stale lockfile)", name);
            println!("Cleaning up lockfile...");
            let _ = fs::remove_file(&lockfile_path);
            return;
        }

        println!("Stopping VM '{}' (PID {})...", name, pid);

        // Try graceful shutdown first
        if self.force {
            // Force kill immediately
            if kill_process(pid, libc::SIGKILL) {
                println!("VM '{}' force killed", name);
            } else {
                eprintln!("Error: Failed to kill VM process");
                std::process::exit(-1);
            }
        } else {
            // Find SSH port
            let ssh_port = vmcfg
                .mapped_ports
                .iter()
                .find(|(_, guest_port)| guest_port.as_str() == "22")
                .map(|(host_port, _)| host_port.as_str());

            // Get SSH key path
            let ssh_key_path = match config::get_vm_ssh_key_path(&name) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("Error getting SSH key path: {}", e);
                    eprintln!("Falling back to force kill...");
                    if kill_process(pid, libc::SIGKILL) {
                        println!("VM '{}' force killed", name);
                    } else {
                        eprintln!("Error: Failed to kill VM process");
                        std::process::exit(-1);
                    }
                    // Clean up lockfile before returning
                    if lockfile_path.exists() {
                        let _ = fs::remove_file(&lockfile_path);
                    }
                    return;
                }
            };

            // Try SSH poweroff if SSH port is available
            if let Some(port) = ssh_port {
                println!("Issuing poweroff command via SSH...");

                let output = Command::new("ssh")
                    .arg("-i")
                    .arg(&ssh_key_path)
                    .arg("-p")
                    .arg(port)
                    .arg("-o")
                    .arg("StrictHostKeyChecking=no")
                    .arg("-o")
                    .arg("UserKnownHostsFile=/dev/null")
                    .arg("-o")
                    .arg("LogLevel=ERROR")
                    .arg("-o")
                    .arg("ConnectTimeout=5")
                    .arg("agent@localhost")
                    .arg("sync")
                    .arg("&&")
                    .arg("sudo")
                    .arg("poweroff")
                    .arg("-f")
                    .output();

                match output {
                    Ok(_) => {
                        // Wait for process to exit
                        if wait_for_process_exit(pid, self.timeout) {
                            println!("VM '{}' stopped gracefully", name);
                        } else {
                            eprintln!("VM did not stop within {} seconds", self.timeout);
                            println!("Use --force to kill immediately");
                            std::process::exit(-1);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error executing SSH command: {}", e);
                        eprintln!("Use --force to kill immediately");
                        std::process::exit(-1);
                    }
                }
            } else {
                eprintln!("No SSH port mapping found for VM '{}'", name);
                eprintln!("Use --force to kill immediately");
                std::process::exit(-1);
            }
        }

        // Clean up lockfile
        if lockfile_path.exists() {
            match fs::remove_file(&lockfile_path) {
                Ok(_) => {}
                Err(e) => eprintln!("Warning: Failed to remove lockfile: {}", e),
            }
        }
    }
}

/// Send a signal to a process
fn kill_process(pid: i32, signal: i32) -> bool {
    unsafe { libc::kill(pid, signal) == 0 }
}

/// Wait for a process to exit, with timeout
fn wait_for_process_exit(pid: i32, timeout_secs: u64) -> bool {
    let check_interval = Duration::from_millis(100);
    let max_checks = (timeout_secs * 1000) / 100;

    for _ in 0..max_checks {
        if !utils::is_process_running(pid) {
            return true;
        }
        thread::sleep(check_interval);
    }

    false
}
