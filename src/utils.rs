// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use crate::config;
use crate::KrunaiConfig;

#[derive(Debug, Clone)]
pub struct PortPair {
    pub host_port: String,
    pub guest_port: String,
}

pub fn port_pairs_to_hash_map(
    port_pairs: impl IntoIterator<Item = PortPair>,
) -> HashMap<String, String> {
    port_pairs
        .into_iter()
        .map(|pair: PortPair| (pair.host_port, pair.guest_port))
        .collect()
}

impl FromStr for PortPair {
    type Err = &'static str;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let vtuple: Vec<&str> = input.split(':').collect();
        if vtuple.len() != 2 {
            return Err("Too many ':' separators");
        }
        let host_port: u16 = match vtuple[0].parse() {
            Ok(p) => p,
            Err(_) => {
                return Err("Invalid host port");
            }
        };
        let guest_port: u16 = match vtuple[1].parse() {
            Ok(p) => p,
            Err(_) => {
                return Err("Invalid guest port");
            }
        };
        Ok(PortPair {
            host_port: host_port.to_string(),
            guest_port: guest_port.to_string(),
        })
    }
}

/// SSH port assignment range
const SSH_PORT_MIN: u16 = 30000;
const SSH_PORT_MAX: u16 = 40000;

/// Find an available SSH port in the range 30000-40000
/// Returns None if all ports in the range are taken
pub fn find_available_ssh_port(cfg: &KrunaiConfig) -> Option<u16> {
    // Collect all currently used host ports
    let mut used_ports: HashSet<u16> = HashSet::new();

    for vm in cfg.vmconfig_map.values() {
        for host_port in vm.mapped_ports.keys() {
            if let Ok(port) = host_port.parse::<u16>() {
                used_ports.insert(port);
            }
        }
    }

    // Find first available port in range
    (SSH_PORT_MIN..=SSH_PORT_MAX).find(|&port| !used_ports.contains(&port))
}

/// Check if SSH port (22) is already mapped
pub fn has_ssh_port_mapping(mapped_ports: &HashMap<String, String>) -> bool {
    mapped_ports.values().any(|guest_port| guest_port == "22")
}

/// Check if a process is running by PID
pub fn is_process_running(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Get the lockfile path for a VM
pub fn get_lockfile_path(vm_name: &str) -> std::io::Result<std::path::PathBuf> {
    Ok(config::get_vm_dir(vm_name)?.join("vm.lock"))
}

/// Read the PID from a VM's lockfile
pub fn get_vm_pid(vm_name: &str) -> Option<i32> {
    if let Ok(lockfile_path) = get_lockfile_path(vm_name) {
        if lockfile_path.exists() {
            if let Ok(content) = fs::read_to_string(&lockfile_path) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    return Some(pid);
                }
            }
        }
    }
    None
}

/// Check if a VM is currently running
pub fn is_vm_running(vm_name: &str) -> bool {
    if let Some(pid) = get_vm_pid(vm_name) {
        is_process_running(pid)
    } else {
        false
    }
}

/// Update a VM's lockfile with a specific PID
pub fn update_lockfile(vm_name: &str, pid: i32) -> std::io::Result<()> {
    let lockfile_path = get_lockfile_path(vm_name)?;
    let mut file = File::create(&lockfile_path)?;
    write!(file, "{}", pid)?;
    Ok(())
}

/// Remove the lockfile for a VM
pub fn remove_lockfile(vm_name: &str) -> std::io::Result<()> {
    let lockfile_path = get_lockfile_path(vm_name)?;
    if lockfile_path.exists() {
        fs::remove_file(&lockfile_path)?;
    }
    Ok(())
}

/// Issue poweroff command to a VM via SSH and wait for it to stop
///
/// Returns Ok(true) if the VM stopped gracefully, Ok(false) if it didn't stop within the timeout,
/// or Err if there was an error executing the SSH command
pub fn poweroff_vm_via_ssh(
    ssh_key_path: &Path,
    ssh_port: &str,
    pid: i32,
    timeout_secs: u64,
) -> std::io::Result<bool> {
    // Issue poweroff command via SSH
    let _status = Command::new("ssh")
        .arg("-i")
        .arg(ssh_key_path)
        .arg("-p")
        .arg(ssh_port)
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
        .status()?;

    // Wait for process to exit
    let check_interval = Duration::from_millis(100);
    let max_checks = (timeout_secs * 1000) / 100;

    for _ in 0..max_checks {
        if !is_process_running(pid) {
            return Ok(true);
        }
        thread::sleep(check_interval);
    }

    // Timeout - VM did not stop
    Ok(false)
}
