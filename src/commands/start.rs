// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use clap::Args;

use crate::config;
use crate::krun::exec_vm;
use crate::utils;
use crate::KrunaiConfig;

const SSH_CONNECT_RETRIES: u32 = 100;
const SSH_CONNECT_INTERVAL_MS: u64 = 50;

/// Test SSH connectivity to the VM
fn test_ssh_connection(_vm_name: &str, ssh_port: &str, ssh_key_path: &Path) -> bool {
    let output = Command::new("ssh")
        .arg("-i")
        .arg(ssh_key_path)
        .arg("-p")
        .arg(ssh_port)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("agent@localhost")
        .arg("echo")
        .arg("connected")
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains("connected")
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Attempt to connect to VM via SSH with retries
pub fn wait_for_ssh_connectivity(vm_name: &str, ssh_port: &str, ssh_key_path: &Path) -> bool {
    for attempt in 1..=SSH_CONNECT_RETRIES {
        std::io::Write::flush(&mut std::io::stdout()).ok();

        if test_ssh_connection(vm_name, ssh_port, ssh_key_path) {
            return true;
        }

        if attempt < SSH_CONNECT_RETRIES {
            thread::sleep(Duration::from_millis(SSH_CONNECT_INTERVAL_MS));
        }
    }

    false
}

/// Generate startup script that launches sshd in background and user process in foreground
pub fn generate_startup_script(
    vm_name: &str,
    guest_ip: &str,
    router_ip: &str,
) -> std::io::Result<String> {
    let script_path = config::get_vm_shared_dir(vm_name)?.join("startup.sh");

    let script_content = format!(
        r#"#!/bin/bash
set -e

# Configure network
echo "==> Configuring the network..."
ip addr add {}/24 dev eth0
ip link set up dev eth0
ip route add default via {}
rm -f /etc/resolv.conf
echo "nameserver {}" > /etc/resolv.conf

echo "==> Mounting work directory..."
mount -t virtiofs work /home/agent/work

echo "==> Starting SSH daemon in foreground..."
/usr/sbin/sshd -D
"#,
        guest_ip, router_ip, router_ip
    );

    // Write the script
    let mut file = File::create(&script_path)?;
    file.write_all(script_content.as_bytes())?;

    // Make the script executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms)?;
    }

    // Return the path as a string
    script_path.to_str().map(|s| s.to_string()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid path encoding")
    })
}

/// Set up SSH port forwarding for VM
pub fn setup_port_forwarding(vm_name: &str, vmcfg: &crate::VmConfig) {
    // Find the SSH port
    let ssh_port = match vmcfg
        .mapped_ports
        .iter()
        .find(|(_, guest_port)| guest_port.as_str() == "22")
    {
        Some((host_port, _)) => host_port,
        None => {
            // No SSH port configured, can't forward ports
            return;
        }
    };

    // Get SSH key path
    let ssh_key_path = match config::get_vm_ssh_key_path(vm_name) {
        Ok(path) => path,
        Err(_) => return,
    };

    // Wait for SSH to be ready
    if !wait_for_ssh_connectivity(vm_name, ssh_port, &ssh_key_path) {
        eprintln!("Warning: SSH not ready, skipping port forwarding setup");
        return;
    }

    // Collect all port forwarding rules (except SSH itself)
    let mut forwarding_rules = Vec::new();
    for (host_port, guest_port) in &vmcfg.mapped_ports {
        if guest_port == "22" {
            // Skip SSH port
            continue;
        }

        forwarding_rules.push((host_port.clone(), guest_port.clone()));
    }

    // If no ports to forward, nothing to do
    if forwarding_rules.is_empty() {
        return;
    }

    // Fork to run SSH port forwarding in background
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("Failed to fork for port forwarding");
        return;
    }

    if pid == 0 {
        // Child process - run SSH port forwarding
        // Daemonize this process
        unsafe {
            libc::setsid();
        }

        // Redirect stdio to /dev/null
        unsafe {
            let devnull = libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            libc::close(devnull);
        }

        // Build SSH command with all port forwarding rules
        let mut cmd = Command::new("ssh");
        cmd.arg("-i")
            .arg(&ssh_key_path)
            .arg("-p")
            .arg(ssh_port)
            .arg("-N") // Don't execute remote command
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg("-o")
            .arg("ExitOnForwardFailure=yes")
            .arg("-o")
            .arg("ServerAliveInterval=60")
            .arg("-o")
            .arg("ServerAliveCountMax=3");

        // Add all port forwarding rules
        for (host_port, guest_port) in forwarding_rules {
            cmd.arg("-L")
                .arg(format!("{}:localhost:{}", host_port, guest_port));
        }

        cmd.arg("agent@localhost");

        // Execute SSH with port forwarding
        let status = cmd.status();

        match status {
            Ok(_) => std::process::exit(0),
            Err(_) => std::process::exit(1),
        }
    }

    // Parent process returns
}

/// Start an existing microVM
#[derive(Args, Debug)]
pub struct StartCmd {
    /// Name of the VM to start
    name: String,

    /// Connect to VM via SSH after starting
    #[arg(short = 'c', long = "connect")]
    connect: bool,

    /// Force restart if VM is already running
    #[arg(short = 'f', long = "force")]
    force: bool,
}

impl StartCmd {
    pub fn run(self, cfg: &KrunaiConfig, verbose: bool) {
        let name = self.name;
        let connect = self.connect;
        let force = self.force;

        // Check if VM exists
        let vmcfg = match cfg.vmconfig_map.get(&name) {
            Some(vm) => vm.clone(),
            None => {
                eprintln!("VM '{}' not found", name);
                std::process::exit(-1);
            }
        };

        // Check if VM is already running
        if utils::is_vm_running(&name) {
            if force {
                crate::vprintln!(
                    verbose,
                    "VM '{}' is already running, forcing restart...",
                    name
                );
                stop_running_vm(&name, &vmcfg, verbose);
            } else {
                eprintln!("Error: VM '{}' is already running", name);
                eprintln!(
                    "Use 'krunai stop {}' to stop it first, or use --force to restart",
                    name
                );
                std::process::exit(-1);
            }
        }

        // If connect flag is set, fork before starting VM
        // Parent will wait and connect via SSH
        // Child will start the VM normally
        if connect {
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                eprintln!("Failed to fork process");
                std::process::exit(-1);
            }
            if pid > 0 {
                // Find SSH port and connect
                if let Some((host_port, _)) = vmcfg
                    .mapped_ports
                    .iter()
                    .find(|(_, gp)| gp.as_str() == "22")
                {
                    if let Ok(ssh_key_path) = config::get_vm_ssh_key_path(&name) {
                        thread::sleep(Duration::from_millis(200));
                        if wait_for_ssh_connectivity(&name, host_port, &ssh_key_path) {
                            crate::vprintln!(verbose, "\nOpening interactive SSH session...");
                            crate::vprintln!(
                                verbose,
                                "(Type 'exit' or press Ctrl+D to close the session)\n"
                            );

                            let _ = Command::new("ssh")
                                .arg("-i")
                                .arg(&ssh_key_path)
                                .arg("-p")
                                .arg(host_port)
                                .arg("-o")
                                .arg("StrictHostKeyChecking=no")
                                .arg("-o")
                                .arg("UserKnownHostsFile=/dev/null")
                                .arg("-o")
                                .arg("LogLevel=ERROR")
                                .arg("agent@localhost")
                                .status();
                        } else {
                            crate::vprintln!(
                                verbose,
                                "\n✗ Warning: Could not verify SSH connectivity"
                            );
                        }
                    }
                }
                std::process::exit(0);
            }
            // Child process continues below
        }

        // Check if VM is already running
        if let Err(e) = check_and_create_lockfile(&name) {
            eprintln!("Error: {}", e);
            std::process::exit(-1);
        }

        crate::vprintln!(verbose, "Starting VM '{}'...", name);

        // Start network proxy to get DHCP IPs
        let proxy_handle = crate::krun::start_network_proxy_for_vm(&vmcfg).unwrap_or_else(|e| {
            eprintln!("Error: Failed to start network proxy: {}", e);
            std::process::exit(-1);
        });

        // Extract IPs from proxy handle
        let guest_ip = proxy_handle.guest_ip.as_str();
        let router_ip = proxy_handle.router_ip.as_str();

        // Generate startup script with dynamic IPs
        let _ = generate_startup_script(&name, guest_ip, router_ip).unwrap_or_else(|e| {
            eprintln!("Error generating startup script: {}", e);
            std::process::exit(-1);
        });

        let cwd = env::current_dir().unwrap();
        let workdir = cwd.to_str();
        if let Some(workdir) = workdir {
            crate::vprintln!(verbose, "Sharing '{workdir}' with '{name}'");
        }

        // Clone data for port forwarding setup
        let name_for_forwarding = name.clone();
        let vmcfg_for_forwarding = vmcfg.clone();

        // Fork to set up port forwarding after VM starts
        let forwarding_pid = unsafe { libc::fork() };
        if forwarding_pid < 0 {
            eprintln!("Failed to fork for port forwarding");
            std::process::exit(-1);
        }

        if forwarding_pid == 0 {
            // Child process - will set up port forwarding
            setup_port_forwarding(&name_for_forwarding, &vmcfg_for_forwarding);
            std::process::exit(0);
        }

        // Parent process continues to start the VM

        // Always daemonize
        daemonize(&name, verbose).unwrap_or_else(|e| {
            eprintln!("Failed to daemonize: {}", e);
            std::process::exit(-1);
        });

        // Set resource limits
        set_rlimits();

        // Execute the VM with the startup script
        unsafe {
            exec_vm(
                &vmcfg,
                false,
                "startup.sh",
                workdir,
                Vec::new(),
                Vec::new(),
                proxy_handle,
            )
        };

        // Clean up lockfile on exit (if we reach here)
        let _ = utils::remove_lockfile(&name);
    }
}

/// Check if VM is already running and create lockfile
pub fn check_and_create_lockfile(vm_name: &str) -> std::io::Result<()> {
    let lockfile_path = config::get_vm_dir(vm_name)?.join("vm.lock");

    // Try to read existing lockfile
    if lockfile_path.exists() {
        if let Ok(content) = fs::read_to_string(&lockfile_path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                // Check if process is still running
                if utils::is_process_running(pid) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!("VM is already running with PID {}", pid),
                    ));
                } else {
                    // Stale lockfile, remove it
                    let _ = fs::remove_file(&lockfile_path);
                }
            }
        }
    }

    // Create lockfile with current PID
    let pid = unsafe { libc::getpid() };
    let mut file = File::create(&lockfile_path)?;
    write!(file, "{}", pid)?;

    // Set exclusive lock
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Could not acquire lock on VM",
        ));
    }

    // Keep the file handle alive by leaking it (process exit will clean up)
    std::mem::forget(file);

    Ok(())
}

/// Daemonize the process
pub fn daemonize(vm_name: &str, verbose: bool) -> std::io::Result<()> {
    // First fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid > 0 {
        // Parent process - print info and exit
        crate::vprintln!(
            verbose,
            "VM '{}' started in background with PID {}",
            vm_name,
            pid
        );
        std::process::exit(0);
    }

    // Child process continues...

    // Create new session
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Second fork to ensure we're not session leader
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid > 0 {
        // First child exits
        std::process::exit(0);
    }

    // Update lockfile with new PID
    let new_pid = unsafe { libc::getpid() };
    let lockfile_path = config::get_vm_dir(vm_name)?.join("vm.lock");
    let mut file = File::create(&lockfile_path)?;
    write!(file, "{}", new_pid)?;
    drop(file);

    // Change working directory to root
    std::env::set_current_dir("/")?;

    // Redirect stdin to /dev/null
    let devnull = File::open("/dev/null")?;
    let devnull_fd = devnull.as_raw_fd();

    // Create log file for stdout in VM's log directory
    let log_path = config::get_vm_logs_dir(vm_name)?.join("vm.log");
    let log_file = File::create(&log_path)?;
    let log_fd = log_file.as_raw_fd();

    unsafe {
        libc::dup2(devnull_fd, 0); // stdin -> /dev/null
        libc::dup2(log_fd, 1); // stdout -> vm.log
        libc::dup2(log_fd, 2); // stderr -> vm.log
    }

    Ok(())
}

/// Set resource limits
pub fn set_rlimits() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if ret < 0 {
        eprintln!("Warning: Couldn't get RLIMIT_NOFILE value");
        return;
    }

    limit.rlim_cur = limit.rlim_max;
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    if ret < 0 {
        eprintln!("Warning: Couldn't set RLIMIT_NOFILE value");
    }
}

/// Gracefully stop a running VM
fn stop_running_vm(vm_name: &str, vmcfg: &crate::VmConfig, verbose: bool) {
    // Get the PID from the VM
    let pid = match utils::get_vm_pid(vm_name) {
        Some(pid) => pid,
        None => {
            // VM not running (stale check), clean up lockfile just in case
            let _ = utils::remove_lockfile(vm_name);
            return;
        }
    };

    crate::vprintln!(verbose, "Stopping VM '{}' (PID {})...", vm_name, pid);

    // Find SSH port
    let ssh_port = vmcfg
        .mapped_ports
        .iter()
        .find(|(_, guest_port)| guest_port.as_str() == "22")
        .map(|(host_port, _)| host_port.as_str());

    let ssh_port = match ssh_port {
        Some(port) => port,
        None => {
            eprintln!("Error: No SSH port mapping found for VM '{}'", vm_name);
            eprintln!("Cannot perform graceful shutdown");
            std::process::exit(-1);
        }
    };

    // Get SSH key path
    let ssh_key_path = match config::get_vm_ssh_key_path(vm_name) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error getting SSH key path: {}", e);
            eprintln!("Cannot perform graceful shutdown");
            std::process::exit(-1);
        }
    };

    // Issue poweroff command via SSH
    crate::vprintln!(verbose, "Issuing poweroff command via SSH...");
    let timeout_secs = 10;
    match utils::poweroff_vm_via_ssh(&ssh_key_path, ssh_port, pid, timeout_secs) {
        Ok(true) => {
            crate::vprintln!(verbose, "VM stopped gracefully");
            let _ = utils::remove_lockfile(vm_name);
        }
        Ok(false) => {
            eprintln!("Error: VM did not stop within {} seconds", timeout_secs);
            eprintln!(
                "Please stop the VM manually with: krunai stop --force {}",
                vm_name
            );
            std::process::exit(-1);
        }
        Err(e) => {
            eprintln!("Error executing SSH command: {}", e);
            eprintln!("Cannot perform graceful shutdown");
            std::process::exit(-1);
        }
    }
}
