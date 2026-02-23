// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::config;
use crate::krun::exec_vm;
use crate::utils::{
    self, find_available_ssh_port, has_ssh_port_mapping, port_pairs_to_hash_map, PortPair,
};
use crate::{KrunaiConfig, VmConfig};

const TEMPLATE_DISK_NAME: &str = "debian-13-nocloud.qcow2";
const SSH_CONNECT_RETRIES: u32 = 100;
const SSH_CONNECT_INTERVAL_MS: u64 = 50;

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

/// Create lockfile for VM
fn create_lockfile(vm_name: &str) -> std::io::Result<()> {
    let lockfile_path = config::get_vm_dir(vm_name)?.join("vm.lock");

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

    // Keep the file handle alive by leaking it
    std::mem::forget(file);

    Ok(())
}

/// Set resource limits
fn set_rlimits() {
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

/// Daemonize the VM process
fn daemonize_vm(vm_name: &str) -> std::io::Result<i32> {
    // First fork
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid > 0 {
        // Parent process - return child PID
        return Ok(pid);
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

    // Update lockfile with daemon PID
    let new_pid = unsafe { libc::getpid() };
    utils::update_lockfile(vm_name, new_pid)?;

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

    Ok(0) // Return 0 in daemon process
}

/// Generate VM setup script
fn generate_setup_script(vm_name: &str, envs: &[String]) -> std::io::Result<()> {
    let script_path = config::get_vm_setup_script_path(vm_name)?;
    let pubkey_path = config::get_vm_ssh_pubkey_path(vm_name)?;

    // Read the public key
    let pubkey = fs::read_to_string(&pubkey_path)?;

    // Get current user's UID and GID
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Build environment variable exports for .bash_env
    let env_exports = if envs.is_empty() {
        String::new()
    } else {
        let mut exports = String::from("\n# User-provided environment variables\n");
        for env_var in envs {
            // Validate format (should be KEY=value)
            if env_var.contains('=') {
                exports.push_str(&format!("export {}\n", env_var));
            }
        }
        exports
    };

    // Generate the setup script
    let script_content = format!(
        r#"#!/bin/bash
set -e

echo "==> Configuring the network..."
ip addr add 192.168.127.2/24 dev eth0
ip link set up dev eth0
ip route add default via 192.168.127.1
rm -f /etc/resolv.conf
echo "nameserver 192.168.127.1" > /etc/resolv.conf

# Create agent group if it doesn't exist
if ! getent group {gid} >/dev/null 2>&1; then
    echo "==> Creating group 'agent' with GID {gid}..."
    groupadd -g {gid} agent
fi

# Create agent user if it doesn't exist
if ! id -u agent >/dev/null 2>&1; then
    echo "==> Creating user 'agent' with UID {uid} and GID {gid}..."
    useradd -m -s /bin/bash -u {uid} -g {gid} agent
    mkdir -p /home/agent/work
    echo ". ~/.bash_env" >> /home/agent/.bashrc
    echo "cd /home/agent/work" >> /home/agent/.bashrc
    echo "agent:agent" | chpasswd
    echo "User 'agent' created with password 'agent'"
else
    echo "==> User 'agent' already exists"
fi

# Add environment variables to .bash_env
touch /home/agent/.bash_env
if [ -n "{env_exports}" ]; then
    echo "==> Setting up environment variables..."
    cat >> /home/agent/.bash_env << 'ENVEOF'
{env_exports}ENVEOF
fi

# Setup SSH for agent user
echo "==> Setting up SSH keys for user 'agent'..."
mkdir -p /home/agent/.ssh
chmod 700 /home/agent/.ssh

# Add public key to authorized_keys
cat > /home/agent/.ssh/authorized_keys << 'EOF'
{pubkey}EOF

chmod 600 /home/agent/.ssh/authorized_keys
chown -R agent:{gid} /home/agent/.ssh

# Allow agent user to use sudo without password
echo "==> Configuring sudo permissions for 'agent'..."
echo "agent ALL=(ALL) NOPASSWD: /usr/sbin/poweroff" > /etc/sudoers.d/agent-poweroff
echo "agent ALL=(ALL) NOPASSWD: /usr/sbin/poweroff" > /etc/sudoers.d/agent-poweroff
echo "agent ALL=(ALL) NOPASSWD: /usr/bin/apt" > /etc/sudoers.d/agent-apt
echo "agent ALL=(ALL) NOPASSWD: /usr/bin/apt-get" >> /etc/sudoers.d/agent-apt
echo "agent ALL=(ALL) NOPASSWD: /usr/bin/apt-cache" >> /etc/sudoers.d/agent-apt
echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/agent-all
chmod 440 /etc/sudoers.d/agent-poweroff
chmod 440 /etc/sudoers.d/agent-all

echo "==> Mounting work directory..."
mount -t virtiofs work /home/agent/work

echo "==> Setup complete!"
echo "    User 'agent' is ready with SSH key authentication"
echo "    Starting SSH service in foreground..."

# Execute sshd in foreground mode
/usr/sbin/sshd -D

echo "==> Removing general sudo permission for agent user"
rm /etc/sudoers.d/agent-all
sync
"#
    );

    // Write the script
    let mut file = fs::File::create(&script_path)?;
    file.write_all(script_content.as_bytes())?;

    // Make the script executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms)?;
    }

    Ok(())
}

/// Generate SSH key pair for the VM
fn generate_ssh_keys(vm_name: &str) -> std::io::Result<()> {
    let private_key_path = config::get_vm_ssh_key_path(vm_name)?;
    let public_key_path = config::get_vm_ssh_pubkey_path(vm_name)?;

    // Check if keys already exist
    if private_key_path.exists() && public_key_path.exists() {
        return Ok(());
    }

    // Generate SSH key using ssh-keygen
    let output = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(&private_key_path)
        .arg("-N")
        .arg("") // No passphrase
        .arg("-C")
        .arg(format!("krunai-{}", vm_name))
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "ssh-keygen not found. Please install OpenSSH.",
                )
            } else {
                e
            }
        })?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Set restrictive permissions on private key (600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&private_key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&private_key_path, perms)?;
    }

    Ok(())
}

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
fn wait_for_ssh_connectivity(
    vm_name: &str,
    ssh_port: &str,
    ssh_key_path: &Path,
    verbose: bool,
) -> bool {
    crate::vprintln!(verbose, "Waiting for VM to be accessible via SSH...");

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

/// Copy the disk template to the VM's directory
fn copy_disk_template(vm_name: &str, verbose: bool) -> std::io::Result<String> {
    // Get template path from config directory
    let config_dir = config::get_config_dir()?;
    let template_path = config_dir.join(TEMPLATE_DISK_NAME);

    // Check if template exists
    if !template_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Disk template not found at: {}\nRun 'krunai init' first to download and initialize the template",
                template_path.display()
            ),
        ));
    }

    // Ensure VM directory structure exists
    config::ensure_vm_dir_exists(vm_name)?;

    // Get VM's disk path
    let dest_path = config::get_vm_disk_path(vm_name)?;

    crate::vprintln!(
        verbose,
        "Copying template from {} to {}",
        template_path.display(),
        dest_path.display()
    );
    fs::copy(&template_path, &dest_path)?;

    // Return the absolute path as a string
    dest_path.to_str().map(|s| s.to_string()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid path encoding")
    })
}

/// Create a new microVM
#[derive(Args, Debug)]
pub struct CreateCmd {
    /// Assign a name to the VM
    name: String,

    /// Port(s) in format "host_port:guest_port" to be exposed to the host
    #[arg(long = "port")]
    ports: Vec<PortPair>,

    /// Environment variable(s) in format "KEY=value" to set in the VM
    #[arg(long = "env")]
    envs: Vec<String>,

    /// Number of CPUs to allocate to the VM
    #[arg(long = "cpus")]
    cpus: Option<u32>,

    /// Amount of RAM in megabytes to allocate to the VM
    #[arg(long = "mem")]
    mem: Option<u32>,

    /// Optional shell script to be executed in the VM for setting up the AI agent.
    script: Option<String>,
}

impl CreateCmd {
    pub fn run(self, cfg: &mut KrunaiConfig, verbose: bool) {
        let mut mapped_ports = port_pairs_to_hash_map(self.ports);
        let name = self.name;

        if cfg.vmconfig_map.contains_key(&name) {
            eprintln!("A VM with this name already exists");
            std::process::exit(-1);
        }

        // Automatically assign an SSH port if not already specified
        if !has_ssh_port_mapping(&mapped_ports) {
            match find_available_ssh_port(cfg) {
                Some(ssh_port) => {
                    crate::vprintln!(
                        verbose,
                        "Automatically assigning SSH port: {} -> 22",
                        ssh_port
                    );
                    mapped_ports.insert(ssh_port.to_string(), "22".to_string());
                }
                None => {
                    eprintln!("Warning: No available SSH ports in range 30000-40000");
                    eprintln!("SSH access may not be available for this VM");
                }
            }
        }

        // Copy disk template to VM's volume directory
        let disk_path = copy_disk_template(&name, verbose).unwrap_or_else(|e| {
            eprintln!("Error copying disk template: {}", e);
            std::process::exit(-1);
        });

        // Generate SSH key pair if it doesn't exist
        generate_ssh_keys(&name).unwrap_or_else(|e| {
            eprintln!("Error generating SSH keys: {}", e);
            std::process::exit(-1);
        });

        // Generate VM setup script
        generate_setup_script(&name, &self.envs).unwrap_or_else(|e| {
            eprintln!("Error generating setup script: {}", e);
            std::process::exit(-1);
        });

        let vmcfg = VmConfig {
            name: name.clone(),
            disk_path,
            mapped_ports: mapped_ports.clone(),
            cpus: self.cpus.unwrap_or(cfg.default_cpus),
            mem: self.mem.unwrap_or(cfg.default_mem),
        };

        // Save configuration before starting VM
        cfg.vmconfig_map.insert(name.clone(), vmcfg.clone());
        config::save_config(cfg).unwrap_or_else(|e| {
            eprintln!("Error saving configuration: {}", e);
            std::process::exit(-1);
        });

        let cwd = env::current_dir().unwrap();
        let workdir = cwd.to_str();
        if let Some(workdir) = workdir {
            crate::vprintln!(verbose, "Sharing '{workdir}' with '{name}'");
        }

        crate::vprintln!(verbose, "Starting VM '{}'...", name);

        // Create lockfile
        create_lockfile(&name).unwrap_or_else(|e| {
            eprintln!("Error creating lockfile: {}", e);
            std::process::exit(-1);
        });

        // Daemonize and start VM
        let vm_for_daemon = vmcfg.clone();
        let daemon_name = name.clone();

        match daemonize_vm(&name) {
            Ok(pid) if pid > 0 => {}
            Ok(_) => {
                // Child/daemon process - run exec_vm
                set_rlimits();
                unsafe {
                    exec_vm(
                        &vm_for_daemon,
                        false,
                        "setup.sh",
                        workdir,
                        Vec::new(),
                        Vec::new(),
                    );
                }
                // Clean up lockfile on exit (if we reach here)
                let _ = utils::remove_lockfile(&daemon_name);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Failed to daemonize: {}", e);
                let _ = utils::remove_lockfile(&name);
                std::process::exit(-1);
            }
        };

        // Test SSH connectivity if SSH port is mapped
        let ssh_ready = if let Some((host_port, _guest_port)) = vmcfg
            .mapped_ports
            .iter()
            .find(|(_, gp)| gp.as_str() == "22")
        {
            // Get SSH key path for testing
            if let Ok(ssh_key_path) = config::get_vm_ssh_key_path(&name) {
                // Test SSH connectivity
                wait_for_ssh_connectivity(&name, host_port, &ssh_key_path, verbose)
            } else {
                false
            }
        } else {
            false
        };

        if !ssh_ready {
            eprintln!("\nError: Failed to establish SSH connection to VM");
            eprintln!("The VM will be deleted");

            // Kill the VM process
            let lockfile_path = config::get_vm_dir(&name).unwrap().join("vm.lock");
            if let Ok(content) = fs::read_to_string(&lockfile_path) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }

            // Delete the VM directory
            if let Ok(vm_dir) = config::get_vm_dir(&name) {
                let _ = fs::remove_dir_all(&vm_dir);
            }

            // Remove from configuration
            cfg.vmconfig_map.remove(&name);
            config::save_config(cfg).ok();

            std::process::exit(-1);
        }

        let mut user_script_success = true;

        // Execute command or open interactive SSH session if SSH is ready
        if ssh_ready {
            if let Some((host_port, _guest_port)) = vmcfg
                .mapped_ports
                .iter()
                .find(|(_, gp)| gp.as_str() == "22")
            {
                if let Ok(ssh_key_path) = config::get_vm_ssh_key_path(&name) {
                    if let Some(ref script) = self.script {
                        // Execute the specified command
                        crate::vprintln!(verbose, "Executing command in VM: {}\n", script);
                        let script = format!("./{script}");

                        let status = Command::new("ssh")
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
                            .arg(format!(
                                "export BASH_ENV=~/.bash_env ; cd /home/agent/work ; bash {script}"
                            ))
                            .status();

                        match status {
                            Err(err) => {
                                eprintln!("Error executing script in the VM: {err}");
                                user_script_success = false;
                            }
                            Ok(status) => {
                                let code = status.code().unwrap_or(-1);
                                if code != 0 {
                                    eprintln!(
                                        "\nUser-provided setup script failed with code {code}"
                                    );
                                    user_script_success = false;
                                }
                            }
                        }
                    } else {
                        // Open interactive SSH session
                        println!("Opening interactive SSH session...\n");
                        println!(
                            "=================================================================="
                        );
                        println!("             *** Install now your AI agent ***\n");
                        println!("You can also install additional development tools using \"sudo apt\"\n");
                        println!(
                            "(Type 'exit' or press Ctrl+D to close the session and save the VM)"
                        );
                        println!(
                            "=================================================================="
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
                    }
                }
            }
        }

        // Check if user script failed and delete VM if so
        if !user_script_success {
            eprintln!("The VM will be deleted");

            // Kill the VM process
            let lockfile_path = config::get_vm_dir(&name).unwrap().join("vm.lock");
            if let Ok(content) = fs::read_to_string(&lockfile_path) {
                if let Ok(pid) = content.trim().parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }

            // Delete the VM directory
            if let Ok(vm_dir) = config::get_vm_dir(&name) {
                let _ = fs::remove_dir_all(&vm_dir);
            }

            // Remove from configuration
            cfg.vmconfig_map.remove(&name);
            config::save_config(cfg).ok();

            std::process::exit(-1);
        }

        // Kill sshd to continue the execution of the initial script. After finishing,
        // the guest will automatically shut down.
        if ssh_ready {
            if let Some((host_port, _guest_port)) = vmcfg
                .mapped_ports
                .iter()
                .find(|(_, gp)| gp.as_str() == "22")
            {
                if let Ok(ssh_key_path) = config::get_vm_ssh_key_path(&name) {
                    crate::vprintln!(verbose, "\nShutting down VM...");
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
                        .arg("-o")
                        .arg("ConnectTimeout=5")
                        .arg("agent@localhost")
                        .arg("sudo")
                        .arg("pkill")
                        .arg("-f")
                        .arg("sshd")
                        .output();
                }
            }
        }

        // Wait for the VM to stop running
        crate::vprintln!(verbose, "\nWaiting for VM to shut down...");

        // Read PID from lockfile
        let lockfile_path = config::get_vm_dir(&name).unwrap().join("vm.lock");
        if let Ok(content) = fs::read_to_string(&lockfile_path) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                if wait_for_process_exit(pid, 30) {
                    crate::vprintln!(verbose, "VM shut down successfully");
                } else {
                    crate::vprintln!(verbose, "Warning: VM did not shut down within 30 seconds");
                }
            } else {
                crate::vprintln!(verbose, "Warning: Could not parse PID from lockfile");
            }
        } else {
            crate::vprintln!(verbose, "Warning: Could not read lockfile");
        }

        // Clean up lockfile
        let _ = utils::remove_lockfile(&name);
    }
}
