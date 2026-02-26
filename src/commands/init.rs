// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use clap::Args;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::FromRawFd;
use std::process::Command;

use crate::config;
use crate::krun::exec_vm;
use crate::VmConfig;

#[cfg(target_arch = "aarch64")]
const DEBIAN_IMAGE_URL: &str =
    "https://cdimage.debian.org/images/cloud/trixie/latest/debian-13-nocloud-arm64.qcow2";
#[cfg(target_arch = "x86_64")]
const DEBIAN_IMAGE_URL: &str =
    "https://cdimage.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2";
const TEMPLATE_DISK_NAME: &str = "debian-13-nocloud.qcow2";

/// Initialize the Debian template
#[derive(Args, Debug)]
pub struct InitCmd {}

impl InitCmd {
    pub fn run(self, cfg: &crate::KrunaiConfig, verbose: bool) {
        crate::vprintln!(verbose, "Initializing VM template...");

        // Get configuration directory
        let config_dir = config::get_config_dir().unwrap_or_else(|e| {
            eprintln!("Error getting config directory: {}", e);
            std::process::exit(-1);
        });

        let template_path = config_dir.join(TEMPLATE_DISK_NAME);

        // Check if template already exists
        if template_path.exists() {
            eprintln!("Template already exists at {}", template_path.display());
            eprintln!("Remove it first if you want to reinitialize");
            std::process::exit(-1);
        }

        // Download the base image
        println!("\nDownloading Debian base image...");
        crate::vprintln!(verbose, "URL: {}", DEBIAN_IMAGE_URL);
        crate::vprintln!(verbose, "Destination: {}", template_path.display());

        let status = Command::new("curl")
            .arg("-L")
            .arg("-o")
            .arg(&template_path)
            .arg("--progress-bar")
            .arg(DEBIAN_IMAGE_URL)
            .status();

        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("Error: Download failed with status: {}", status);
                std::process::exit(-1);
            }
            Err(e) => {
                eprintln!("Error downloading image: {}", e);
                std::process::exit(-1);
            }
        }

        // Resize the image to 100GB
        println!("\nResizing image to 100GB...");
        let status = Command::new("qemu-img")
            .arg("resize")
            .arg(&template_path)
            .arg("100G")
            .status();

        match status {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("Error: Resize failed with status: {}", status);
                std::process::exit(-1);
            }
            Err(e) => {
                eprintln!("Error resizing image: {}", e);
                eprintln!("Make sure qemu-img is installed");
                std::process::exit(-1);
            }
        }

        // Initialize the template using exec_vm with serial console
        println!("\nInitializing template VM...");

        // Create a temporary VM directory structure
        let temp_vm_name = "template-init";
        let temp_vm_dir = config::get_vm_dir(temp_vm_name).unwrap_or_else(|e| {
            eprintln!("Error getting temp VM directory: {}", e);
            std::process::exit(-1);
        });

        // Ensure the VM directories exist
        config::ensure_vm_dir_exists(temp_vm_name).unwrap_or_else(|e| {
            eprintln!("Error creating temp VM directories: {}", e);
            std::process::exit(-1);
        });

        // Create a temporary VmConfig for initialization
        // Add a temporary SSH port mapping (even though we won't use SSH)
        let mut temp_ports = HashMap::new();
        temp_ports.insert("30000".to_string(), "22".to_string());

        let temp_vmcfg = VmConfig {
            name: temp_vm_name.to_string(),
            disk_path: template_path.to_str().unwrap().to_string(),
            mapped_ports: temp_ports,
            cpus: cfg.default_cpus,
            mem: cfg.default_mem,
        };

        // Start network proxy to get DHCP IPs
        crate::vprintln!(verbose, "Starting network proxy...");
        let proxy_handle = crate::krun::start_network_proxy_for_vm(&temp_vmcfg, verbose)
            .unwrap_or_else(|e| {
                eprintln!("Error: Failed to start network proxy: {}", e);
                std::process::exit(-1);
            });

        // Extract IPs from proxy handle
        let guest_ip = &proxy_handle.guest_ip;
        let router_ip = &proxy_handle.router_ip;

        crate::vprintln!(
            verbose,
            "Using guest IP: {}, router IP: {}",
            guest_ip,
            router_ip
        );

        let setup_script_content = format!(
            r##"#!/bin/bash

# Configure network
echo "==> Configuring the network..."
ip addr add {}/24 dev eth0
ip link set up dev eth0
ip route add default via {}
rm /etc/resolv.conf
echo "nameserver {}" > /etc/resolv.conf

# Update package lists
echo "==> Updating package lists..."
apt-get update -qq

# Install openssh-server and sudo
echo "==> Installing cloud-guest-utils openssh-server, sudo, build-essential and git..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server sudo cloud-guest-utils build-essential git

# Resizing partition
echo "==> Resizing /dev/vda to be as large as possible"
growpart /dev/vda 1
resize2fs /dev/vda1

# Disabling motd
echo "==> Disabling motd"
sed -E -i 's/.*(session.*motd.*)/\#\1/' /etc/pam.d/sshd

# Writing init script
echo "==> Writing init script"
cat > /.krunai.sh << 'EOFINIT'
#!/bin/sh
mkdir -p /run/sshd
mkdir -p /krunai
mount -t virtiofs krunai /krunai
exec /krunai/$ENTRY
EOFINIT
chmod +x /.krunai.sh

echo "==> Done"
sync
echo "KRUNAIDONE"
"##,
            guest_ip, router_ip, router_ip
        );

        crate::vprintln!(verbose, "\nStarting VM with serial console...");

        // Create pipes for stdin and stdout
        let mut stdin_pipe: [libc::c_int; 2] = [0; 2];
        let mut stdout_pipe: [libc::c_int; 2] = [0; 2];

        unsafe {
            if libc::pipe(stdin_pipe.as_mut_ptr()) < 0 {
                eprintln!("Failed to create stdin pipe");
                std::process::exit(-1);
            }
            if libc::pipe(stdout_pipe.as_mut_ptr()) < 0 {
                eprintln!("Failed to create stdout pipe");
                std::process::exit(-1);
            }
        }

        // Fork to run exec_vm in a separate process
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            eprintln!("Failed to fork process");
            std::process::exit(-1);
        }

        if pid == 0 {
            // Child process - redirect stdin/stdout to pipes and run exec_vm
            unsafe {
                // Close unused ends of pipes
                libc::close(stdin_pipe[1]); // Close write end of stdin
                libc::close(stdout_pipe[0]); // Close read end of stdout

                // Redirect stdin from pipe
                libc::dup2(stdin_pipe[0], 0);
                libc::close(stdin_pipe[0]);

                // Redirect stdout to pipe
                libc::dup2(stdout_pipe[1], 1);
                // Also redirect stderr to stdout
                libc::dup2(stdout_pipe[1], 2);
                libc::close(stdout_pipe[1]);

                // Run a simple shell to interact with
                exec_vm(
                    &temp_vmcfg,
                    true,
                    "/bin/sh",
                    None,
                    Vec::new(),
                    Vec::new(),
                    proxy_handle,
                    verbose,
                );
            }
            std::process::exit(0);
        }

        // Parent process - close unused ends of pipes
        unsafe {
            libc::close(stdin_pipe[0]); // Close read end of stdin
            libc::close(stdout_pipe[1]); // Close write end of stdout
        }

        // Create File handles from the pipe file descriptors
        let mut vm_stdin = unsafe { File::from_raw_fd(stdin_pipe[1]) };

        let vm_stdout = unsafe { File::from_raw_fd(stdout_pipe[0]) };
        let mut reader = BufReader::new(vm_stdout);

        // Wait for VM to boot and get a shell prompt
        crate::vprintln!(verbose, "Waiting for VM to boot...");

        // Read any initial output
        let mut buf = [0; 1];
        let _ = reader.read(&mut buf);

        crate::vprintln!(verbose, "\nWriting setup script to VM...");

        // Create the script using cat with heredoc
        writeln!(vm_stdin, "cat > /.krunai-setup.sh << 'EOFSCRIPT'").ok();
        write!(vm_stdin, "{}", setup_script_content).ok();
        writeln!(vm_stdin, "EOFSCRIPT").ok();

        writeln!(vm_stdin, "chmod +x /.krunai-setup.sh").ok();

        crate::vprintln!(verbose, "\nExecuting setup script...");
        writeln!(vm_stdin, "/.krunai-setup.sh").ok();

        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() && !line.is_empty() {
                if line.contains("KRUNAIDONE") {
                    break;
                }
                crate::vprint!(verbose, "VM: {}", line);
            }
            line.clear();
        }

        // Shutdown the VM
        println!("\nShutting down VM...");
        writeln!(vm_stdin, "/sbin/poweroff -f").ok();

        // Wait for child process to complete
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }

        // Clean up temporary VM directory
        let _ = fs::remove_dir_all(&temp_vm_dir);

        println!("\nTemplate initialized successfully!");
    }
}
