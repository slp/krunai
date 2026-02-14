// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use crate::KrunaiConfig;

const CONFIG_DIR_NAME: &str = ".krunai";
const CONFIG_FILE_NAME: &str = "config.toml";
const VM_DISK_NAME: &str = "disk.qcow2";
const VM_SOCKET_NAME: &str = "vm.sock";
const VM_LOGS_DIR_NAME: &str = "logs";
const NETWORK_LOG_NAME: &str = "network.log";
const VM_SSH_KEY_NAME: &str = "id_ed25519";
const VM_SSH_PUBKEY_NAME: &str = "id_ed25519.pub";
const VM_SHARED_DIR_NAME: &str = "shared";
const VM_SETUP_SCRIPT_NAME: &str = "setup.sh";

/// Get the base configuration directory path ($HOME/.krunai)
pub fn get_config_dir() -> io::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| io::Error::new(ErrorKind::NotFound, "HOME environment variable not set"))?;

    Ok(PathBuf::from(home).join(CONFIG_DIR_NAME))
}

/// Get the configuration file path ($HOME/.krunai/config.toml)
pub fn get_config_file_path() -> io::Result<PathBuf> {
    Ok(get_config_dir()?.join(CONFIG_FILE_NAME))
}

/// Get a VM's directory path ($HOME/.krunai/<vm_name>)
pub fn get_vm_dir(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_config_dir()?.join(vm_name))
}

/// Get a VM's disk path ($HOME/.krunai/<vm_name>/disk.qcow2)
pub fn get_vm_disk_path(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_dir(vm_name)?.join(VM_DISK_NAME))
}

/// Get a VM's socket path ($HOME/.krunai/<vm_name>/vm.sock)
pub fn get_vm_socket_path(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_dir(vm_name)?.join(VM_SOCKET_NAME))
}

/// Get a VM's logs directory path ($HOME/.krunai/<vm_name>/logs)
pub fn get_vm_logs_dir(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_dir(vm_name)?.join(VM_LOGS_DIR_NAME))
}

/// Get a VM's network log path ($HOME/.krunai/<vm_name>/logs/network.log)
pub fn get_vm_network_log_path(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_logs_dir(vm_name)?.join(NETWORK_LOG_NAME))
}

/// Get a VM's SSH private key path ($HOME/.krunai/<vm_name>/id_ed25519)
pub fn get_vm_ssh_key_path(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_dir(vm_name)?.join(VM_SSH_KEY_NAME))
}

/// Get a VM's SSH public key path ($HOME/.krunai/<vm_name>/id_ed25519.pub)
pub fn get_vm_ssh_pubkey_path(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_dir(vm_name)?.join(VM_SSH_PUBKEY_NAME))
}

/// Get a VM's shared directory path ($HOME/.krunai/<vm_name>/shared)
pub fn get_vm_shared_dir(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_dir(vm_name)?.join(VM_SHARED_DIR_NAME))
}

/// Get a VM's setup script path ($HOME/.krunai/<vm_name>/shared/setup.sh)
pub fn get_vm_setup_script_path(vm_name: &str) -> io::Result<PathBuf> {
    Ok(get_vm_shared_dir(vm_name)?.join(VM_SETUP_SCRIPT_NAME))
}

/// Ensure the configuration directory structure exists
pub fn ensure_config_dir_exists() -> io::Result<()> {
    let config_dir = get_config_dir()?;
    fs::create_dir_all(&config_dir)?;
    Ok(())
}

/// Ensure a VM's directory structure exists
pub fn ensure_vm_dir_exists(vm_name: &str) -> io::Result<()> {
    let vm_dir = get_vm_dir(vm_name)?;
    let logs_dir = get_vm_logs_dir(vm_name)?;
    let shared_dir = get_vm_shared_dir(vm_name)?;

    fs::create_dir_all(&vm_dir)?;
    fs::create_dir_all(&logs_dir)?;
    fs::create_dir_all(&shared_dir)?;

    Ok(())
}

/// Load the configuration from $HOME/.krunai/config.toml
pub fn load_config() -> io::Result<KrunaiConfig> {
    ensure_config_dir_exists()?;

    let config_path = get_config_file_path()?;

    // If config file doesn't exist, create default and return it
    if !config_path.exists() {
        let default_config = KrunaiConfig::default();
        save_config(&default_config)?;
        return Ok(default_config);
    }

    // Read and parse the config file
    let config_content = fs::read_to_string(&config_path)?;
    let config: KrunaiConfig =
        toml::from_str(&config_content).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    Ok(config)
}

/// Save the configuration to $HOME/.krunai/config.toml
pub fn save_config(config: &KrunaiConfig) -> io::Result<()> {
    ensure_config_dir_exists()?;

    let config_path = get_config_file_path()?;
    let config_content =
        toml::to_string_pretty(config).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

    fs::write(&config_path, config_content)?;

    Ok(())
}
