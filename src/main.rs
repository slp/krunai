// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::env;
#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::io::{Error, ErrorKind};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStringExt;

use crate::commands::{CloneCmd, ConnectCmd, CreateCmd, DeleteCmd, ExportCmd, ImportCmd, InitCmd, ListCmd, StartCmd, StopCmd};
use clap::{Parser, Subcommand};
#[cfg(target_os = "macos")]
use nix::unistd::execve;
use serde_derive::{Deserialize, Serialize};

mod commands;
mod config;
#[cfg(target_os = "macos")]
mod gvproxy;
mod krun;
mod network_proxy;
#[cfg(target_os = "linux")]
mod passt;
mod utils;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub name: String,
    pub disk_path: String,
    pub cpus: u32,
    pub mem: u32,
    pub mapped_ports: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KrunaiConfig {
    version: u8,
    default_cpus: u32,
    default_mem: u32,
    vmconfig_map: HashMap<String, VmConfig>,
}

impl Default for KrunaiConfig {
    fn default() -> KrunaiConfig {
        KrunaiConfig {
            version: 1,
            default_cpus: 4,
            default_mem: 8192,
            vmconfig_map: HashMap::new(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Sets the level of verbosity
    #[arg(short)]
    verbosity: Option<u8>, //TODO: implement or remove this
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Clone(CloneCmd),
    Connect(ConnectCmd),
    Create(CreateCmd),
    Delete(DeleteCmd),
    Export(ExportCmd),
    Import(ImportCmd),
    Init(InitCmd),
    List(ListCmd),
    Start(StartCmd),
    Stop(StopCmd),
}

#[cfg(target_os = "macos")]
fn get_brew_prefix() -> Option<String> {
    let output = std::process::Command::new("brew")
        .arg("--prefix")
        .stderr(std::process::Stdio::inherit())
        .output()
        .ok()?;

    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 {
        return None;
    }

    Some(std::str::from_utf8(&output.stdout).ok()?.trim().to_string())
}

#[cfg(target_os = "macos")]
fn reexec() -> Result<(), Error> {
    let exec_path = env::current_exe().map_err(|_| ErrorKind::NotFound)?;
    let exec_cstr = CString::new(exec_path.to_str().ok_or(ErrorKind::InvalidFilename)?)?;

    let args: Vec<CString> = env::args_os()
        .map(|arg| CString::new(arg.into_vec()).unwrap())
        .collect();

    let mut envs: Vec<CString> = env::vars_os()
        .map(|(key, value)| {
            CString::new(format!(
                "{}={}",
                key.into_string().unwrap(),
                value.into_string().unwrap()
            ))
            .unwrap()
        })
        .collect();
    let brew_prefix = get_brew_prefix().ok_or(ErrorKind::NotFound)?;
    envs.push(CString::new(format!(
        "DYLD_LIBRARY_PATH={brew_prefix}/lib"
    ))?);

    // Use execve to replace the current process. This function only returns
    // if an error occurs.
    match execve(&exec_cstr, &args, &envs) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("Error re-executing krunai: {}", e);
            std::process::exit(-1);
        }
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    {
        if env::var("DYLD_LIBRARY_PATH").is_err() {
            _ = reexec();
        }
    }

    let mut cfg: KrunaiConfig = config::load_config().unwrap_or_else(|e| {
        eprintln!("Error loading configuration: {}", e);
        std::process::exit(-1);
    });
    let cli_args = Cli::parse();

    match cli_args.command {
        Command::Clone(cmd) => cmd.run(&mut cfg),
        Command::Connect(cmd) => cmd.run(&cfg),
        Command::Create(cmd) => cmd.run(&mut cfg),
        Command::Delete(cmd) => cmd.run(&mut cfg),
        Command::Export(cmd) => cmd.run(&cfg),
        Command::Import(cmd) => cmd.run(&mut cfg),
        Command::Init(cmd) => cmd.run(&cfg),
        Command::List(cmd) => cmd.run(&cfg),
        Command::Start(cmd) => cmd.run(&cfg),
        Command::Stop(cmd) => cmd.run(&cfg),
    }
}
