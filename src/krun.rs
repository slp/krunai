use std::convert::TryInto;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::str::FromStr;

use krun_sys::COMPAT_NET_FEATURES;
use libc::c_char;
use mac_address::MacAddress;

use crate::config::get_vm_shared_dir;
use crate::network_proxy;
use crate::network_proxy::ProxyHandle;
use crate::VmConfig;

/// Start network proxy for a VM and return the handle
pub fn start_network_proxy_for_vm(vmcfg: &VmConfig) -> std::io::Result<ProxyHandle> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // Check if SSH port is mapped (port 22)
        let ssh_port = vmcfg
            .mapped_ports
            .iter()
            .find(|(_, guest_port)| guest_port.as_str() == "22")
            .and_then(|(host_port, _)| host_port.parse::<u16>().ok());

        let proxy_config = network_proxy::ProxyConfig::new(&vmcfg.name, ssh_port)?;

        let handle = network_proxy::start_network_proxy(&proxy_config)?;
        println!(
            "\nStarted {} with socket: {}",
            handle.proxy_type, handle.socket_path
        );
        Ok(handle)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Network proxy not supported on this platform",
        ))
    }
}

pub unsafe fn exec_vm(
    vmcfg: &VmConfig,
    init: bool,
    cmd: &str,
    workdir: Option<&str>,
    args: Vec<CString>,
    env_pairs: Vec<CString>,
    proxy_handle: ProxyHandle,
) {
    //krun_sys::krun_set_log_level(9);

    let ctx = krun_sys::krun_create_ctx() as u32;

    let ret = krun_sys::krun_set_vm_config(ctx, vmcfg.cpus.try_into().unwrap(), vmcfg.mem);
    if ret < 0 {
        println!("Error setting VM config");
        std::process::exit(-1);
    }

    let path_cstr = CString::new(vmcfg.disk_path.as_str()).unwrap();
    let path_ptr = path_cstr.as_ptr();

    let label_cstr = CString::new("root").unwrap();
    let label_ptr = label_cstr.as_ptr();

    println!("Configuring disk: {}", vmcfg.disk_path);
    let ret = krun_sys::krun_add_disk2(
        ctx,
        label_ptr,
        path_ptr,
        krun_sys::KRUN_DISK_FORMAT_QCOW2,
        false,
    );
    if ret < 0 {
        println!("Error adding disk");
        std::process::exit(-1);
    }

    let device_cstr = CString::new("/dev/vda1").unwrap();
    let device_ptr = device_cstr.as_ptr();

    let fstype_cstr = CString::new("ext4").unwrap();
    let fstype_ptr = fstype_cstr.as_ptr();

    let ret = krun_sys::krun_set_root_disk_remount(ctx, device_ptr, fstype_ptr, std::ptr::null());
    if ret < 0 {
        println!("Error configuring root disk");
        std::process::exit(-1);
    }

    let tag_cstr = CString::new("krunai").unwrap();
    let tag_ptr = tag_cstr.as_ptr();

    let path_cstr =
        CString::new(get_vm_shared_dir(&vmcfg.name).unwrap().to_str().unwrap()).unwrap();
    let path_ptr = path_cstr.as_ptr();

    let ret = krun_sys::krun_add_virtiofs(ctx, tag_ptr, path_ptr);
    if ret < 0 {
        println!("Error configuring krunai virtio-fs");
        std::process::exit(-1);
    }

    if let Some(workdir) = workdir {
        let tag_cstr = CString::new("work").unwrap();
        let tag_ptr = tag_cstr.as_ptr();

        let path_cstr = CString::new(workdir).unwrap();
        let path_ptr = path_cstr.as_ptr();

        let ret = krun_sys::krun_add_virtiofs(ctx, tag_ptr, path_ptr);
        if ret < 0 {
            println!("Error configuring workdir virtio-fs");
            std::process::exit(-1);
        }
    }

    let ret = krun_sys::krun_disable_implicit_vsock(ctx);
    if ret < 0 {
        println!("Error disabling implicit vsock");
        std::process::exit(-1);
    }

    // Configure a vsock device without TSI. We just need it for TIMESYNC.
    let ret = krun_sys::krun_add_vsock(ctx, 0);
    if ret < 0 {
        println!("Error configuring vsock");
        std::process::exit(-1);
    }

    let mac = MacAddress::from_str("5a:94:ef:e4:0c:ee").unwrap();
    let ret = if let Some(socket_pair) = proxy_handle.socket_pair {
        krun_sys::krun_add_net_unixstream(
            ctx,
            std::ptr::null(),
            socket_pair.parent.as_raw_fd(),
            mac.bytes().as_mut_ptr(),
            COMPAT_NET_FEATURES,
            0,
        )
    } else {
        let path_cstr = CString::new(proxy_handle.socket_path).unwrap();
        let path_ptr = path_cstr.as_ptr();
        krun_sys::krun_add_net_unixstream(
            ctx,
            path_ptr,
            -1,
            mac.bytes().as_mut_ptr(),
            COMPAT_NET_FEATURES,
            0,
        )
    };
    if ret < 0 {
        println!("Error configuring the network");
        std::process::exit(-1);
    }

    let mut ports = Vec::new();
    for (host_port, guest_port) in vmcfg.mapped_ports.iter() {
        let map = format!("{}:{}", host_port, guest_port);
        ports.push(CString::new(map).unwrap());
    }
    let mut ps: Vec<*const c_char> = Vec::new();
    for port in ports.iter() {
        ps.push(port.as_ptr());
    }
    ps.push(std::ptr::null());

    let hostname = CString::new(format!("HOSTNAME={}", vmcfg.name)).unwrap();
    let home = CString::new("HOME=/root").unwrap();
    let entry = CString::new(format!("ENTRY={cmd}")).unwrap();

    let mut env: Vec<*const c_char> = Vec::new();
    env.push(hostname.as_ptr());
    env.push(home.as_ptr());
    env.push(entry.as_ptr());
    for value in env_pairs.iter() {
        env.push(value.as_ptr());
    }
    env.push(std::ptr::null());

    let mut argv: Vec<*const c_char> = Vec::new();
    for a in args.iter() {
        argv.push(a.as_ptr());
    }
    argv.push(std::ptr::null());

    let c_cmd = if init {
        CString::new(cmd).unwrap()
    } else {
        CString::new("/.krunai.sh").unwrap()
    };
    let ret = krun_sys::krun_set_exec(ctx, c_cmd.as_ptr(), argv.as_ptr(), env.as_ptr());
    if ret < 0 {
        println!("Error setting VM config");
        std::process::exit(-1);
    }

    let ret = krun_sys::krun_start_enter(ctx);
    if ret < 0 {
        println!("Error starting VM");
        std::process::exit(-1);
    }
}
