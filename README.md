# krunai

An easy to use, fast and powerful tool for running AI agents inside microVM sandboxes.

## Requirements

- macOS or Linux (soon, waiting on a new libkrunfw release)
- `gvproxy` (on macOS, for network access)
- `passt` (on Linux, for network access)
- `qemu-img` (for image resizing)
- `curl` (for downloading base images)
- `ssh` client
- Rust toolchain (for building from source)

## Installation

### macOS Homebrew Tap

```bash
brew tap slp/krun
brew install krunai
```

### Linux

Coming soon, waiting on a new libkrunfw release.

## Quick Start

### 1. Initialize the VM Template

First, download and initialize the VM template:

```bash
krunai init
```

### 2. Create a VM sandbox

Switch to your project's directory (will be automatically shared with the VM) and create a new VM sandbox for your agent:

```bash
cd ~/Project/myproject
krunai create myagent
```

After the VM sandbox has been created, you'll be presented with the VM's shell and asked to install your agent following the usual installation instructions (network access is enabled).

Your project's directory will be mounted at `~/work`, in case your agent requires per-project configuration.

Alternatively, you can automate the installation and configuration of the AI agent by creating a shell script in your project's directory, and passing it as positional argument to `krunai`:

```bash
cp agent-setup.sh ~/Project/myproject
cd ~/Project/myproject
krunai create myagent agent-setup.sh
```

If your agent accepts network connections (i.e. from an IDE), you can expose the agent's port using `--port HOST_PORT:GUEST_PORT` (can be specified multiple times if more that one port needs to be exposed):

```bash
cd ~/Project/myproject
krunai create --port 1234:1234 --port 3333:8080 myagent
```

By default, the VM will be created with 4 cpus and 8192 MB of RAM. If your agent's requirements are different, you can use the `--cpus` and `--mem` flags to set them as desired:

```bash
cd ~/Project/myproject
krunai create --cpus 4 --mem 4096 myagent
```

### 3. Start the VM

Switch to your project's directory (will be automatically shared with the VM) and start the VM sandbox in the background:

```bash
cd ~/Project/myproject
krunai start myagent
```

Or start and immediately connect via SSH:

```bash
cd ~/Project/myproject
krunai start -c myagent
```

If the VM is already running, use the `-f` flag to restart it:

```bash
cd ~/Project/myproject
krunai start -f myagent
```

You can combine both flags to always ensure you get a clean shell for working your current project:

```bash
cd ~/Project/myproject
krunai start -fc myagent

Your project's directory will be mounted at `~/work` in the sandbox.

### 4. Connect to the VM

Connect to a running VM:

```bash
krunai connect myagent
```

## Commands

### list

List all VMs and their status:

```bash
krunai list
```

Use `--verbose` for detailed output including disk paths, SSH keys, and port mappings.

### stop

Stop a running VM:

```bash
krunai stop myagent
```

### delete

Delete a VM and all its data:

```bash
krunai delete myagent
```

### clone

Clone an existing VM to create a new VM with the same configuration and disk contents:

```bash
krunai clone myagent myagent-clone
```

The cloned VM will automatically receive a new SSH key pair and SSH port assignment.

### export

Export a VM to a tarball for backup or sharing:

```bash
krunai export myagent myagent-backup.tar.gz
```

The tarball contains the VM disk, configuration, and SSH keys. The VM must be stopped before exporting.

### import

Import a VM from a previously exported tarball:

```bash
krunai import myagent-backup.tar.gz myagent-restored
```

The imported VM will automatically receive a new SSH port assignment.

## Global Options

### Verbose Output

Use the `--verbose` or `-v` flag with any command to see detailed progress messages:

```bash
krunai --verbose start myagent
krunai -v create myagent
```

Without the verbose flag, only essential messages and errors are displayed.

## Caveats

### Platform discrepancy

Even when running the tool on macOS, the VM sandbox is actually a Linux system. If your project is producing native binaries or using OS-specific functions, it may confuse the agent running in the sandbox.

Make sure to tell the agent about the platform discrepancy. In most cases, you can manually build the project from the host and feed the build process messages to the agent.

## License

Apache License 2.0

## Credits

Built on top of:
- [libkrun](https://github.com/containers/libkrun) - Lightweight VM library
- [gvproxy](https://github.com/containers/gvisor-tap-vsock) - A new network stack based on gVisor
- [passt](https://passt.top/passt/) - Plug A Simple Socket Transport
- [Debian Cloud Images](https://cloud.debian.org/) - Base VM images
