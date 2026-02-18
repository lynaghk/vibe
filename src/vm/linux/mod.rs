mod ch;
mod qemu;

pub use crate::cli::Backend;

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use libc;

use crate::{io::LoginAction, share::DirectoryShare};

pub(super) const START_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) const LOGIN_EXPECT_TIMEOUT: Duration = Duration::from_secs(120);

// ── Shared binary/KVM utilities ───────────────────────────────────────────────

pub(super) fn find_binary(name: &str) -> Option<PathBuf> {
    env::var("PATH")
        .ok()?
        .split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|p| p.exists())
}

pub(super) fn check_kvm() -> Result<(), Box<dyn std::error::Error>> {
    let kvm = std::path::Path::new("/dev/kvm");

    if !kvm.exists() {
        return Err(
            "KVM device /dev/kvm not found.\n\
             Make sure the kvm kernel module is loaded: sudo modprobe kvm\n\
             On Intel: sudo modprobe kvm_intel\n\
             On AMD:   sudo modprobe kvm_amd"
                .into(),
        );
    }

    // Check read+write access via access(2) — cheaper than opening the device.
    let ok = unsafe { libc::access(c"/dev/kvm".as_ptr(), libc::R_OK | libc::W_OK) } == 0;
    if !ok {
        let username = env::var("USER").unwrap_or_else(|_| "your user".into());
        return Err(format!(
            "Permission denied on /dev/kvm.\n\
             Add {username} to the kvm group, then start a new shell:\n\
             \n  sudo usermod -aG kvm {username}\n  newgrp kvm"
        )
        .into());
    }

    Ok(())
}

// ── Shared virtiofsd startup ──────────────────────────────────────────────────

pub(super) struct VirtiofsdGuard(Vec<std::process::Child>);

impl Drop for VirtiofsdGuard {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(super) fn start_virtiofsd(
    directory_shares: &[DirectoryShare],
    tmp_dir: &Path,
) -> Result<VirtiofsdGuard, Box<dyn std::error::Error>> {
    if directory_shares.is_empty() {
        return Ok(VirtiofsdGuard(vec![]));
    }

    let vfsd = find_binary("virtiofsd").ok_or(
        "virtiofsd not found in PATH.\n\
         Install: sudo apt install virtiofsd  (Ubuntu 23.10+)\n\
         Or via cargo: cargo install virtiofsd  (then add ~/.cargo/bin to PATH)\n\
         Or download from: https://gitlab.com/virtio-fs/virtiofsd/-/releases",
    )?;

    let mut children: Vec<std::process::Child> = Vec::new();

    for share in directory_shares {
        let socket_path = tmp_dir.join(format!("{}.sock", share.tag()));
        let child = Command::new(&vfsd)
            .args([
                "--socket-path", &socket_path.to_string_lossy(),
                "--shared-dir",  &share.host.to_string_lossy(),
                "--cache",       "auto",
                "--log-level",   "error",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Failed to start virtiofsd: {e}"))?;
        children.push(child);
    }

    // Wait for all virtiofsd sockets to appear
    let vfsd_deadline = Instant::now() + Duration::from_secs(10);
    for share in directory_shares {
        let socket_path = tmp_dir.join(format!("{}.sock", share.tag()));
        while !socket_path.exists() {
            if Instant::now() >= vfsd_deadline {
                return Err(format!(
                    "Timed out waiting for virtiofsd socket for {}",
                    share.host.display()
                )
                .into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    Ok(VirtiofsdGuard(children))
}

// ── Backend availability ──────────────────────────────────────────────────────

/// Returns `(cloud_hypervisor_available, qemu_available)`.
pub fn available_backends() -> (bool, bool) {
    (ch::is_available(), qemu::is_available())
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn run_vm(
    disk_path: &Path,
    login_actions: &[LoginAction],
    directory_shares: &[DirectoryShare],
    cpu_count: usize,
    ram_bytes: u64,
    backend: Option<Backend>,
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = match backend {
        Some(b) => b,
        None => {
            if ch::is_available() {
                Backend::CloudHypervisor
            } else if qemu::is_available() {
                Backend::Qemu
            } else {
                return Err(
                    "No VM backend found.\n\
                     Install cloud-hypervisor: sudo apt install cloud-hypervisor\n\
                     Or install QEMU:          sudo apt install qemu-system-x86 ovmf virtiofsd"
                        .into(),
                );
            }
        }
    };

    match backend {
        Backend::CloudHypervisor => {
            ch::run_vm(disk_path, login_actions, directory_shares, cpu_count, ram_bytes)
        }
        Backend::Qemu => {
            qemu::run_vm(disk_path, login_actions, directory_shares, cpu_count, ram_bytes)
        }
    }
}
