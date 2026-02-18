use std::{
    collections::HashSet,
    ffi::OsString,
    fs,
    io::{BufRead, BufReader},
    os::unix::io::OwnedFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use crate::{
    disk::BYTES_PER_MB,
    io::{
        LoginAction, LoginAction::Send, VmOutput, OutputMonitor,
        spawn_vm_io, spawn_login_actions_thread,
    },
    share::DirectoryShare,
};

// ── Architecture-specific helpers ─────────────────────────────────────────────

fn qemu_binary_name() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "qemu-system-aarch64"
    } else {
        "qemu-system-x86_64"
    }
}

fn machine_type() -> &'static str {
    if cfg!(target_arch = "aarch64") { "virt" } else { "q35" }
}

// ── Firmware discovery ────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn find_ovmf_firmware() -> Option<(PathBuf, PathBuf)> {
    let candidates: &[(&str, &str)] = &[
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ),
        (
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
        ),
        (
            "/usr/share/ovmf/OVMF_CODE.fd",
            "/usr/share/ovmf/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ),
    ];
    for &(code, vars) in candidates {
        let code = PathBuf::from(code);
        let vars = PathBuf::from(vars);
        if code.exists() && vars.exists() {
            return Some((code, vars));
        }
    }
    None
}

#[cfg(target_arch = "aarch64")]
fn find_ovmf_firmware() -> Option<(PathBuf, PathBuf)> {
    let candidates: &[(&str, &str)] = &[
        (
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/AAVMF/AAVMF_VARS.fd",
        ),
        (
            "/usr/share/aavmf/AAVMF_CODE.fd",
            "/usr/share/aavmf/AAVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/aarch64/QEMU_EFI.fd",
            "/usr/share/edk2/aarch64/QEMU_VARS.fd",
        ),
    ];
    for &(code, vars) in candidates {
        let code = PathBuf::from(code);
        let vars = PathBuf::from(vars);
        if code.exists() && vars.exists() {
            return Some((code, vars));
        }
    }
    None
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn find_ovmf_firmware() -> Option<(PathBuf, PathBuf)> {
    None
}

// ── Availability check ────────────────────────────────────────────────────────

pub fn is_available() -> bool {
    super::find_binary(qemu_binary_name()).is_some()
}

// ── PTY detection via /dev/pts polling ───────────────────────────────────────

fn existing_pts_entries() -> HashSet<OsString> {
    fs::read_dir("/dev/pts")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name())
        .collect()
}

fn wait_for_new_pty(
    before: &HashSet<OsString>,
    deadline: Instant,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    loop {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for QEMU serial PTY".into());
        }
        let new = fs::read_dir("/dev/pts")
            .into_iter()
            .flatten()
            .flatten()
            .find(|e| {
                let name = e.file_name();
                name.to_str() != Some("ptmx") && !before.contains(&name)
            })
            .map(|e| e.path());
        if let Some(path) = new {
            return Ok(path);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ── run_vm ────────────────────────────────────────────────────────────────────

pub fn run_vm(
    disk_path: &Path,
    login_actions: &[LoginAction],
    directory_shares: &[DirectoryShare],
    cpu_count: usize,
    ram_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Preflight checks ──────────────────────────────────────────────────────

    if let Err(e) = super::check_kvm() {
        return Err(e);
    }

    let qemu_bin = super::find_binary(qemu_binary_name()).ok_or_else(|| -> Box<dyn std::error::Error> {
        format!(
            "{} not found in PATH.\n\
             Install: sudo apt install qemu-system-x86  (x86_64) or qemu-system-arm  (aarch64)",
            qemu_binary_name()
        )
        .into()
    })?;

    let (ovmf_code, ovmf_vars) = find_ovmf_firmware().ok_or(
        "OVMF firmware not found.\n\
         Install: sudo apt install ovmf  (x86_64) or sudo apt install qemu-efi-aarch64  (aarch64)",
    )?;

    // ── Per-session temp directory ────────────────────────────────────────────

    let pid = std::process::id();
    let tmp_dir = std::env::temp_dir().join(format!("vibe-{pid}"));
    fs::create_dir_all(&tmp_dir)?;

    struct TmpDirGuard(PathBuf);
    impl Drop for TmpDirGuard {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    let _tmp_guard = TmpDirGuard(tmp_dir.clone());

    // ── Copy OVMF vars to writable per-session file ───────────────────────────

    let efivars_path = tmp_dir.join("efivars.fd");
    fs::copy(&ovmf_vars, &efivars_path)
        .map_err(|e| format!("Failed to copy OVMF vars: {e}"))?;

    // ── Start virtiofsd for each directory share ──────────────────────────────

    let _vfsd_guard = super::start_virtiofsd(directory_shares, &tmp_dir)?;

    // ── Build QEMU command ────────────────────────────────────────────────────

    let ram_mb = ram_bytes / BYTES_PER_MB;

    let mut qemu_cmd = Command::new(&qemu_bin);
    qemu_cmd.args([
        "-enable-kvm",
        "-machine", machine_type(),
        "-cpu", "host",
        "-smp", &cpu_count.to_string(),
        "-m", &format!("{}M", ram_mb),
        "-drive", &format!("file={},if=virtio,format=raw", disk_path.to_string_lossy()),
        "-drive", &format!("if=pflash,format=raw,readonly=on,file={}", ovmf_code.to_string_lossy()),
        "-drive", &format!("if=pflash,format=raw,file={}", efivars_path.to_string_lossy()),
        "-netdev", "user,id=net0",
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", "pty",
    ]);

    // For virtiofs: need shared memory backend
    if !directory_shares.is_empty() {
        qemu_cmd.args([
            "-object", &format!("memory-backend-memfd,id=mem,size={}M,share=on", ram_mb),
            "-numa", "node,memdev=mem",
        ]);
        for (i, share) in directory_shares.iter().enumerate() {
            let socket_path = tmp_dir.join(format!("{}.sock", share.tag()));
            qemu_cmd.args([
                "-chardev", &format!("socket,id=char{i},path={}", socket_path.to_string_lossy()),
                "-device", &format!("vhost-user-fs-pci,queue-size=1024,chardev=char{i},tag={}", share.tag()),
            ]);
        }
    }

    // ── Snapshot /dev/pts before spawning ────────────────────────────────────

    let pts_before = existing_pts_entries();

    let mut qemu_process = qemu_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start {}: {e}", qemu_binary_name()))?;

    struct QemuGuard(Option<std::process::Child>);
    impl Drop for QemuGuard {
        fn drop(&mut self) {
            if let Some(ref mut c) = self.0 { let _ = c.kill(); let _ = c.wait(); }
        }
    }

    // Forward QEMU stderr, suppressing known harmless noise
    let stderr = qemu_process.stderr.take().unwrap();
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if !line.contains("Cannot announce submounts") {
                eprintln!("{line}");
            }
        }
    });

    // ── Find the serial PTY ───────────────────────────────────────────────────

    let deadline = Instant::now() + super::START_TIMEOUT;
    let pty_path = match wait_for_new_pty(&pts_before, deadline) {
        Ok(p) => p,
        Err(e) => { let _ = qemu_process.kill(); return Err(e); }
    };

    let mut qemu_guard = QemuGuard(Some(qemu_process));

    println!("VM booting...");

    let pty_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pty_path)
        .map_err(|e| format!("Failed to open serial PTY {}: {e}", pty_path.display()))?;

    let vm_output_fd: OwnedFd = pty_file.try_clone()?.into();
    let vm_input_fd: OwnedFd = pty_file.into();

    // ── Wire up I/O and build login sequence ──────────────────────────────────

    let output_monitor = Arc::new(OutputMonitor::default());
    let io_ctx = spawn_vm_io(output_monitor.clone(), vm_output_fd, vm_input_fd);

    let mut all_login_actions = vec![
        LoginAction::Expect { text: "login: ".into(), timeout: super::LOGIN_EXPECT_TIMEOUT },
        Send("root".into()),
        LoginAction::Expect { text: "~#".into(), timeout: super::LOGIN_EXPECT_TIMEOUT },
        Send("stty sane".into()),
    ];

    for share in directory_shares {
        let guest = share.guest.to_string_lossy();
        all_login_actions.push(Send(format!("mkdir -p {}", guest)));
        all_login_actions.push(Send(format!("mount -t virtiofs {} {}", share.tag(), guest)));
    }

    for a in login_actions {
        all_login_actions.push(a.clone());
    }

    // ── Event loop ────────────────────────────────────────────────────────────

    let (vm_output_tx, vm_output_rx) = mpsc::channel::<VmOutput>();
    let login_thread = spawn_login_actions_thread(
        all_login_actions,
        output_monitor.clone(),
        io_ctx.input_tx.clone(),
        vm_output_tx,
    );

    let mut exit_result: Result<(), Box<dyn std::error::Error>> = Ok(());

    loop {
        match qemu_guard.0.as_mut().unwrap().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => {
                exit_result = Err(format!("Error waiting for QEMU: {e}").into());
                break;
            }
        }

        match vm_output_rx.try_recv() {
            Ok(VmOutput::LoginActionTimeout { action, timeout }) => {
                exit_result = Err(format!(
                    "Login action ({}) timed out after {:?}; shutting down.",
                    action, timeout
                )
                .into());
                if let Some(ref mut c) = qemu_guard.0 {
                    let _ = c.kill();
                }
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {}
        }

        thread::sleep(Duration::from_millis(200));
    }

    let _ = login_thread.join();
    io_ctx.shutdown();

    if let Some(ref mut qemu) = qemu_guard.0 {
        let _ = qemu.wait();
    }
    qemu_guard.0 = None;

    exit_result
}
