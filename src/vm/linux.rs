use std::{
    env,
    fs,
    io::{Read, Write},
    os::unix::{io::OwnedFd, net::UnixStream},
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

const START_TIMEOUT: Duration = Duration::from_secs(60);
const LOGIN_EXPECT_TIMEOUT: Duration = Duration::from_secs(120);

// ── Binary / firmware discovery ───────────────────────────────────────────────

fn find_binary(name: &str) -> Option<PathBuf> {
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    for prefix in ["/usr/bin", "/usr/local/bin", "/opt/cloud-hypervisor"] {
        let candidate = PathBuf::from(prefix).join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn find_efi_firmware() -> Option<PathBuf> {
    let candidates: &[&str] = &[
        "/usr/share/cloud-hypervisor/CLOUDHV.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/aavmf/AAVMF_CODE.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

// ── cloud-hypervisor REST API (raw HTTP/1.1 over Unix socket) ─────────────────

fn ch_api_get(socket_path: &Path, api_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect to API socket: {e}"))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        api_path
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let raw = String::from_utf8_lossy(&buf).into_owned();

    // Strip HTTP headers
    Ok(if let Some(pos) = raw.find("\r\n\r\n") { raw[pos + 4..].to_string() } else { raw })
}

fn ch_api_put(
    socket_path: &Path,
    api_path: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect to API socket: {e}"))?;

    let request = format!(
        "PUT {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        api_path, body.len(), body
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(())
}

// ── Serial PTY discovery ──────────────────────────────────────────────────────

/// Extract a `/dev/pts/N` path from a cloud-hypervisor `vm.info` JSON body.
///
/// cloud-hypervisor reports the serial PTY as:
///   `"serial": { "file": "/dev/pts/N", "mode": "Pty", ... }`
fn extract_pty_path(body: &str) -> Option<PathBuf> {
    let pos = body.find("/dev/pts/")?;
    let rest = &body[pos..];
    let end = rest
        .find(|c: char| c == '"' || c == ',' || c == '}' || c == ' ' || c == '\n')
        .unwrap_or(rest.len());
    let pty = rest[..end].trim();
    if pty.is_empty() { None } else { Some(PathBuf::from(pty)) }
}

fn wait_for_serial_pty(api_socket: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + START_TIMEOUT;

    while !api_socket.exists() {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for cloud-hypervisor API socket to appear".into());
        }
        thread::sleep(Duration::from_millis(50));
    }

    loop {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for cloud-hypervisor serial PTY".into());
        }
        thread::sleep(Duration::from_millis(100));

        let body = match ch_api_get(api_socket, "/api/v1/vm.info") {
            Ok(b) => b,
            Err(_) => continue,
        };

        if let Some(path) = extract_pty_path(&body) {
            return Ok(path);
        }
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
    // ── Locate required binaries ──────────────────────────────────────────────

    let ch_bin = find_binary("cloud-hypervisor").ok_or(
        "cloud-hypervisor not found.\n\
         Install: sudo apt install cloud-hypervisor\n\
         Or see: https://github.com/cloud-hypervisor/cloud-hypervisor/releases",
    )?;

    let virtiofsd_bin = if !directory_shares.is_empty() {
        Some(find_binary("virtiofsd").ok_or(
            "virtiofsd not found.\n\
             Install: sudo apt install virtiofsd\n\
             Or see: https://gitlab.com/virtio-fs/virtiofsd",
        )?)
    } else {
        None
    };

    let firmware = find_efi_firmware().ok_or(
        "EFI firmware not found.\n\
         Install: sudo apt install cloud-hypervisor\n\
         Or: sudo apt install ovmf",
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

    // ── Start virtiofsd for each directory share ──────────────────────────────

    let mut virtiofsd_children: Vec<std::process::Child> = Vec::new();

    if let Some(ref vfsd) = virtiofsd_bin {
        for share in directory_shares {
            let socket_path = tmp_dir.join(format!("{}.sock", share.tag()));
            let child = Command::new(vfsd)
                .args([
                    "--socket-path", &socket_path.to_string_lossy(),
                    "--shared-dir",  &share.host.to_string_lossy(),
                    "--cache", "auto",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("Failed to start virtiofsd: {e}"))?;
            virtiofsd_children.push(child);
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
    }

    struct VirtiofsdGuard(Vec<std::process::Child>);
    impl Drop for VirtiofsdGuard {
        fn drop(&mut self) {
            for child in &mut self.0 { let _ = child.kill(); let _ = child.wait(); }
        }
    }
    let _vfsd_guard = VirtiofsdGuard(virtiofsd_children);

    // ── Build and launch cloud-hypervisor ─────────────────────────────────────

    let api_socket = tmp_dir.join("api.sock");
    let ram_mb = ram_bytes / BYTES_PER_MB;

    let mut ch_cmd = Command::new(&ch_bin);
    ch_cmd.args([
        "--firmware",   &firmware.to_string_lossy(),
        "--disk",       &format!("path={}", disk_path.to_string_lossy()),
        "--memory",     &format!("size={}M", ram_mb),
        "--cpus",       &format!("boot={}", cpu_count),
        "--net",        "tap=,mac=,ip=,mask=",
        "--serial",     "pty",
        "--console",    "off",
        "--api-socket", &api_socket.to_string_lossy(),
    ]);

    for share in directory_shares {
        let socket_path = tmp_dir.join(format!("{}.sock", share.tag()));
        ch_cmd.args([
            "--fs",
            &format!(
                "tag={},socket={},num_queues=1,queue_size=1024",
                share.tag(),
                socket_path.to_string_lossy()
            ),
        ]);
    }

    let mut ch_process = ch_cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start cloud-hypervisor: {e}"))?;

    struct ChGuard(Option<std::process::Child>);
    impl Drop for ChGuard {
        fn drop(&mut self) {
            if let Some(ref mut c) = self.0 { let _ = c.kill(); let _ = c.wait(); }
        }
    }
    let mut ch_guard = ChGuard(None);

    // ── Find the serial PTY ───────────────────────────────────────────────────

    let pty_path = match wait_for_serial_pty(&api_socket) {
        Ok(p) => p,
        Err(e) => { let _ = ch_process.kill(); return Err(e); }
    };
    ch_guard.0 = Some(ch_process);

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
        LoginAction::Expect { text: "login: ".into(), timeout: LOGIN_EXPECT_TIMEOUT },
        Send("root".into()),
        LoginAction::Expect { text: "~#".into(), timeout: LOGIN_EXPECT_TIMEOUT },
        Send("stty sane".into()),
    ];

    // Each virtiofs share is mounted directly at its guest path — no staging needed.
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
        match ch_guard.0.as_mut().unwrap().try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => {
                exit_result = Err(format!("Error waiting for cloud-hypervisor: {e}").into());
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
                let _ = ch_api_put(&api_socket, "/api/v1/vm.shutdown", "");
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {}
        }

        thread::sleep(Duration::from_millis(200));
    }

    let _ = login_thread.join();
    io_ctx.shutdown();

    if let Some(ref mut ch) = ch_guard.0 {
        let _ = ch.wait();
    }
    ch_guard.0 = None; // prevent double-kill in Drop

    exit_result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pty_path_from_typical_api_response() {
        let body = r#"{"config":{"serial":{"file":"/dev/pts/3","mode":"Pty"}},"state":"Running"}"#;
        assert_eq!(extract_pty_path(body), Some(PathBuf::from("/dev/pts/3")));
    }

    #[test]
    fn extract_pty_path_higher_numbered_pts() {
        let body = r#"{"serial":{"file":"/dev/pts/42","mode":"Pty"}}"#;
        assert_eq!(extract_pty_path(body), Some(PathBuf::from("/dev/pts/42")));
    }

    #[test]
    fn extract_pty_path_missing_returns_none() {
        assert_eq!(extract_pty_path(r#"{"state":"Running"}"#), None);
    }

    #[test]
    fn extract_pty_path_stops_at_quote() {
        let body = r#""/dev/pts/7","other":"stuff""#;
        assert_eq!(extract_pty_path(body), Some(PathBuf::from("/dev/pts/7")));
    }
}
