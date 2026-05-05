use std::{
    env,
    ffi::{CString, OsString},
    fs,
    io::{self, Write},
    os::{
        fd::RawFd,
        unix::{
            io::{AsRawFd, IntoRawFd, OwnedFd},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};
use std::process::Child;
use std::sync::atomic::{AtomicI32, Ordering};
use block2::RcBlock;
use dispatch2::DispatchQueue;
use lexopt::prelude::*;
use objc2::{AnyThread, rc::Retained, runtime::ProtocolObject};
use objc2_foundation::*;
use objc2_virtualization::*;
use single_instance::SingleInstance;

mod networking;
use networking::*;
const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
const DEBIAN_COMPRESSED_SHA: &str = "6ab9be9e6834adc975268367f2f0235251671184345c34ee13031749fdfbf66fe4c3aafd949a2d98550426090e9ac645e79009c51eb0eefc984c15786570bb38";
const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 280901576;
const SHARED_DIRECTORIES_TAG: &str = "shared";

const BYTES_PER_MB: u64 = 1024 * 1024;
const DEFAULT_CPU_COUNT: usize = 2;
const DEFAULT_RAM_MB: u64 = 2048;
const DEFAULT_RAM_BYTES: u64 = DEFAULT_RAM_MB * BYTES_PER_MB;
const START_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_EXPECT_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_EXPECT_TIMEOUT: Duration = Duration::from_secs(120);
const PROVISION_SCRIPT: &str = include_str!("provision.sh");
const BASH_LOGOUT_SCRIPT: &str = include_str!("bash_logout.sh");

#[derive(Clone)]
enum LoginAction {
    Expect {
        text: String,
        timeout: Duration,
    },
    Send(String),
    Script {
        path: PathBuf,
        index: usize,
    },
}
use LoginAction::*;

#[derive(Clone)]
struct DirectoryShare {
    host: PathBuf,
    guest: PathBuf,
    read_only: bool,
}

impl DirectoryShare {
    fn new(
        host: PathBuf,
        mut guest: PathBuf,
        read_only: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !host.exists() {
            return Err(format!("Host path does not exist: {}", host.display()).into());
        }
        if !guest.is_absolute() {
            guest = PathBuf::from("/root").join(guest);
        }
        Ok(Self {
            host,
            guest,
            read_only,
        })
    }

    fn from_mount_spec(spec: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!("Invalid mount spec: {spec}").into());
        }
        let host = PathBuf::from(parts[0]);
        let guest = PathBuf::from(parts[1]);
        let read_only = if parts.len() == 3 {
            match parts[2] {
                "read-only" => true,
                "read-write" => false,
                _ => {
                    return Err(format!(
                        "Invalid mount mode '{}'; expected read-only or read-write",
                        parts[2]
                    )
                    .into());
                }
            }
        } else {
            false
        };
        DirectoryShare::new(host, guest, read_only)
    }

    fn tag(&self) -> String {
        let path_str = self.host.to_string_lossy();
        let hash = path_str
            .bytes()
            .fold(5381u64, |h, b| h.wrapping_mul(33).wrapping_add(b as u64));
        let base_name = self
            .host
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or("share".into());
        format!("{}_{:016x}", base_name, hash)
    }
}

fn attach_console(
    project_root: PathBuf,
    login_actions: Vec<LoginAction>,
    clear: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let instance_dir = project_root.join(".vibe");
    // eprintln!("Attaching to console ...");
    // hvc0.sock is the main daemon console
    // The others are extra getty sessions (hvc2/4/6)
    const SOCK_NAMES: [&str; 4] = ["hvc0.sock", "hvc2.sock", "hvc4.sock", "hvc6.sock"];

    let mut chosen_stream: Option<UnixStream> = None;
    let mut chosen_resize_path: Option<PathBuf> = None;

    let mut _lck: Option<SingleInstance> = None;

    for name in &SOCK_NAMES {
        let lock_path = instance_dir.join(name.replace(".sock", ".lock"));
        let lock_path_str = lock_path.to_str().unwrap();
        let lock = SingleInstance::new(lock_path_str)?;
        if !lock.is_single() {
            continue;
        }
        _lck = Some(lock);
        let path = instance_dir.join(name);
        let Ok(s) = UnixStream::connect(&path) else {
            return Err(format!("Could not connect to {}", path.display()).into());
        };
        eprintln!("Connected to {}", path.display());

        let resize_name = name.replace(".sock", "-resize.sock");
        chosen_resize_path = Some(instance_dir.join(resize_name));
        chosen_stream = Some(s);
        break;
    }

    let stream = chosen_stream.ok_or(
        "All console slots are busy. Try again when a session exits.",
    )?;
    let stream_fd = stream.as_raw_fd();
    let _stream = stream;

    // Send terminal resize events over the matching resize socket.
    let resize_socket_path = chosen_resize_path.ok_or("Resize path not given?")?;
    if !resize_socket_path.exists() {
        return Err(format!("Resize socket {} does not exist", resize_socket_path.display()).into());
    }
    if let Ok(mut resize_stream) = UnixStream::connect(&resize_socket_path) {
        eprintln!("Connected to resize {}", resize_socket_path.display());
        let _ = thread::spawn(move || {
            loop {
                if let Some((rows, cols)) = terminal_size(libc::STDOUT_FILENO) {
                    let msg = format!("{rows} {cols}\n");
                    if resize_stream.write_all(msg.as_bytes()).is_err() {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
    } else {
        return Err(format!("Could not connect to resize socket {}", resize_socket_path.display()).into());
    }

    let mut all_actions: Vec<LoginAction> =
        vec![
            Send("".to_string()),
            Expect {
                text: "~#".to_string(),
                timeout: LOGIN_EXPECT_TIMEOUT,
            },
        ];

    let abspath = env::current_dir()?
        .into_os_string()
        .to_string_lossy()
        .into_owned();
    all_actions.push(Send(format!(" cd {abspath}")));

    // if clear {
    //     all_actions.push(Send(" clear && cat /etc/vibe_motd".to_string()));
    // } else {
    //     all_actions.push(Send(" cat /etc/vibe_motd".to_string()));
    // }

    all_actions.extend(login_actions);

    let mut buf = [0u8; 4096];
    // Seed with any bytes already read during the busy-check poll.
    let mut output_buf = String::new();
    let mut raw_guard: Option<RawModeGuard> = None;

    // Helper: poll both fds, forward stdin→socket, accumulate socket→stdout into output_buf.
    // Returns false if the socket closed.
    macro_rules! poll_and_forward {
        ($timeout_ms:expr) => {{
            let mut fds = [
                libc::pollfd {
                    fd: libc::STDIN_FILENO,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stream_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, $timeout_ms) };
            if ret < 0 {
                false
            } else {
                if fds[0].revents & libc::POLLIN != 0 {
                    let n = unsafe {
                        libc::read(libc::STDIN_FILENO, buf.as_mut_ptr() as *mut _, buf.len())
                    };
                    if n > 0 {
                        unsafe {
                            libc::write(stream_fd, buf.as_ptr() as *const _, n as usize);
                        }
                    }
                }
                if fds[1].revents & libc::POLLIN != 0 {
                    let n = unsafe {
                        libc::read(stream_fd, buf.as_mut_ptr() as *mut _, buf.len())
                    };
                    if n <= 0 {
                        eprintln!("poll and forward exiting!");
                        return Ok(());
                    }
                    let data = &buf[..n as usize];
                    if raw_guard.is_none() {
                        raw_guard = enable_raw_mode(libc::STDIN_FILENO).ok();
                    }
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout.write_all(data);
                    let _ = stdout.flush();
                    output_buf.push_str(&String::from_utf8_lossy(data));
                }
                true
            }
        }};
    }

    for action in all_actions {
        eprintln!("login action ...");
        match action {
            Expect { text, timeout } => {
                eprintln!("login action expect ...");
                let deadline = Instant::now() + timeout;
                loop {
                    if let Some((_, rest)) = output_buf.split_once(text.as_str()) {
                        output_buf = rest.to_string();
                        break;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        eprintln!("login action expect ... Timeout!");
                        return Err(format!("Timeout waiting for '{text}'").into());
                    }
                    poll_and_forward!(1);
                }
            }
            Send(text) => {
                let mut bytes = text.into_bytes();
                bytes.push(b'\n');
                unsafe { libc::write(stream_fd, bytes.as_ptr() as *const _, bytes.len()) };
            }
            Script { path, index } => {
                let command = script_command_from_path(&path, index)?;
                let mut bytes = command.into_bytes();
                bytes.push(b'\n');
                unsafe { libc::write(stream_fd, bytes.as_ptr() as *const _, bytes.len()) };
            }
        }
    }

    eprintln!("login actions done");

    // Interactive loop: bidirectional proxy using poll_with_wakeup in two threads.
    let (wakeup_read, wakeup_write) = create_pipe();
    let raw_guard = Arc::new(Mutex::new(raw_guard));

    let stdin_thread = thread::spawn({
        let wakeup_read = wakeup_read.try_clone().unwrap();
        let raw_guard = raw_guard.clone();
        move || {
            let mut buf = [0u8; 4096];
            loop {
                match poll_with_wakeup(libc::STDIN_FILENO, wakeup_read.as_raw_fd(), &mut buf) {
                    PollResult::Shutdown | PollResult::Error => break,
                    PollResult::Spurious => continue,
                    PollResult::Ready(bytes) => {
                        if raw_guard.lock().unwrap().is_none() {
                            continue;
                        }
                        unsafe { libc::write(stream_fd, bytes.as_ptr() as *const _, bytes.len()); }
                    }
                }
            }
        }
    });

    let socket_thread = thread::spawn({
        let raw_guard = raw_guard.clone();
        move || {
            let mut stdout = std::io::stdout().lock();
            let mut buf = [0u8; 4096];
            loop {
                match poll_with_wakeup(stream_fd, wakeup_read.as_raw_fd(), &mut buf) {
                    PollResult::Shutdown => {
                        eprintln!("attach_console socket thread: PollResult::Shutdown");
                        break;
                    }
                    PollResult::Error => {
                        eprintln!("attach_console socket thread: PollResult::Error");
                        break;
                    }
                    PollResult::Spurious => continue,
                    PollResult::Ready(bytes) => {
                        {
                            let mut guard = raw_guard.lock().unwrap();
                            if guard.is_none() {
                                *guard = enable_raw_mode(libc::STDIN_FILENO).ok();
                            }
                        }
                        let _ = stdout.write_all(bytes);
                        let _ = stdout.flush();
                    }
                }
            }
        }
    });

    eprintln!("joining socket thread...!");
    socket_thread.join().ok();
    eprintln!("socket_thread exited!");
    unsafe { libc::write(wakeup_write.as_raw_fd(), [0u8].as_ptr() as *const _, 1) };
    stdin_thread.join().ok();

    Ok(())
}

fn spawn_console_socket_proxy(connected_clients: Arc<AtomicI32>,
                              hvc_out: OwnedFd,
                              hvc_in: OwnedFd,
                              disconnect_read: OwnedFd,
                              done_tx: Sender<Result<(), String>>,
                              socket_path: PathBuf) {
    // Bind synchronously so the socket file exists as soon as this function returns.
    let _ = fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[console] Failed to bind socket {}: {e}", socket_path.display());
            return;
        }
    };
    let _ = thread::spawn(move || {
        let hvc_out_fd = hvc_out.as_raw_fd();
        let hvc_in_fd = hvc_in.as_raw_fd();
        let _hvc_out = hvc_out;
        let _hvc_in = hvc_in;

        let disconnect_read_fd = disconnect_read.as_raw_fd();
        loop {
            // Blocking accept: wait for the next client.
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };

            connected_clients.fetch_add(1, Ordering::SeqCst);

            let client_fd = stream.as_raw_fd();
            let _stream = stream;
            let mut buf = [0u8; 4096];
            let mut shutdown_wait: bool = false;

            'client: loop {
                let mut fds = [
                    libc::pollfd {
                        fd: hvc_out_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: client_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: disconnect_read_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];

                let ret = unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) };
                if ret < 0 {
                    // client disconnected
                    let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                    eprintln!("number of connected clients: {new_val}");
                    break 'client;
                }

                // data from /dev/hvcN
                if fds[0].revents & libc::POLLIN != 0 {
                    let n =
                        unsafe { libc::read(hvc_out_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if n <= 0 {
                        eprintln!("vm console gone");
                        return; // VM console gone
                    }
                    // Session-end sentinel written by the guest wrapper script after login
                    // exits. Close the client socket so attach_console exits via normal
                    // socket-close detection. OSC 9999 won't appear in real terminal output.
                    // const SENTINEL: &[u8] = b"\x1b]9999\x07";
                    // const SENTINEL_SHUTDOWN: &[u8] = b"\x1b]9998\x07";
                    // const DSR: &[u8] = b"\x1b[6n";
                    // if data.windows(SENTINEL.len()).any(|w| w == SENTINEL) {
                        // means disconnect
                        // let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        // eprintln!("number of connected clients: {new_val}");
                        // break 'client;
                    // }
                    // if data.windows(SENTINEL_SHUTDOWN.len()).any(|w| w == SENTINEL_SHUTDOWN) {
                        // don't push more data to the client once we know that the VM is shutting down
                        // shutdown_wait = true;
                        // let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        // eprintln!("number of connected clients: {new_val}");
                    // }
                    // Strip ESC[6n (DSR cursor-position query) — prevents spurious CPR
                    // responses from leaking onto the client terminal.
                    if unsafe {
                        libc::write(client_fd, buf.as_ptr() as *const _, n as usize)
                    } < 0
                    {
                        let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        eprintln!("number of connected clients: {new_val}");
                        break 'client; // client disconnected
                    }
                }

                if fds[1].revents & libc::POLLIN != 0 {
                    let n = unsafe { libc::read(client_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if n <= 0 {
                        let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        break 'client; // client disconnected
                    }
                    if unsafe {
                        libc::write(hvc_in_fd, buf.as_ptr() as *const _, n as usize)
                    } < 0
                    {
                        let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        eprintln!("number of connected clients: {new_val}");
                        return; // VM console gone
                    }
                }

                if fds[2].revents & libc::POLLIN != 0 {
                    let n = unsafe { libc::read(disconnect_read_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if n <= 0 {
                        let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        break 'client;
                    } else {
                        let old_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                        if old_val == 1 {
                            let msg = "VM shutting down...";
                            eprintln!("VM shutting down");
                            unsafe { libc::write(client_fd, msg.as_ptr() as *const _, msg.len()) };
                            let _ = done_tx.send(Ok(()));
                        }
                        break 'client;
                    }
                }

                // if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                //     let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                //     eprintln!("number of connected clients: {new_val}");
                //     return;
                // }
                // if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                //     let new_val = connected_clients.fetch_sub(1, Ordering::SeqCst);
                //     eprintln!("number of connected clients: {new_val}");
                //     break 'client;
                // }
            }
        }
    });
}

fn spawn_console_resize_proxy(hvc_in: OwnedFd, socket_path: PathBuf) {
    // Bind synchronously so the socket file exists as soon as this function returns.
    let _ = fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[console resize] Failed to bind socket {}: {e}", socket_path.display());
            return;
        }
    };
    let _ = thread::spawn(move || {
        let hvc_in_fd = hvc_in.as_raw_fd();
        let _hvc_in = hvc_in;

        loop {
            let (stream, _) = match listener.accept() {
                Ok(s) => s,
                Err(_) => break,
            };

            let client_fd = stream.as_raw_fd();
            let _stream = stream;
            let mut buf = [0u8; 64];

            loop {
                let n = unsafe { libc::read(client_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    break; // client disconnected, wait for next
                }
                if unsafe { libc::write(hvc_in_fd, buf.as_ptr() as *const _, n as usize) } < 0 {
                    return; // VM gone
                }
            }
        }
    });
}

/// Try to acquire an exclusive advisory lock on `instance_dir/instance.lock`.
///
/// The file is opened **without** `O_CLOEXEC` so that the daemon process
/// inherits the file descriptor across the `exec` call.  As long as the
/// daemon keeps the inherited FD open the lock is held, preventing a second
/// `vibe` from starting another VM in the same directory.
///
/// Returns `Some(raw_fd)` if the lock was acquired, `None` if another process
/// already holds it (VM is running).
fn try_acquire_instance_lock(instance_dir: &Path) -> io::Result<Option<libc::c_int>> {
    let lock_path = instance_dir.join("instance.lock");
    // Create the file if it doesn't exist (ignoring errors — open below will fail if needed).
    let _ = fs::OpenOptions::new().write(true).create(true).open(&lock_path);

    let c_path = CString::new(lock_path.to_str().ok_or_else(|| {
        io::Error::other("instance.lock path is not valid UTF-8")
    })?)
    .map_err(io::Error::other)?;

    // Open without O_CLOEXEC so the FD survives exec in the daemon child.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_WRONLY, 0) };
    if fd < 0 {
        eprintln!("Could not open instance.lock");
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        // eprintln!("Acquired instance.lock");
        Ok(Some(fd)) // caller must keep fd open; do NOT wrap in OwnedFd
    } else {
        unsafe { libc::close(fd) };
        // eprintln!("Lock already held");
        Ok(None)
    }
}

fn run_daemon_vm(args: CliArgs, instance_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let home = env::var("HOME").map(PathBuf::from)?;
    let cache_home = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".cache"));
    let cache_dir = cache_home.join("vibe");
    let project_root = env::current_dir()?;

    let vmnet_helper_path = cache_dir.join("vmnet-helper");
    let prepare_network_backend = || args.network_mode.prepare(&vmnet_helper_path).unwrap();

    let mut login_actions = Vec::new();
    let mut directory_shares = Vec::new();

    if !args.no_default_mounts {
        let abspath = env::current_dir()?
            .into_os_string()
            .to_string_lossy()
            .into_owned();
        login_actions.push(Send(format!(" cd {abspath}")));

        // Discourage read/write of project dir subfolders within the VM.
        // Note that this isn't secure, since the VM runs as root and could unmount this.
        // I couldn't find an alternative way to do this --- the MacOS sandbox doesn't apply to the Apple Virtualization system =(
        for subfolder in [".git", ".vibe"] {
            if project_root.join(subfolder).exists() {
                login_actions.push(Send(format!(r" mount -t tmpfs tmpfs {}", subfolder)))
            }
        }

        directory_shares.push(
            DirectoryShare::new(project_root, env::current_dir()?, false)
                .expect("Project directory must exist"),
        );

        for subfolder in [".venv", "node_modules"] {
            if env::current_dir()?.join(subfolder).exists() {
                // println!(r"creating mapping {}", subfolder);
                fs::create_dir_all(env::current_dir()?.join(".vibe").join(subfolder))
                    .expect("Could not create .vibe/ subfolder");
                directory_shares.push(
                    DirectoryShare::new(
                        env::current_dir()?.join(".vibe").join(subfolder),
                        env::current_dir()?.join(subfolder),
                        false,
                    )
                        .expect("Project directory must exist"),
                );
            }
        }

        let guest_mise_cache = cache_dir.join(".guest-mise-cache");
        let mise_directory_share =
            DirectoryShare::new(guest_mise_cache, "/root/.local/share/mise".into(), false)?;
        directory_shares.push(mise_directory_share);

        // Add default shares, if they exist
        for share in [
            DirectoryShare::new(home.join(".m2"), "/root/.m2".into(), false),
            DirectoryShare::new(
                home.join(".cargo/registry"),
                "/root/.cargo/registry".into(),
                false,
            ),
            DirectoryShare::new(home.join(".codex"), "/root/.codex".into(), false),
            DirectoryShare::new(home.join(".claude"), "/root/.claude".into(), false),
            DirectoryShare::new(home.join(".gemini"), "/root/.gemini".into(), false),
        ]
            .into_iter()
            .flatten()
        {
            directory_shares.push(share)
        }
        // Bind-mount linux ripgrep over shared macos binary to ensure compatibility
        login_actions.push(Send(
            " if [ -f /root/.gemini/tmp/bin/rg ] && [ -f /usr/bin/rg ]; then mount --bind /usr/bin/rg /root/.gemini/tmp/bin/rg; fi"
                .to_string()
        ));
    }

    for spec in &args.mounts {
        directory_shares.push(DirectoryShare::from_mount_spec(spec)?);
    }

    // Enable bash history
    login_actions.push(Send(" export HISTFILE=/root/.bash_history".to_string()));

    if let Some(motd_action) = motd_login_action(&directory_shares) {
        login_actions.push(motd_action);
    }

    // if the vibe client attaching aborts _before_ actually logging in,
    // we still want to shutdown the VM:
    // const S: &str = " bash -c '(while true; do sleep 3; if [[ \"$(who | wc -l | tr -d \" \")\" == \"0\" ]]; then echo \"VM powering off...\"; systemctl poweroff; fi; done) 2>&1 &'";
    // login_actions.push(Send(S.to_string()));

    // temporarily disable automatic poweroff when logging out
    login_actions.push(Send(" export VIBE_POWEROFF=false".to_string()));

    login_actions.push(Send(" exit".to_string()));
    login_actions.push(Expect {
        text: "login:".to_string(),
        timeout: LOGIN_EXPECT_TIMEOUT,
    });

    let instance_raw = instance_dir.join("instance.raw");

    let disk_path = if let Some(path) = args.disk {
        if !path.exists() {
            return Err(format!("Disk image does not exist: {}", path.display()).into());
        }
        path
    } else {
        instance_raw
    };

    run_vm(
        &disk_path,
        &login_actions,
        &directory_shares[..],
        prepare_network_backend,
        args.cpu_count,
        args.ram_bytes,
        Some(instance_dir.join("console.sock")),
    )
}

fn provision_vm(args: CliArgs, instance_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let home = env::var("HOME").map(PathBuf::from)?;
    let cache_home = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".cache"));
    let cache_dir = cache_home.join("vibe");

    let vmnet_helper_path = cache_dir.join("vmnet-helper");
    let prepare_network_backend = || args.network_mode.prepare(&vmnet_helper_path).unwrap();

    let guest_mise_cache = cache_dir.join(".guest-mise-cache");

    let basename_compressed = DEBIAN_COMPRESSED_DISK_URL.rsplit('/').next().unwrap();
    let base_compressed = cache_dir.join(basename_compressed);
    let base_raw = cache_dir.join(format!(
        "{}.raw",
        basename_compressed.trim_end_matches(".tar.xz")
    ));

    let default_raw = cache_dir.join("default.raw");
    let instance_raw = instance_dir.join("instance.raw");

    // Prepare system-wide directories
    fs::create_dir_all(&cache_dir)?;
    fs::create_dir_all(&guest_mise_cache)?;

    let mise_directory_share =
        DirectoryShare::new(guest_mise_cache, "/root/.local/share/mise".into(), false)?;

    let _disk_path = if let Some(path) = args.disk {
        if !path.exists() {
            return Err(format!("Disk image does not exist: {}", path.display()).into());
        }
        path
    } else {
        ensure_default_image(
            &base_raw,
            &base_compressed,
            &default_raw,
            std::slice::from_ref(&mise_directory_share),
            prepare_network_backend,
        )?;
        ensure_instance_disk(&instance_raw, &default_raw)?;

        instance_raw
    };
    Ok(())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_signed();

    let args = parse_cli()?;

    if args.version {
        println!("Vibe");
        println!("https://github.com/lynaghk/vibe/");
        println!("Git SHA: {}", env!("GIT_SHA"));
        println!("Built: {}", env!("BUILD_DATE"));
        std::process::exit(0);
    }

    if args.help {
        println!(
            "Vibe is a quick way to spin up a Linux virtual machine on Mac to sandbox LLM agents.

vibe [OPTIONS] [disk-image.raw]

Options

  --help                                                    Print this help message.
  --version                                                 Print the version (commit SHA and build date).
  --no-default-mounts                                       Disable all default mounts, including .git and .vibe project subfolder masking.
  --mount host-path:guest-path[:read-only | :read-write]    Mount `host-path` inside VM at `guest-path`.
                                                            Defaults to read-write.
                                                            Errors if host-path does not exist.
  --network [nat | vznat | <bridge interface>]              Guest networking mode (default `nat`).
                                                            Providing an interface (e.g., `en0`) exposes the VM on that interface.
                                                            This is just like plugging it in, so it'll get its own IP address, be able to accept incoming connections, etc.

  --cpus <count>                                            Number of virtual CPUs (default 2).
  --ram <megabytes>                                         RAM size in megabytes (default 2048).
  --script <path/to/script.sh>                              Run script in VM.
  --send <some-command>                                     Type `some-command` followed by newline into the VM.
  --expect <string> [timeout-seconds]                       Wait for `string` to appear in console output before executing next `--script` or `--send`.
                                                            If `string` does not appear within timeout (default 30 seconds), shutdown VM with error.
"
        );
        std::process::exit(0);
    }

    let project_root = env::current_dir()?;
    let instance_dir = project_root.join(".vibe");

    if !instance_dir.exists() {
        fs::create_dir_all(project_root.join(".vibe")).expect("Could not create .vibe folder");
    }

    // If we're the daemon child we skip locking — the inherited FD already holds it.
    // Otherwise, try to acquire the instance lock.  Failure means a VM is already
    // running in this directory; just attach to its console.
    let _lock_fd: Option<libc::c_int> = if args.daemon {
        None
    } else {
        match try_acquire_instance_lock(&instance_dir)
            .map_err(|e| format!("Could not open instance lock: {e}"))?
        {
            None => {
                // eprintln!("VM is running / lock is held...");
                return attach_console(project_root, args.login_actions, args.clear)
            },
            Some(fd) => Some(fd),
            // fd is intentionally leaked here: it must stay open so the daemon
            // inherits it across exec and continues to hold the lock.
        }
    };

    if !args.daemon {
        // We are the initial client.
        let hvc0_sock = instance_dir.join("hvc0.sock");
        if !args.attach {
            // Sanity check that no VM is running:
            if hvc0_sock.exists() {
                return Err("hvc0.sock exists".into());
            }
        }

        // Provision the VM if needed.
        provision_vm(args, project_root.join(".vibe"))?;

        // Spawn the daemon by re-execing this binary with --_daemon prepended to
        // the original arguments.  Using Command::spawn (fork+exec) rather than a
        // bare fork() is required on macOS: a raw fork leaves the child with a
        // corrupted ObjC/GCD runtime, causing the Virtualization framework to fail
        // with "Internal Virtualization error".  After exec the child starts fresh.
        //
        // The instance-lock file descriptor was opened without O_CLOEXEC, so the
        // daemon inherits it across the exec call and holds the lock for its entire
        // lifetime — preventing a second `vibe` from starting a second VM.
        // let log_file = fs::OpenOptions::new()
        //     .write(true)
        //     .create(true)
        //     .truncate(true)
        //     .open(instance_dir.join("daemon.log"))?;
        // eprintln!("Spawning VM daemon...");
        let mut child: Option<Child> = None;
        if !parse_cli()?.attach {
            child = Some(Command::new(env::current_exe()?)
                .arg("--_daemon")
                .args(env::args_os().skip(1))
                // .stdin(Stdio::null())
                // .stdout(log_file.try_clone()?)
                // .stderr(log_file)
                .spawn()?);
        }

        let deadline = Instant::now() + Duration::from_secs(300); // 5 minute timeout
        while !hvc0_sock.exists() {
            if let Some(c) = &mut child {
                match c.try_wait() {
                    Ok(Some(status)) => {
                        return Err(format!("Daemon exited with {status}").into());
                    }
                    Ok(None) => { /* still running */ }
                    Err(e) => { return Err(e.into()); }
                }
            }
            if Instant::now() >= deadline {
                return Err("client: Timed out waiting for VM daemon to finish booting".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        attach_console(project_root, parse_cli()?.login_actions, parse_cli()?.clear)
    } else {
        // We are the daemon process.
        // At this point the VM is provisioned. The VM is now powered off.
        // Run the VM and keep it alive.
        // The instance lock is already held via the inherited file descriptor.
        run_daemon_vm(args, instance_dir)
    }
}

struct CliArgs {
    disk: Option<PathBuf>,
    version: bool,
    help: bool,
    daemon: bool,
    attach: bool,
    clear: bool,
    no_default_mounts: bool,
    mounts: Vec<String>,
    login_actions: Vec<LoginAction>,
    network_mode: NetworkMode,
    cpu_count: usize,
    ram_bytes: u64,
}

fn parse_cli() -> Result<CliArgs, Box<dyn std::error::Error>> {
    fn os_to_string(value: OsString, flag: &str) -> Result<String, Box<dyn std::error::Error>> {
        value
            .into_string()
            .map_err(|_| format!("{flag} expects valid UTF-8").into())
    }

    let mut parser = lexopt::Parser::from_env();
    let mut disk = None;
    let mut version = false;
    let mut help = false;
    let mut daemon = false;
    let mut clear = true;
    let mut attach = false;
    let mut no_default_mounts = false;
    let mut mounts = Vec::new();
    let mut login_actions = Vec::new();
    let mut network_mode = NetworkMode::VmnetNat;
    let mut script_index = 0;
    let mut cpu_count = DEFAULT_CPU_COUNT;
    let mut ram_bytes = DEFAULT_RAM_BYTES;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("version") => version = true,
            Long("help") | Short('h') => help = true,
            Long("_daemon") => daemon = true,
            Long("_attach") => attach = true,
            Long("no-clear") => clear = false,
            Long("no-default-mounts") => no_default_mounts = true,
            Long("cpus") => {
                let value = os_to_string(parser.value()?, "--cpus")?.parse()?;
                if value == 0 {
                    return Err("--cpus must be >= 1".into());
                }
                cpu_count = value;
            }
            Long("ram") => {
                let value: u64 = os_to_string(parser.value()?, "--ram")?.parse()?;
                if value == 0 {
                    return Err("--ram must be >= 1".into());
                }
                ram_bytes = value * BYTES_PER_MB;
            }
            Long("mount") => {
                mounts.push(os_to_string(parser.value()?, "--mount")?);
            }
            Long("network") => {
                let value = os_to_string(parser.value()?, "--network")?;
                network_mode = NetworkMode::parse(&value);
            }
            Long("script") => {
                login_actions.push(Script {
                    path: os_to_string(parser.value()?, "--script")?.into(),
                    index: script_index,
                });
                script_index += 1;
            }
            Long("send") => {
                login_actions.push(Send(os_to_string(parser.value()?, "--send")?));
            }
            Long("expect") => {
                let text = os_to_string(parser.value()?, "--expect")?;
                let timeout = match parser.optional_value() {
                    Some(value) => Duration::from_secs(os_to_string(value, "--expect")?.parse()?),
                    None => DEFAULT_EXPECT_TIMEOUT,
                };
                login_actions.push(Expect { text, timeout });
            }
            Value(value) => {
                if disk.is_some() {
                    return Err("Only one disk path may be provided".into());
                }
                disk = Some(PathBuf::from(value));
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    Ok(CliArgs {
        disk,
        version,
        help,
        daemon,
        attach,
        clear,
        no_default_mounts,
        mounts,
        login_actions,
        network_mode,
        cpu_count,
        ram_bytes,
    })
}

fn script_command_from_path(
    path: &Path,
    index: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let script = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read script {}: {err}", path.display()))?;
    let label = format!("{}_{}", index, path.file_name().unwrap().display());
    script_command_from_content(&label, &script)
}

fn script_command_from_content(
    label: &str,
    script: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let marker = "VIBE_SCRIPT_EOF";
    let guest_dir = "/tmp/vibe-scripts";
    let guest_path = format!("{guest_dir}/{label}.sh");
    let command = format!(
        " mkdir -p {guest_dir}\ncat >{guest_path} <<'{marker}'\n{script}\n{marker}\nchmod +x {guest_path}\n {guest_path}"
    );
    if script.contains(marker) {
        return Err(
            format!("Script '{label}' contains marker '{marker}', cannot safely upload").into(),
        );
    }
    Ok(command)
}

fn motd_login_action(directory_shares: &[DirectoryShare]) -> Option<LoginAction> {
    if directory_shares.is_empty() {
        return Some(Send(" clear".into()));
    }

    let host_header = "Host";
    let guest_header = "Guest";
    let mode_header = "Mode";
    let mut host_width = host_header.len();
    let mut guest_width = guest_header.len();
    let mut mode_width = mode_header.len();
    let mut rows = Vec::with_capacity(directory_shares.len());

    for share in directory_shares {
        let host = share.host.to_string_lossy().into_owned();
        let guest = share.guest.to_string_lossy().into_owned();
        let mode = if share.read_only {
            "read-only"
        } else {
            "read-write"
        }
        .to_string();
        host_width = host_width.max(host.len());
        guest_width = guest_width.max(guest.len());
        mode_width = mode_width.max(mode.len());
        rows.push((host, guest, mode));
    }

    let mut output = String::new();
    output.push_str(
        "
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░   
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
   ░▒▓██▓▒░  ░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░

",
    );
    output.push_str(&format!(
        "{host_header:<host_width$}  {guest_header:<guest_width$}  {mode_header}\n",
        host_width = host_width
    ));
    output.push_str(&format!(
        "{:-<host_width$}  {:-<guest_width$}  {:-<mode_width$}\n",
        "",
        "",
        "",
        host_width = host_width,
        guest_width = guest_width,
        mode_width = mode_width
    ));

    for (host, guest, mode) in rows {
        output.push_str(&format!(
            "{host:<host_width$}  {guest:<guest_width$}  {mode}\n"
        ));
    }

    let command = format!(" cat <<'VIBE_MOTD' > /etc/vibe_motd\n{output}\nVIBE_MOTD\n");
    Some(Send(command))
}

#[derive(PartialEq, Eq)]
enum WaitResult {
    Timeout,
    Found,
}

pub enum VmInput {
    Bytes(Vec<u8>),
    Shutdown,
}

enum VmOutput {
    LoginActionTimeout { action: String, timeout: Duration },
}

#[derive(Default)]
pub struct OutputMonitor {
    buffer: Mutex<String>,
    condvar: Condvar,
}

impl OutputMonitor {
    fn push(&self, bytes: &[u8]) {
        self.buffer
            .lock()
            .unwrap()
            .push_str(&String::from_utf8_lossy(bytes));
        self.condvar.notify_all();
    }

    fn wait_for(&self, needle: &str, timeout: Duration) -> WaitResult {
        let (_unused, timeout_result) = self
            .condvar
            .wait_timeout_while(self.buffer.lock().unwrap(), timeout, |buf| {
                if let Some((_, remaining)) = buf.split_once(needle) {
                    *buf = remaining.to_string();
                    false
                } else {
                    true
                }
            })
            .unwrap();

        if timeout_result.timed_out() {
            WaitResult::Timeout
        } else {
            WaitResult::Found
        }
    }

}

fn ensure_base_image(
    base_raw: &Path,
    base_compressed: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if base_raw.exists() {
        return Ok(());
    }

    if !base_compressed.exists()
        || std::fs::metadata(base_compressed).map(|m| m.len())? < DEBIAN_COMPRESSED_SIZE_BYTES
    {
        println!("Downloading base image...");
        let status = Command::new("curl")
            .args([
                "--continue-at",
                "-",
                "--compressed",
                "--location",
                "--fail",
                "-o",
                &base_compressed.to_string_lossy(),
                DEBIAN_COMPRESSED_DISK_URL,
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to download base image".into());
        }
    }

    // Check SHA
    {
        let input = format!("{}  {}\n", DEBIAN_COMPRESSED_SHA, base_compressed.display());

        let mut child = Command::new("/usr/bin/shasum")
            .args(["--algorithm", "512", "--check"])
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to spawn shasum");

        child
            .stdin
            .take()
            .expect("failed to open stdin")
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");

        let status = child.wait().expect("failed to wait on child");
        if !status.success() {
            return Err(format!("SHA validation failed for {DEBIAN_COMPRESSED_DISK_URL}").into());
        }
    }

    println!("Decompressing base image...");
    let status = Command::new("tar")
        .args(["-xOf", &base_compressed.to_string_lossy(), "disk.raw"])
        .stdout(std::fs::File::create(base_raw)?)
        .status()?;

    if !status.success() {
        return Err("Failed to decompress base image".into());
    }

    Ok(())
}

fn ensure_default_image(
    base_raw: &Path,
    base_compressed: &Path,
    default_raw: &Path,
    directory_shares: &[DirectoryShare],
    prepare_network_backend: impl Fn() -> PreparedNetworkBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    if default_raw.exists() {
        return Ok(());
    }

    ensure_base_image(base_raw, base_compressed)?;

    println!("Configuring base image...");
    fs::copy(base_raw, default_raw)?;

    fs::OpenOptions::new()
        .write(true)
        .open(default_raw)?
        // resize to 20GiB
        .set_len(20 * 1024 * BYTES_PER_MB)?;

    let provision_command = script_command_from_content("provision.sh", PROVISION_SCRIPT)?;
    run_vm(
        default_raw,
        &[Send(provision_command)],
        directory_shares,
        prepare_network_backend,
        DEFAULT_CPU_COUNT,
        DEFAULT_RAM_BYTES,
        None,
    )?;

    Ok(())
}

fn ensure_instance_disk(
    instance_raw: &Path,
    template_raw: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if instance_raw.exists() {
        return Ok(());
    }

    println!("Creating instance disk from {}...", template_raw.display());
    std::fs::create_dir_all(instance_raw.parent().unwrap())?;
    fs::copy(template_raw, instance_raw)?;
    Ok(())
}

pub struct IoContext {
    pub input_tx: Sender<VmInput>,
    wakeup_write: OwnedFd,
    stdin_thread: thread::JoinHandle<()>,
    mux_thread: thread::JoinHandle<OwnedFd>,
    resize_thread: thread::JoinHandle<OwnedFd>,
    stdout_thread: thread::JoinHandle<OwnedFd>,
}

pub fn create_pipe() -> (OwnedFd, OwnedFd) {
    let (read_stream, write_stream) = UnixStream::pair().expect("Failed to create socket pair");
    (read_stream.into(), write_stream.into())
}

enum PollResult<'a> {
    Ready(&'a [u8]),
    Spurious,
    Shutdown,
    Error,
}

fn poll_with_wakeup<'a>(main_fd: RawFd, wakeup_fd: RawFd, buf: &'a mut [u8]) -> PollResult<'a> {
    let mut fds = [
        libc::pollfd {
            fd: main_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wakeup_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
    if ret <= 0 || fds[1].revents & libc::POLLIN != 0 {
        PollResult::Shutdown
    } else if fds[0].revents & libc::POLLIN != 0 {
        let n = unsafe { libc::read(main_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n < 0 {
            PollResult::Error
        } else if n == 0 {
            PollResult::Shutdown
        } else {
            PollResult::Ready(&buf[..(n as usize)])
        }
    } else {
        PollResult::Spurious
    }
}

pub fn spawn_vm_io(
    output_monitor: Arc<OutputMonitor>,
    vm_output_fd: OwnedFd,
    vm_input_fd: OwnedFd,
    host_write_resize_fd: OwnedFd,
) -> IoContext {
    let (input_tx, input_rx): (Sender<VmInput>, Receiver<VmInput>) = mpsc::channel();

    // raw_guard is set when we've put the user's terminal into raw mode because we've attached stdin/stdout to the VM.
    let raw_guard = Arc::new(Mutex::new(None));

    let (wakeup_read, wakeup_write) = create_pipe();

    // Copies from stdin to the VM; also polls wakeup_read to exit the thread when it's time to shutdown.
    let stdin_thread = thread::spawn({
        let input_tx = input_tx.clone();
        let raw_guard = raw_guard.clone();
        let wakeup_read = wakeup_read.try_clone().unwrap();

        move || {
            let mut buf = [0u8; 1024];
            loop {
                match poll_with_wakeup(libc::STDIN_FILENO, wakeup_read.as_raw_fd(), &mut buf) {
                    PollResult::Shutdown | PollResult::Error => break,
                    PollResult::Spurious => continue,
                    PollResult::Ready(bytes) => {
                        // discard input if the VM hasn't booted up yielded output yet (which triggers us entering raw_mode)
                        if raw_guard.lock().unwrap().is_none() {
                            continue;
                        }
                        if input_tx.send(VmInput::Bytes(bytes.to_vec())).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    // Copies VM output to stdout; also polls wakeup_read to exit the thread when it's time to shutdown.
    let stdout_thread = thread::spawn({
        let raw_guard = raw_guard.clone();
        let wakeup_read = wakeup_read.try_clone().unwrap();

        move || -> OwnedFd {
            let mut stdout = std::io::stdout().lock();
            let mut buf = [0u8; 1024];
            loop {
                match poll_with_wakeup(vm_output_fd.as_raw_fd(), wakeup_read.as_raw_fd(), &mut buf)
                {
                    PollResult::Shutdown | PollResult::Error => break,
                    PollResult::Spurious => continue,
                    PollResult::Ready(bytes) => {
                        // enable raw mode, if we haven't already
                        let mut raw_guard_inner = raw_guard.lock().unwrap();
                        if raw_guard_inner.is_none()
                            && let Ok(guard) = enable_raw_mode(libc::STDIN_FILENO)
                        {
                            *raw_guard_inner = Some(guard);
                        }

                        if let Err(e) = stdout.write_all(bytes) {
                            eprintln!("[stdout_thread] write failed: {e:?}");
                            break;
                        }
                        let _ = stdout.flush();
                        output_monitor.push(bytes);
                    }
                }
            }
            vm_output_fd
        }
    });

    // Copies data from mpsc channel into VM, so vibe can "type" stuff and run scripts.
    let mux_thread = thread::spawn(move || -> OwnedFd {
        let mut vm_writer = std::fs::File::from(vm_input_fd);
        loop {
            match input_rx.recv() {
                Ok(VmInput::Bytes(data)) => {
                    if let Err(e) = vm_writer.write_all(&data) {
                        eprintln!("[mux] write failed: {e:?}");
                        break;
                    }
                }
                Ok(VmInput::Shutdown) | Err(_) => break,
            }
        }
        vm_writer.into()
    });

    let resize_thread = thread::spawn({
        let wakeup_read = wakeup_read.try_clone().unwrap();
        move || -> OwnedFd {
            let mut writer = std::fs::File::from(host_write_resize_fd);
            let resize_fd = writer.as_raw_fd();
            let flags = unsafe { libc::fcntl(resize_fd, libc::F_GETFL) };
            if flags >= 0 {
                let _ = unsafe { libc::fcntl(resize_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }

            loop {
                let mut pollfd = libc::pollfd {
                    fd: wakeup_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let poll_result = unsafe { libc::poll(&mut pollfd, 1, 200) };
                if poll_result > 0 && (pollfd.revents & libc::POLLIN) != 0 {
                    break;
                }

                if let Some((rows, cols)) = terminal_size(libc::STDOUT_FILENO) {
                    let message = format!("{rows} {cols}\n");
                    let bytes = message.as_bytes();
                    match writer.write(bytes) {
                        Ok(n) if n == bytes.len() => {}
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(err) => {
                            eprintln!("[resize_thread] write failed: {err:?}");
                            break;
                        }
                    }
                }
            }
            writer.into()
        }
    });

    IoContext {
        input_tx,
        wakeup_write,
        stdin_thread,
        mux_thread,
        resize_thread,
        stdout_thread,
    }
}

impl IoContext {
    /// Shut down all I/O threads and return the raw hvc0 FDs so they can be
    /// handed off to a socket proxy: `(vm_output_fd, vm_input_fd, resize_fd)`.
    pub fn shutdown(self) -> (OwnedFd, OwnedFd, OwnedFd) {
        let _ = self.input_tx.send(VmInput::Shutdown);
        unsafe { libc::write(self.wakeup_write.as_raw_fd(), b"x".as_ptr() as *const _, 1) };
        let _ = self.stdin_thread.join();
        let vm_out = self.stdout_thread.join().expect("stdout_thread panicked");
        let vm_in = self.mux_thread.join().expect("mux_thread panicked");
        let resize = self.resize_thread.join().expect("resize_thread panicked");
        (vm_out, vm_in, resize)
    }
}

fn create_vm_configuration(
    disk_path: &Path,
    directory_shares: &[DirectoryShare],
    network_backend: &mut PreparedNetworkBackend,
    vm_reads_from_fd: OwnedFd,
    vm_writes_to_fd: OwnedFd,
    vm_resize_reads_from_fd: OwnedFd,
    vm_resize_writes_to_fd: OwnedFd,
    // Each entry adds one hvcN (bidirectional) + one hvcN+1 (resize read-only) serial port.
    extra_consoles: Vec<(OwnedFd, OwnedFd, OwnedFd)>,
    cpu_count: usize,
    ram_bytes: u64,
) -> Result<Retained<VZVirtualMachineConfiguration>, Box<dyn std::error::Error>> {
    unsafe {
        let platform =
            VZGenericPlatformConfiguration::init(VZGenericPlatformConfiguration::alloc());

        let boot_loader = VZEFIBootLoader::init(VZEFIBootLoader::alloc());
        let variable_store = load_efi_variable_store()?;
        boot_loader.setVariableStore(Some(&variable_store));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(cpu_count as NSUInteger);
        config.setMemorySize(ram_bytes);

        config.setNetworkDevices(&NSArray::from_retained_slice(&[{
            let network_device = VZVirtioNetworkDeviceConfiguration::new();
            match network_backend {
                PreparedNetworkBackend::VzNat => {
                    network_device.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
                }
                PreparedNetworkBackend::VmnetHelper { vm_socket_fd, .. } => {
                    let network_fd = vm_socket_fd
                        .take()
                        .ok_or_else(|| io::Error::other("vmnet-helper socket already consumed"))?;
                    let file_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                        NSFileHandle::alloc(),
                        network_fd.into_raw_fd(),
                        true,
                    );
                    let attachment = VZFileHandleNetworkDeviceAttachment::initWithFileHandle(
                        VZFileHandleNetworkDeviceAttachment::alloc(),
                        &file_handle,
                    );
                    network_device.setAttachment(Some(&attachment));
                }
            }
            Retained::into_super(network_device)
        }]));

        config.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
            VZVirtioEntropyDeviceConfiguration::new(),
        )]));

        ////////////////////////////
        // Disks
        {
            let disk_attachment = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &nsurl_from_path(disk_path).unwrap(),
                false,
                VZDiskImageCachingMode::Cached,
                VZDiskImageSynchronizationMode::Full,
            ).unwrap();

            let disk_device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &disk_attachment,
            );

            let storage_devices: Retained<NSArray<_>> =
                NSArray::from_retained_slice(&[Retained::into_super(disk_device)]);

            config.setStorageDevices(&storage_devices);
        };

        ////////////////////////////
        // Directory shares

        if !directory_shares.is_empty() {
            let directories: Retained<NSMutableDictionary<NSString, VZSharedDirectory>> =
                NSMutableDictionary::new();

            for share in directory_shares.iter() {
                assert!(
                    share.host.is_dir(),
                    "path does not exist or is not a directory: {:?}",
                    share.host
                );

                let url = nsurl_from_path(&share.host)?;
                let shared_directory = VZSharedDirectory::initWithURL_readOnly(
                    VZSharedDirectory::alloc(),
                    &url,
                    share.read_only,
                );

                let key = NSString::from_str(&share.tag());
                directories.setObject_forKey(&*shared_directory, ProtocolObject::from_ref(&*key));
            }

            let multi_share = VZMultipleDirectoryShare::initWithDirectories(
                VZMultipleDirectoryShare::alloc(),
                &directories,
            );

            let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str(SHARED_DIRECTORIES_TAG),
            );
            device.setShare(Some(&multi_share));

            let share_devices = NSArray::from_retained_slice(&[device.into_super()]);
            config.setDirectorySharingDevices(&share_devices);
        }

        ////////////////////////////
        // Serial ports
        {
            let ns_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                vm_reads_from_fd.into_raw_fd(),
                true,
            );

            let ns_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                vm_writes_to_fd.into_raw_fd(),
                true,
            );

            let serial_attach =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&ns_read_handle),
                    Some(&ns_write_handle),
                );
            let serial_port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            serial_port.setAttachment(Some(&serial_attach));

            let resize_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                vm_resize_reads_from_fd.into_raw_fd(),
                true,
            );
            let resize_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(),
                vm_resize_writes_to_fd.into_raw_fd(),
                true,
            );
            let resize_attach =
                VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                    VZFileHandleSerialPortAttachment::alloc(),
                    Some(&resize_read_handle),
                    Some(&resize_write_handle),
                );
            let resize_port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            resize_port.setAttachment(Some(&resize_attach));

            let mut all_ports = vec![
                Retained::into_super(serial_port),
                Retained::into_super(resize_port),
            ];
            for (console_reads, console_writes, console_resize_reads) in extra_consoles {
                let console_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                    NSFileHandle::alloc(),
                    console_reads.into_raw_fd(),
                    true,
                );
                let console_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                    NSFileHandle::alloc(),
                    console_writes.into_raw_fd(),
                    true,
                );
                let console_attach =
                    VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                        VZFileHandleSerialPortAttachment::alloc(),
                        Some(&console_read_handle),
                        Some(&console_write_handle),
                    );
                let console_port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
                console_port.setAttachment(Some(&console_attach));
                //
                let console_resize_read_handle =
                    NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                        NSFileHandle::alloc(),
                        console_resize_reads.into_raw_fd(),
                        true,
                    );
                let console_resize_attach =
                    VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                        VZFileHandleSerialPortAttachment::alloc(),
                        Some(&console_resize_read_handle),
                        None,
                    );
                let console_resize_port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
                console_resize_port.setAttachment(Some(&console_resize_attach));
                //
                all_ports.push(Retained::into_super(console_port));
                all_ports.push(Retained::into_super(console_resize_port));
            }
            let serial_ports: Retained<NSArray<_>> =
                NSArray::from_retained_slice(all_ports.as_slice());
            config.setSerialPorts(&serial_ports);
        }

        ////////////////////////////
        // Validate
        config.validateWithError().map_err(|e| {
            io::Error::other(format!(
                "Invalid VM configuration: {:?}",
                e.localizedDescription()
            ))
        })?;

        Ok(config)
    }
}

fn load_efi_variable_store() -> Result<Retained<VZEFIVariableStore>, Box<dyn std::error::Error>> {
    unsafe {
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("efi_variable_store_{}.efivars", std::process::id()));
        let url = nsurl_from_path(&temp_path)?;
        let options = VZEFIVariableStoreInitializationOptions::AllowOverwrite;
        let store = VZEFIVariableStore::initCreatingVariableStoreAtURL_options_error(
            VZEFIVariableStore::alloc(),
            &url,
            options,
        )?;
        Ok(store)
    }
}

fn spawn_login_actions_thread(
    login_actions: Vec<LoginAction>,
    output_monitor: Arc<OutputMonitor>,
    input_tx: mpsc::Sender<VmInput>,
    vm_output_tx: mpsc::Sender<VmOutput>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for a in login_actions {
            match a {
                Expect { text, timeout } => {
                    if WaitResult::Timeout == output_monitor.wait_for(&text, timeout) {
                        let _ = vm_output_tx.send(VmOutput::LoginActionTimeout {
                            action: format!("expect '{}'", text),
                            timeout,
                        });
                        return;
                    }
                }
                Send(mut text) => {
                    text.push('\n'); // Type the newline so the command is actually submitted.
                    input_tx.send(VmInput::Bytes(text.into_bytes())).unwrap();
                }
                Script { path, index } => {
                    let command = match script_command_from_path(&path, index) {
                        Ok(command) => command,
                        Err(err) => {
                            eprintln!("{err}");
                            return;
                        }
                    };
                    let mut text = command;
                    text.push('\n');
                    input_tx.send(VmInput::Bytes(text.into_bytes())).unwrap();
                }
            }
        }
    })
}

fn run_vm(
    disk_path: &Path,
    login_actions: &[LoginAction],
    directory_shares: &[DirectoryShare],
    prepare_network_backend: impl Fn() -> PreparedNetworkBackend,
    cpu_count: usize,
    ram_bytes: u64,
    console_socket_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (vm_reads_from, host_writes_to) = create_pipe(); // hvc0 host->guest
    let (we_read_from, vm_writes_to) = create_pipe(); // hvc0 host<-guest
    let (vm_reads_resize_from, host_write_resize_to) = create_pipe(); // hvc1 host->guest
    let (host_reads_resize_from, vm_writes_resize_to) = create_pipe(); // hvc1 host<-guest
    let (hvc0_disconnect_read, hvc0_disconnect_write) = create_pipe(); // hvc1 exit => attached console

    // hvc2/hvc3, hvc4/hvc5, hvc6/hvc7 — one console+resize pair per attach slot.
    const N_CONSOLE_SLOTS: usize = 3;
    let (vm_extra_consoles, host_console_fds): (Vec<_>, Vec<_>) =
        if console_socket_path.is_some() {
            (0..N_CONSOLE_SLOTS)
                .map(|_| {
                    let (reads_from, we_write) = create_pipe();
                    let (we_read, writes_to) = create_pipe();
                    let (resize_reads_from, host_write_resize) = create_pipe();
                    let (disconnect_read, disconnect_write) = create_pipe();
                    (
                        (reads_from, writes_to, resize_reads_from),
                        (we_read, we_write, host_write_resize, disconnect_read, disconnect_write),
                    )
                })
                .unzip()
        } else {
            (vec![], vec![])
        };

    let mut prepared_network_backend = prepare_network_backend();
    let config = create_vm_configuration(
        disk_path,
        directory_shares,
        &mut prepared_network_backend,
        vm_reads_from,
        vm_writes_to,
        vm_reads_resize_from,
        vm_writes_resize_to,
        vm_extra_consoles,
        cpu_count,
        ram_bytes,
    )?;

    let queue = DispatchQueue::main();

    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &config, queue)
    };

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        if error.is_null() {
            let _ = tx.send(Ok(()));
        } else {
            let err = unsafe { &*error };
            let _ = tx.send(Err(format!("{:?}", err.localizedDescription())));
        }
    });

    unsafe {
        vm.startWithCompletionHandler(&completion_handler);
    }

    let start_deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < start_deadline {
        unsafe {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.1),
            )
        };

        match rx.try_recv() {
            Ok(result) => {
                result.map_err(|e| format!("Failed to start VM: {}", e))?;
                break;
            }
            Err(mpsc::TryRecvError::Empty) => continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("VM start channel disconnected".into());
            }
        }
    }

    if Instant::now() >= start_deadline {
        return Err("Timed out waiting for VM to start".into());
    }

    println!("VM booting...");
    let connect_clients = Arc::new(AtomicI32::new(0));
    const CONSOLE_SOCK_NAMES: [&str; N_CONSOLE_SLOTS] =
        ["hvc2.sock", "hvc4.sock", "hvc6.sock"];
    const RESIZE_SOCK_NAMES: [&str; N_CONSOLE_SLOTS] =
        ["hvc2-resize.sock", "hvc4-resize.sock", "hvc6-resize.sock"];

    let mut all_login_actions = vec![
        Expect {
            text: "login: ".to_string(),
            timeout: LOGIN_EXPECT_TIMEOUT,
        },
        Send("root".to_string()),
        Expect {
            text: "~#".to_string(),
            timeout: LOGIN_EXPECT_TIMEOUT,
        },
        // Temporarily disable bash history and set commands starting with space to be ignored
        Send(" export HISTCONTROL=ignorespace".to_string()),
        Send(" unset HISTFILE".to_string()),
        // Our terminal is connected via /dev/hvc0 which Debian apparently keeps barebones.
        // We want sane terminal defaults like icrnl (translating carriage returns into newlines)
        Send(" stty -F /dev/hvc0 sane".to_string()),
        Send(" stty -F /dev/hvc2 sane".to_string()),
        Send(" stty -F /dev/hvc4 sane".to_string()),
        Send(" stty -F /dev/hvc6 sane".to_string()),
        // In background, continuously read host terminal resizes sent over hvc1 and update hvc0.
        Send({
            // sorry for this nonsense, the string is so long it angers rustfmt =(
            const S: &str = " sh -c '(while IFS=\" \" read -s -r rows cols; do stty -F /dev/hvc0 rows \"$rows\" cols \"$cols\"; done) < /dev/hvc1 >/dev/null 2>&1 &'";
            S.to_string()
        }),
    ];

    if !directory_shares.is_empty() {
        all_login_actions.push(Send(" mkdir -p /mnt/shared".into()));
        all_login_actions.push(Send(format!(
            " mount -t virtiofs {} /mnt/shared",
            SHARED_DIRECTORIES_TAG
        )));

        for share in directory_shares {
            let staging = format!("/mnt/shared/{}", share.tag());
            let guest = share.guest.to_string_lossy();
            all_login_actions.push(Send(format!(" mkdir -p {}", guest)));
            all_login_actions.push(Send(format!(" mount --bind {} {}", staging, guest)));
        }
    }

    if console_socket_path.is_some() {
        all_login_actions.push(Send(script_command_from_content(
            "bash_logout.sh",
            BASH_LOGOUT_SCRIPT,
        )?));
        // Start getty on hvc2/4/6 so attach_console can connect to them.
        all_login_actions.push(Send(
            " systemctl start serial-getty@hvc2.service serial-getty@hvc4.service serial-getty@hvc6.service"
                .to_string(),
        ));
        // Resize handlers: read resize events from hvcN+1 and apply them to hvcN.
        for (console, resize) in [(2u8, 3u8), (4, 5), (6, 7)] {
            all_login_actions.push(Send(format!(
                " sh -c '(while IFS=\" \" read -s -r rows cols; \
                  do stty -F /dev/hvc{console} rows \"$rows\" cols \"$cols\"; done) \
                  < /dev/hvc{resize} >/dev/null 2>&1 &'"
            )));
        }
    }

    for a in login_actions {
        all_login_actions.push(a.clone())
    }

    if let Some(ref console_path) = console_socket_path {
        // eprintln!("Daemon mode ...");
        // ── Daemon mode ────────────────────────────────────────────────────────
        // Use spawn_vm_io to wire hvc0 to stdin/stdout during boot so that boot
        // output is visible.  After login completes the supervisor shuts down
        // spawn_vm_io, recovers the raw hvc0 FDs, and hands them to the socket
        // proxy so that `attach_console` can connect.

        let output_monitor = Arc::new(OutputMonitor::default());
        let io_ctx = spawn_vm_io(
            output_monitor.clone(),
            we_read_from,
            host_writes_to,
            host_write_resize_to,
        );

        let (vm_output_tx, vm_output_rx) = mpsc::channel::<VmOutput>();
        let login_thread = spawn_login_actions_thread(
            all_login_actions,
            output_monitor,
            io_ctx.input_tx.clone(),
            vm_output_tx,
        );

        // Channel used by the supervisor to report success or a timeout error.
        let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();

        let hvc0_sock        = console_path.with_file_name("hvc0.sock");
        let hvc0_resize_sock = console_path.with_file_name("hvc0-resize.sock");

        let mut disconnect_writes = vec![];
        for (i, (host_read, host_write, host_resize_write, disconnect_read, disconnect_write)) in
            host_console_fds.into_iter().enumerate()
        {
            disconnect_writes.push(disconnect_write);
            eprintln!("spawning");
            spawn_console_socket_proxy(
                Arc::clone(&connect_clients),
                host_read,
                host_write,
                disconnect_read,
                done_tx.clone(),
                console_path.with_file_name(CONSOLE_SOCK_NAMES[i]),
            );
            spawn_console_resize_proxy(
                host_resize_write,
                console_path.with_file_name(RESIZE_SOCK_NAMES[i]),
            );
        }

        // Supervisor: waits for login actions, shuts down spawn_vm_io, then
        // hands the recovered hvc0 FDs to a socket proxy.
        thread::spawn(move || {
            login_thread.join().ok();

            match vm_output_rx.try_recv() {
                Ok(VmOutput::LoginActionTimeout { action, timeout }) => {
                    let _ = done_tx.send(Err(format!(
                        "Login action ({action}) timed out after {timeout:?}; shutting down."
                    )));
                }
                _ => {
                    let (vm_out, vm_in, resize) = io_ctx.shutdown();
                    thread::spawn(move || {
                        // poll host_reads_resize_from
                        let mut buf = [0u8; 4096];
                        loop {
                            let mut fds = [
                                libc::pollfd {
                                    fd: host_reads_resize_from.as_raw_fd(),
                                    events: libc::POLLIN,
                                    revents: 0,
                                },
                            ];
                            let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 1000) };
                            if ret == 0 {
                                // eprintln!("timeout!");
                            } else if ret == -1 {
                                eprintln!("Error!");
                                return;
                            } else if fds[0].revents & libc::POLLIN != 0 { // data from /dev/hvc1
                                let n =
                                    unsafe { libc::read(host_reads_resize_from.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
                                if n <= 0 {
                                    return;
                                } else {
                                    // eprintln!("received data from client /dev/hvc1: {n}");
                                    let slice = &buf[..n as usize];
                                    let mut i = 0;
                                    while i < slice.len() {
                                        let byt = slice[i];
                                        if byt == 97 { // a
                                            eprintln!("disconnected /dev/hvc0");
                                            unsafe { libc::write(hvc0_disconnect_write.as_raw_fd(), b"x".as_ptr() as *const _, 1); };
                                        } else if byt == 98 { // b
                                            let fd = disconnect_writes.get(0).unwrap().as_raw_fd();
                                            unsafe { libc::write(fd, b"x".as_ptr() as *const _, 1); };
                                            eprintln!("disconnected /dev/hvc2");
                                        } else if byt == 99 { // c
                                            let fd = disconnect_writes.get(1).unwrap().as_raw_fd();
                                            unsafe { libc::write(fd, b"x".as_ptr() as *const _, 1); };
                                            eprintln!("disconnected /dev/hvc4");
                                        } else if byt == 100 { // d
                                            let fd = disconnect_writes.get(2).unwrap().as_raw_fd();
                                            unsafe { libc::write(fd, b"x".as_ptr() as *const _, 1); };
                                            eprintln!("disconnected /dev/hvc6");
                                        }
                                        i += 1;
                                    }
                                }
                            } else {
                                // POLLHUP / POLLERR / POLLNVAL — fd is gone
                                eprintln!("poll: unexpected revents: {:#x}", fds[0].revents);
                                return;
                            }
                        }
                    });
                    // Write a single newline to trigger the display of the login prompt
                    // as the original prompt has already been consumed
                    unsafe {
                         libc::write(vm_in.as_raw_fd(), "\n".as_ptr() as *const _, 1);
                    };
                    spawn_console_socket_proxy(Arc::clone(&connect_clients),
                                               vm_out,
                                               vm_in,
                                               hvc0_disconnect_read,
                                               done_tx,
                                               hvc0_sock);
                    spawn_console_resize_proxy(resize, hvc0_resize_sock);
                }
            }
        });

        // Main loop: keep pumping the run-loop so the VM stays alive.
        let mut exit_result: Result<(), Box<dyn std::error::Error>> = Ok(());
        loop {
            unsafe {
                NSRunLoop::mainRunLoop().runMode_beforeDate(
                    NSDefaultRunLoopMode,
                    &NSDate::dateWithTimeIntervalSinceNow(0.2),
                )
            };

            match done_rx.try_recv() {
                Ok(Err(msg)) => {
                    exit_result = Err(msg.into());
                    unsafe {
                        if vm.canRequestStop() {
                            vm.requestStopWithError().ok();
                        } else if vm.canStop() {
                            vm.stopWithCompletionHandler(&RcBlock::new(|_: *mut NSError| {}));
                        }
                    }
                    break;
                }
                Ok(Ok(())) => {
                    exit_result = Ok(());
                    unsafe {
                        if vm.canRequestStop() {
                            vm.requestStopWithError().ok();
                        } else if vm.canStop() {
                            vm.stopWithCompletionHandler(&RcBlock::new(|_: *mut NSError| {}));
                        }
                    }
                    break;
                }
                Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => {}
            }

            if unsafe { vm.state() } != objc2_virtualization::VZVirtualMachineState::Running {
                break;
            }
        }
        // eprintln!("VM poweroff");

        // Clean up all socket files.
        let base = console_path;
        for name in ["hvc0.sock", "hvc0-resize.sock"]
            .iter()
            .chain(CONSOLE_SOCK_NAMES.iter())
            .chain(RESIZE_SOCK_NAMES.iter())
        {
            let _ = fs::remove_file(base.with_file_name(name));
        }

        exit_result
    } else {
        // ── Provisioning mode ──────────────────────────────────────────────────
        // Wire hvc0 directly to stdin/stdout so the operator can watch progress.

        let output_monitor = Arc::new(OutputMonitor::default());
        let io_ctx = spawn_vm_io(
            output_monitor.clone(),
            we_read_from,
            host_writes_to,
            host_write_resize_to,
        );

        let (vm_output_tx, vm_output_rx) = mpsc::channel::<VmOutput>();
        let login_actions_thread = spawn_login_actions_thread(
            all_login_actions,
            output_monitor,
            io_ctx.input_tx.clone(),
            vm_output_tx,
        );

        let mut exit_result: Result<(), Box<dyn std::error::Error>> = Ok(());
        loop {
            unsafe {
                NSRunLoop::mainRunLoop().runMode_beforeDate(
                    NSDefaultRunLoopMode,
                    &NSDate::dateWithTimeIntervalSinceNow(0.2),
                )
            };

            let state = unsafe { vm.state() };
            match vm_output_rx.try_recv() {
                Ok(VmOutput::LoginActionTimeout { action, timeout }) => {
                    exit_result = Err(format!(
                        "Login action ({action}) timed out after {timeout:?}; shutting down."
                    )
                    .into());
                    unsafe {
                        if vm.canRequestStop() {
                            if let Err(err) = vm.requestStopWithError() {
                                eprintln!("Failed to request VM stop: {:?}", err);
                            }
                        } else if vm.canStop() {
                            let handler = RcBlock::new(|_error: *mut NSError| {});
                            vm.stopWithCompletionHandler(&handler);
                        }
                    }
                    break;
                }
                Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => {}
            }
            if state != objc2_virtualization::VZVirtualMachineState::Running {
                break;
            }
        }

        login_actions_thread.join().ok();
        io_ctx.shutdown();
        exit_result
    }
}

fn nsurl_from_path(path: &Path) -> Result<Retained<NSURL>, Box<dyn std::error::Error>> {
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let ns_path = NSString::from_str(
        abs_path
            .to_str()
            .ok_or("Non-UTF8 path encountered while building NSURL")?,
    );
    Ok(NSURL::fileURLWithPath(&ns_path))
}

fn terminal_size(fd: i32) -> Option<(u16, u16)> {
    let mut winsize: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut winsize) } != 0 {
        return None;
    }
    if winsize.ws_row == 0 || winsize.ws_col == 0 {
        return None;
    }
    Some((winsize.ws_row, winsize.ws_col))
}

fn enable_raw_mode(fd: i32) -> io::Result<RawModeGuard> {
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };

    if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let original = attributes;

    // Disable translation of carriage return to newline on input
    attributes.c_iflag &= !(libc::ICRNL);
    // Disable canonical mode (line buffering), echo, and signal generation
    attributes.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
    attributes.c_cc[libc::VMIN] = 0;
    attributes.c_cc[libc::VTIME] = 1;

    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(RawModeGuard { fd, original })
}

struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

// Ensure the running binary has com.apple.security.virtualization entitlements by checking and, if not, signing and relaunching.
pub fn ensure_signed() {
    let exe = std::env::current_exe().expect("failed to get current exe path");
    let exe_str = exe.to_str().expect("exe path not valid utf-8");

    let has_required_entitlements = {
        let output = Command::new("codesign")
            .args(["-d", "--entitlements", "-", "--xml", exe.to_str().unwrap()])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("com.apple.security.virtualization")
            }
            _ => false,
        }
    };

    if has_required_entitlements {
        return;
    }

    const ENTITLEMENTS: &str = include_str!("entitlements.plist");
    let entitlements_path = std::env::temp_dir().join("entitlements.plist");
    std::fs::write(&entitlements_path, ENTITLEMENTS).expect("failed to write entitlements");

    let status = Command::new("codesign")
        .args([
            "--sign",
            "-",
            "--force",
            "--entitlements",
            entitlements_path.to_str().unwrap(),
            exe_str,
        ])
        .status();

    let _ = std::fs::remove_file(&entitlements_path);

    match status {
        Ok(s) if s.success() => {
            let err = Command::new(&exe).args(std::env::args_os().skip(1)).exec();
            eprintln!("failed to re-exec after signing: {err}");
            std::process::exit(1);
        }
        Ok(s) => {
            eprintln!("codesign failed with status: {s}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("failed to run codesign: {e}");
            std::process::exit(1);
        }
    }
}
