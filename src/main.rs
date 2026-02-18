use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    os::{
        fd::RawFd,
        unix::{
            io::{AsRawFd, OwnedFd},
            net::UnixStream,
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

#[cfg(target_os = "macos")]
use std::os::unix::{io::IntoRawFd, process::CommandExt};

#[cfg(target_os = "macos")]
use {
    block2::RcBlock,
    dispatch2::DispatchQueue,
    objc2::{AnyThread, rc::Retained, runtime::ProtocolObject},
    objc2_foundation::*,
    objc2_virtualization::*,
};

use lexopt::prelude::*;

// ── Disk image constants ──────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
#[cfg(target_os = "macos")]
const DEBIAN_COMPRESSED_SHA: &str = "6ab9be9e6834adc975268367f2f0235251671184345c34ee13031749fdfbf66fe4c3aafd949a2d98550426090e9ac645e79009c51eb0eefc984c15786570bb38";
#[cfg(target_os = "macos")]
const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 280_901_576;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-amd64-20260112-2355.tar.xz";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const DEBIAN_COMPRESSED_SHA: &str = "765890bb31a071be829a64d086923447476b94b9c02faecff80f787a7e261f2088449f94ce362e5cb752901b188c443a284cb91bc98991fdcf375beca4a54eb9";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 285_000_000;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const DEBIAN_COMPRESSED_SHA: &str = "6ab9be9e6834adc975268367f2f0235251671184345c34ee13031749fdfbf66fe4c3aafd949a2d98550426090e9ac645e79009c51eb0eefc984c15786570bb38";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 280_901_576;

#[cfg(target_os = "macos")]
const SHARED_DIRECTORIES_TAG: &str = "shared";

const BYTES_PER_MB: u64 = 1024 * 1024;
const DEFAULT_CPU_COUNT: usize = 2;
const DEFAULT_RAM_MB: u64 = 2048;
const DEFAULT_RAM_BYTES: u64 = DEFAULT_RAM_MB * BYTES_PER_MB;
const START_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_EXPECT_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_EXPECT_TIMEOUT: Duration = Duration::from_secs(120);
const PROVISION_SCRIPT: &str = include_str!("provision.sh");

#[derive(Clone)]
enum LoginAction {
    Expect { text: String, timeout: Duration },
    Send(String),
    Script { path: PathBuf, index: usize },
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_cli()?;

    if args.version {
        println!("Vibe");
        println!("https://github.com/lynaghk/vibe/");
        println!("Git SHA: {}", env!("GIT_SHA"));
        std::process::exit(0);
    }

    if args.help {
        println!(
            "Vibe is a quick way to spin up a Linux virtual machine to sandbox LLM agents.

vibe [OPTIONS] [disk-image.raw]

Options

  --help                                                    Print this help message.
  --version                                                 Print the version (commit SHA).
  --no-default-mounts                                       Disable all default mounts, including .git and .vibe project subfolder masking.
  --mount host-path:guest-path[:read-only | :read-write]    Mount `host-path` inside VM at `guest-path`.
                                                            Defaults to read-write.
                                                            Errors if host-path does not exist.
  --cpus <count>                                            Number of virtual CPUs (default {DEFAULT_CPU_COUNT}).
  --ram <megabytes>                                         RAM size in megabytes (default {DEFAULT_RAM_MB}).
  --script <path/to/script.sh>                              Run script in VM.
  --send <some-command>                                     Type `some-command` followed by newline into the VM.
  --expect <string> [timeout-seconds]                       Wait for `string` to appear in console output before executing next `--script` or `--send`.
                                                            If `string` does not appear within timeout (default 30 seconds), shutdown VM with error.
"
        );
        std::process::exit(0);
    }

    #[cfg(target_os = "macos")]
    ensure_signed();

    let project_root = env::current_dir()?;
    let project_name = project_root
        .file_name()
        .ok_or("Project directory has no name")?
        .to_string_lossy()
        .into_owned();

    let home = env::var("HOME").map(PathBuf::from)?;
    let cache_home = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".cache"));
    let cache_dir = cache_home.join("vibe");
    let guest_mise_cache = cache_dir.join(".guest-mise-cache");

    let instance_dir = project_root.join(".vibe");

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

    let disk_path = if let Some(path) = args.disk {
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
        )?;
        ensure_instance_disk(&instance_raw, &default_raw)?;

        instance_raw
    };

    let mut login_actions = Vec::new();
    let mut directory_shares = Vec::new();

    if !args.no_default_mounts {
        login_actions.push(Send(format!("cd {project_name}")));

        // Discourage read/write of project dir subfolders within the VM.
        for subfolder in [".git", ".vibe"] {
            if project_root.join(subfolder).exists() {
                login_actions.push(Send(format!(r"mount -t tmpfs tmpfs {}", subfolder)))
            }
        }

        directory_shares.push(
            DirectoryShare::new(
                project_root,
                PathBuf::from("/root/").join(project_name),
                false,
            )
            .expect("Project directory must exist"),
        );

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
    }

    for spec in &args.mounts {
        directory_shares.push(DirectoryShare::from_mount_spec(spec)?);
    }

    if let Some(motd_action) = motd_login_action(&directory_shares) {
        login_actions.push(motd_action);
    }

    // Any user-provided login actions must come after our system ones
    login_actions.extend(args.login_actions);

    run_vm(
        &disk_path,
        &login_actions,
        &directory_shares[..],
        args.cpu_count,
        args.ram_bytes,
    )
}

struct CliArgs {
    disk: Option<PathBuf>,
    version: bool,
    help: bool,
    no_default_mounts: bool,
    mounts: Vec<String>,
    login_actions: Vec<LoginAction>,
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
    let mut no_default_mounts = false;
    let mut mounts = Vec::new();
    let mut login_actions = Vec::new();
    let mut script_index = 0;
    let mut cpu_count = DEFAULT_CPU_COUNT;
    let mut ram_bytes = DEFAULT_RAM_BYTES;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("version") => version = true,
            Long("help") | Short('h') => help = true,
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
        no_default_mounts,
        mounts,
        login_actions,
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
        "mkdir -p {guest_dir}\ncat >{guest_path} <<'{marker}'\n{script}\n{marker}\nchmod +x {guest_path}\n{guest_path}"
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
        return Some(Send("clear".into()));
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

    let command = format!("clear && cat <<'VIBE_MOTD'\n{output}\nVIBE_MOTD");
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

fn verify_sha512(file_path: &Path, expected_sha: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        let input = format!("{}  {}\n", expected_sha, file_path.display());
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
            return Err(format!("SHA validation failed for {}", file_path.display()).into());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let input = format!("{}  {}\n", expected_sha, file_path.display());
        let mut child = Command::new("sha512sum")
            .args(["--check"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn sha512sum: {e}"))?;
        child
            .stdin
            .take()
            .expect("failed to open stdin")
            .write_all(input.as_bytes())
            .expect("failed to write to stdin");
        let status = child.wait().expect("failed to wait on child");
        if !status.success() {
            return Err(format!("SHA validation failed for {}", file_path.display()).into());
        }
    }

    Ok(())
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

    verify_sha512(base_compressed, DEBIAN_COMPRESSED_SHA)?;

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
        DEFAULT_CPU_COUNT,
        DEFAULT_RAM_BYTES,
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
    mux_thread: thread::JoinHandle<()>,
    stdout_thread: thread::JoinHandle<()>,
}

pub fn create_pipe() -> (OwnedFd, OwnedFd) {
    let (read_stream, write_stream) = UnixStream::pair().expect("Failed to create socket pair");
    (read_stream.into(), write_stream.into())
}

pub fn spawn_vm_io(
    output_monitor: Arc<OutputMonitor>,
    vm_output_fd: OwnedFd,
    vm_input_fd: OwnedFd,
) -> IoContext {
    let (input_tx, input_rx): (Sender<VmInput>, Receiver<VmInput>) = mpsc::channel();

    // raw_guard is set when we've put the user's terminal into raw mode because we've attached stdin/stdout to the VM.
    let raw_guard = Arc::new(Mutex::new(None));

    let (wakeup_read, wakeup_write) = create_pipe();

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

        move || {
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
        }
    });

    // Copies data from mpsc channel into VM, so vibe can "type" stuff and run scripts.
    let mux_thread = thread::spawn(move || {
        let mut vm_writer = std::fs::File::from(vm_input_fd);
        loop {
            match input_rx.recv() {
                Ok(VmInput::Bytes(data)) => {
                    if let Err(e) = vm_writer.write_all(&data) {
                        eprintln!("[mux] write failed: {e:?}");
                        break;
                    }
                }
                Ok(VmInput::Shutdown) => break,
                Err(_) => break,
            }
        }
    });

    IoContext {
        input_tx,
        wakeup_write,
        stdin_thread,
        mux_thread,
        stdout_thread,
    }
}

impl IoContext {
    pub fn shutdown(self) {
        let _ = self.input_tx.send(VmInput::Shutdown);
        unsafe { libc::write(self.wakeup_write.as_raw_fd(), b"x".as_ptr() as *const _, 1) };
        let _ = self.stdin_thread.join();
        let _ = self.stdout_thread.join();
        let _ = self.mux_thread.join();
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

// ── macOS backend ─────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn create_vm_configuration(
    disk_path: &Path,
    directory_shares: &[DirectoryShare],
    vm_reads_from_fd: OwnedFd,
    vm_writes_to_fd: OwnedFd,
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
            network_device.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
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
        // Serial port
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

            let serial_ports: Retained<NSArray<_>> =
                NSArray::from_retained_slice(&[Retained::into_super(serial_port)]);

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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn run_vm(
    disk_path: &Path,
    login_actions: &[LoginAction],
    directory_shares: &[DirectoryShare],
    cpu_count: usize,
    ram_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let (vm_reads_from, we_write_to) = create_pipe();
    let (we_read_from, vm_writes_to) = create_pipe();

    let config = create_vm_configuration(
        disk_path,
        directory_shares,
        vm_reads_from,
        vm_writes_to,
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

    let output_monitor = Arc::new(OutputMonitor::default());
    let io_ctx = spawn_vm_io(output_monitor.clone(), we_read_from, we_write_to);

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
        // Our terminal is connected via /dev/hvc0 which Debian apparently keeps barebones.
        // We want sane terminal defaults like icrnl (translating carriage returns into newlines)
        Send("stty sane".to_string()),
    ];

    if !directory_shares.is_empty() {
        all_login_actions.push(Send("mkdir -p /mnt/shared".into()));
        all_login_actions.push(Send(format!(
            "mount -t virtiofs {} /mnt/shared",
            SHARED_DIRECTORIES_TAG
        )));

        for share in directory_shares {
            let staging = format!("/mnt/shared/{}", share.tag());
            let guest = share.guest.to_string_lossy();
            all_login_actions.push(Send(format!("mkdir -p {}", guest)));
            all_login_actions.push(Send(format!("mount --bind {} {}", staging, guest)));
        }
    }

    for a in login_actions {
        all_login_actions.push(a.clone())
    }

    let (vm_output_tx, vm_output_rx) = mpsc::channel::<VmOutput>();
    let login_actions_thread = spawn_login_actions_thread(
        all_login_actions,
        output_monitor.clone(),
        io_ctx.input_tx.clone(),
        vm_output_tx,
    );

    let mut last_state = None;
    let mut exit_result = Ok(());
    loop {
        unsafe {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.2),
            )
        };

        let state = unsafe { vm.state() };
        if last_state != Some(state) {
            last_state = Some(state);
        }
        match vm_output_rx.try_recv() {
            Ok(VmOutput::LoginActionTimeout { action, timeout }) => {
                exit_result = Err(format!(
                    "Login action ({}) timed out after {:?}; shutting down.",
                    action, timeout
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
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {}
        }
        if state != objc2_virtualization::VZVirtualMachineState::Running {
            break;
        }
    }

    let _ = login_actions_thread.join();

    io_ctx.shutdown();

    exit_result
}

#[cfg(target_os = "macos")]
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

// Ensure the running binary has com.apple.security.virtualization entitlements by checking and, if not, signing and relaunching.
#[cfg(target_os = "macos")]
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

// ── Linux backend (cloud-hypervisor + virtiofsd) ──────────────────────────────

#[cfg(target_os = "linux")]
fn find_binary(name: &str) -> Option<PathBuf> {
    // Check PATH first
    if let Ok(path_var) = env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    // Check common install locations
    for prefix in ["/usr/bin", "/usr/local/bin", "/opt/cloud-hypervisor"] {
        let candidate = PathBuf::from(prefix).join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Find EFI firmware for cloud-hypervisor. Returns the path to the firmware file.
#[cfg(target_os = "linux")]
fn find_efi_firmware() -> Option<PathBuf> {
    // cloud-hypervisor ships its own firmware on some distros
    let candidates: &[&str] = &[
        "/usr/share/cloud-hypervisor/CLOUDHV.fd",
        // OVMF (x86_64)
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF.fd",
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/OVMF_CODE.fd",
        // AAVMF (aarch64)
        "/usr/share/AAVMF/AAVMF_CODE.fd",
        "/usr/share/aavmf/AAVMF_CODE.fd",
        "/usr/share/edk2/aarch64/QEMU_EFI.fd",
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Send a raw HTTP GET to cloud-hypervisor's REST API over a Unix socket.
/// Returns the response body (everything after the HTTP headers).
#[cfg(target_os = "linux")]
fn ch_api_get(socket_path: &Path, api_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Read;

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

    // Strip HTTP headers — body starts after the blank line
    if let Some(body_start) = raw.find("\r\n\r\n") {
        Ok(raw[body_start + 4..].to_string())
    } else {
        Ok(raw)
    }
}

/// Send a raw HTTP PUT to cloud-hypervisor's REST API over a Unix socket.
#[cfg(target_os = "linux")]
fn ch_api_put(
    socket_path: &Path,
    api_path: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect to API socket: {e}"))?;

    let request = format!(
        "PUT {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        api_path,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    // Drain response
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(())
}

/// Wait for the cloud-hypervisor API socket to appear, then query it to get
/// the serial console PTY path. Retries for up to START_TIMEOUT.
#[cfg(target_os = "linux")]
fn wait_for_serial_pty(api_socket: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + START_TIMEOUT;

    // Wait for the API socket file to appear
    while !api_socket.exists() {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for cloud-hypervisor API socket to appear".into());
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Poll until the VM is running and the PTY path is reported
    loop {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for cloud-hypervisor serial PTY".into());
        }
        thread::sleep(Duration::from_millis(100));

        let body = match ch_api_get(api_socket, "/api/v1/vm.info") {
            Ok(b) => b,
            Err(_) => continue, // VM not ready yet
        };

        // cloud-hypervisor reports the PTY path in the JSON as:
        //   "serial": { "file": "/dev/pts/N", "mode": "Pty", ... }
        // We scan for "/dev/pts/" to extract it without a JSON parser.
        if let Some(pos) = body.find("/dev/pts/") {
            let rest = &body[pos..];
            let end = rest
                .find(|c: char| c == '"' || c == ',' || c == '}' || c == ' ' || c == '\n')
                .unwrap_or(rest.len());
            let pty_path = rest[..end].trim().to_string();
            if !pty_path.is_empty() {
                return Ok(PathBuf::from(pty_path));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn run_vm(
    disk_path: &Path,
    login_actions: &[LoginAction],
    directory_shares: &[DirectoryShare],
    cpu_count: usize,
    ram_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── Locate required binaries ──────────────────────────────────────────────

    let ch_bin = find_binary("cloud-hypervisor").ok_or_else(|| {
        "cloud-hypervisor not found.\n\
         Install it with: sudo apt install cloud-hypervisor\n\
         Or see: https://github.com/cloud-hypervisor/cloud-hypervisor/releases"
    })?;

    let virtiofsd_bin = if !directory_shares.is_empty() {
        Some(find_binary("virtiofsd").ok_or_else(|| {
            "virtiofsd not found.\n\
             Install it with: sudo apt install virtiofsd\n\
             Or see: https://gitlab.com/virtio-fs/virtiofsd"
        })?)
    } else {
        None
    };

    let firmware = find_efi_firmware().ok_or_else(|| {
        "EFI firmware not found.\n\
         Install cloud-hypervisor firmware: sudo apt install cloud-hypervisor\n\
         Or install OVMF: sudo apt install ovmf"
    })?;

    // ── Per-session temp directory ────────────────────────────────────────────

    let pid = std::process::id();
    let tmp_dir = std::env::temp_dir().join(format!("vibe-{pid}"));
    fs::create_dir_all(&tmp_dir)?;

    // Guard: remove tmp_dir when this scope ends
    struct TmpDirGuard(PathBuf);
    impl Drop for TmpDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _tmp_guard = TmpDirGuard(tmp_dir.clone());

    // ── Start virtiofsd for each directory share ──────────────────────────────

    let mut virtiofsd_children: Vec<std::process::Child> = Vec::new();

    if let Some(ref vfsd) = virtiofsd_bin {
        for share in directory_shares {
            let socket_path = tmp_dir.join(format!("{}.sock", share.tag()));

            let child = Command::new(vfsd)
                .args([
                    "--socket-path",
                    &socket_path.to_string_lossy(),
                    "--shared-dir",
                    &share.host.to_string_lossy(),
                    "--cache",
                    "auto",
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

    // Guard: kill all virtiofsd children when this scope ends
    struct VirtiofsdGuard(Vec<std::process::Child>);
    impl Drop for VirtiofsdGuard {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let _vfsd_guard = VirtiofsdGuard(virtiofsd_children);

    // ── Build and launch cloud-hypervisor ─────────────────────────────────────

    let api_socket = tmp_dir.join("api.sock");
    let ram_mb = ram_bytes / BYTES_PER_MB;

    let mut ch_cmd = Command::new(&ch_bin);
    ch_cmd.args([
        "--firmware",
        &firmware.to_string_lossy(),
        "--disk",
        &format!("path={}", disk_path.to_string_lossy()),
        "--memory",
        &format!("size={}M", ram_mb),
        "--cpus",
        &format!("boot={}", cpu_count),
        "--net",
        "tap=,mac=,ip=,mask=",
        "--serial",
        "pty",
        "--console",
        "off",
        "--api-socket",
        &api_socket.to_string_lossy(),
    ]);

    // One --fs entry per directory share
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

    // Guard: kill cloud-hypervisor if we return early
    struct ChGuard(Option<std::process::Child>);
    impl Drop for ChGuard {
        fn drop(&mut self) {
            if let Some(ref mut child) = self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut ch_guard = ChGuard(None); // We move ch_process in below

    // ── Find the serial PTY ───────────────────────────────────────────────────

    let pty_path = match wait_for_serial_pty(&api_socket) {
        Ok(p) => p,
        Err(e) => {
            let _ = ch_process.kill();
            return Err(e);
        }
    };

    ch_guard.0 = Some(ch_process);

    println!("VM booting...");

    // Open the slave PTY for bidirectional console I/O
    let pty_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pty_path)
        .map_err(|e| format!("Failed to open serial PTY {}: {e}", pty_path.display()))?;

    let vm_output_fd: OwnedFd = pty_file.try_clone()?.into();
    let vm_input_fd: OwnedFd = pty_file.into();

    // ── Wire up I/O ───────────────────────────────────────────────────────────

    let output_monitor = Arc::new(OutputMonitor::default());
    let io_ctx = spawn_vm_io(output_monitor.clone(), vm_output_fd, vm_input_fd);

    // ── Build login action sequence ───────────────────────────────────────────

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
        Send("stty sane".to_string()),
    ];

    // On Linux each virtiofs share gets its own tag and is mounted directly
    // at the target guest path — no staging directory needed.
    for share in directory_shares {
        let guest = share.guest.to_string_lossy();
        all_login_actions.push(Send(format!("mkdir -p {}", guest)));
        all_login_actions.push(Send(format!(
            "mount -t virtiofs {} {}",
            share.tag(),
            guest
        )));
    }

    for a in login_actions {
        all_login_actions.push(a.clone());
    }

    // ── Event loop ────────────────────────────────────────────────────────────

    let (vm_output_tx, vm_output_rx) = mpsc::channel::<VmOutput>();
    let login_actions_thread = spawn_login_actions_thread(
        all_login_actions,
        output_monitor.clone(),
        io_ctx.input_tx.clone(),
        vm_output_tx,
    );

    let mut exit_result: Result<(), Box<dyn std::error::Error>> = Ok(());

    loop {
        // Check if cloud-hypervisor process has exited (VM shutdown)
        let ch = ch_guard.0.as_mut().unwrap();
        match ch.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => {
                exit_result = Err(format!("Error waiting for cloud-hypervisor: {e}").into());
                break;
            }
        }

        // Check for login action timeouts
        match vm_output_rx.try_recv() {
            Ok(VmOutput::LoginActionTimeout { action, timeout }) => {
                exit_result = Err(format!(
                    "Login action ({}) timed out after {:?}; shutting down.",
                    action, timeout
                )
                .into());
                // Request clean VM shutdown via the REST API
                let _ = ch_api_put(&api_socket, "/api/v1/vm.shutdown", "");
                break;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {}
        }

        thread::sleep(Duration::from_millis(200));
    }

    let _ = login_actions_thread.join();
    io_ctx.shutdown();

    // cloud-hypervisor will exit on its own after VM shutdown; we wait briefly
    if let Some(ref mut ch) = ch_guard.0 {
        let _ = ch.wait();
    }
    ch_guard.0 = None; // prevent double-kill in Drop

    exit_result
}
