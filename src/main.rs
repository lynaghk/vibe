use std::{
    env, fs,
    io::{self, Read, Write},
    os::unix::{
        io::{AsRawFd, IntoRawFd, OwnedFd},
        net::UnixStream,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use block2::RcBlock;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command as ClapCommand};
use dispatch2::DispatchQueue;
use objc2::{rc::Retained, runtime::ProtocolObject, AnyThread};
use objc2_foundation::*;
use objc2_virtualization::*;

const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
const DEBIAN_COMPRESSED_SHA: &str = "6ab9be9e6834adc975268367f2f0235251671184345c34ee13031749fdfbf66fe4c3aafd949a2d98550426090e9ac645e79009c51eb0eefc984c15786570bb38";
const SHARED_DIRECTORIES_TAG: &str = "shared";

const DISK_SIZE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const CPU_COUNT: usize = 4;
const RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
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
    let matches = build_cli().get_matches();

    if matches.get_flag("version") {
        println!("Vibe");
        println!("https://github.com/lynaghk/vibe/");
        println!("Git SHA: {}", env!("GIT_SHA"));
        std::process::exit(0);
    }

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

    let disk_path = if let Some(path) = matches.get_one::<PathBuf>("disk").cloned() {
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

    if !matches.get_flag("no-default-mounts") {
        login_actions.push(Send(format!("cd {project_name}")));

        // discourage read/write of .git folder from within the VM. note that this isn't secure, since the VM runs as root and could unmount this.
        // I couldn't find an alternative way to do this --- the MacOS sandbox doesn't apply to the Apple Virtualization system
        if project_root.join(".git").exists() {
            login_actions.push(Send(r"mount -t tmpfs tmpfs .git/".into()));
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
        ]
        .into_iter()
        .flatten()
        {
            directory_shares.push(share)
        }
    }

    if let Some(mounts) = matches.get_many::<String>("mount") {
        for spec in mounts {
            directory_shares.push(DirectoryShare::from_mount_spec(spec)?);
        }
    }

    if let Some(motd_action) = motd_login_action(&directory_shares) {
        login_actions.push(motd_action);
    }

    // Any user-provided login actions must come after our system ones
    login_actions.extend(collect_ordered_actions(&matches)?);

    run_vm(&disk_path, &login_actions, &directory_shares[..])
}

fn build_cli() -> ClapCommand {
    ClapCommand::new("vibe")
        .arg(
            Arg::new("disk")
                .value_name("DISK")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("version")
                .long("version")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-default-mounts")
                .long("no-default-mounts")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mount")
                .long("mount")
                .action(ArgAction::Append)
                .value_name("host-path:guest-path[:read-only|:read-write]")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("script")
                .long("script")
                .action(ArgAction::Append)
                .value_name("FILE")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("send")
                .long("send")
                .action(ArgAction::Append)
                .value_name("COMMAND")
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("expect")
                .long("expect")
                .action(ArgAction::Append)
                .num_args(1..=2)
                .value_names(["STRING", "TIMEOUT"])
                .value_parser(value_parser!(String)),
        )
}

fn collect_ordered_actions(
    matches: &ArgMatches,
) -> Result<Vec<LoginAction>, Box<dyn std::error::Error>> {
    let mut ordered: Vec<(usize, LoginAction)> = Vec::new();

    for (index, values) in collect_occurrences_with_indices(matches, "script") {
        let [path] = values.as_slice() else {
            return Err("--script expects exactly one value".into());
        };
        ordered.push((
            index,
            Script {
                path: path.into(),
                index,
            },
        ));
    }

    for (index, values) in collect_occurrences_with_indices(matches, "send") {
        let [text] = values.as_slice() else {
            return Err("--send expects exactly one value".into());
        };
        ordered.push((index, Send(text.clone())));
    }

    for (index, values) in collect_occurrences_with_indices(matches, "expect") {
        let (text, timeout) = match values.as_slice() {
            [t] => (t.clone(), DEFAULT_EXPECT_TIMEOUT),
            [t, secs] => (t.clone(), Duration::from_secs(secs.parse()?)),
            _ => return Err("--expect expects a string and an optional timeout in seconds".into()),
        };
        ordered.push((index, Expect { text, timeout }));
    }

    ordered.sort_by_key(|(i, _)| *i);
    Ok(ordered.into_iter().map(|(_, a)| a).collect())
}

fn collect_occurrences_with_indices(matches: &ArgMatches, id: &str) -> Vec<(usize, Vec<String>)> {
    let occurrences: Vec<Vec<String>> = matches
        .get_occurrences::<String>(id)
        .map(|occ| {
            occ.map(|values| values.map(|v| v.to_string()).collect())
                .collect()
        })
        .unwrap_or_default();

    let mut indices = matches.indices_of(id).unwrap_or_default();
    let mut out = Vec::with_capacity(occurrences.len());
    for values in occurrences {
        let mut first_index = None;
        for _ in 0..values.len() {
            let idx = indices
                .next()
                .ok_or_else(|| format!("Missing indices for argument {id}"))
                .unwrap();
            if first_index.is_none() {
                first_index = Some(idx);
            }
        }
        out.push((first_index.unwrap(), values));
    }

    out
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

    let command = format!("clear && cat <<'VIBE_MOTD'\n{output}VIBE_MOTD\n");
    Some(Send(command))
}

#[derive(PartialEq, Eq)]
enum WaitResult {
    Timeout,
    Found,
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

pub enum VmInput {
    Bytes(Vec<u8>),
    Shutdown,
}

fn ensure_base_image(
    base_raw: &Path,
    base_compressed: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if base_raw.exists() {
        return Ok(());
    }

    if !base_compressed.exists() {
        println!("Downloading base image...");
        let status = Command::new("curl")
            .args([
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
) -> Result<(), Box<dyn std::error::Error>> {
    if default_raw.exists() {
        return Ok(());
    }

    ensure_base_image(base_raw, base_compressed)?;

    println!("Configuring base image...");
    fs::copy(base_raw, default_raw)?;
    resize(default_raw, DISK_SIZE_BYTES)?;

    let provision_command = script_command_from_content("provision.sh", PROVISION_SCRIPT)?;
    run_vm(default_raw, &[Send(provision_command)], directory_shares)?;

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
    resize(instance_raw, DISK_SIZE_BYTES)?;
    Ok(())
}

pub struct IoContext {
    pub input_tx: Sender<VmInput>,
    shutdown_flag: Arc<AtomicBool>,
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
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let flag_clone = shutdown_flag.clone();

    let (wakeup_read, wakeup_write) = create_pipe();

    // Copies from stdin to the VM; uses poll so we can break the loop and exit the thread when it's time to shutdown.
    let stdin_thread = thread::spawn({
        let input_tx = input_tx.clone();
        move || {
            let stdin_fd = libc::STDIN_FILENO;
            let mut buf = [0u8; 64];

            loop {
                let mut fds = [
                    libc::pollfd {
                        fd: stdin_fd,
                        events: libc::POLLIN,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: wakeup_read.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    },
                ];

                let ret = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
                if ret <= 0 {
                    break;
                }

                if fds[1].revents & libc::POLLIN != 0 {
                    break;
                }

                if fds[0].revents & libc::POLLIN != 0 {
                    let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
                    if n <= 0 {
                        break;
                    }
                    if flag_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    if input_tx
                        .send(VmInput::Bytes(buf[..n as usize].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mux_thread = thread::spawn(move || {
        let mut vm_writer = std::fs::File::from(vm_input_fd);
        loop {
            match input_rx.recv() {
                Ok(VmInput::Bytes(data)) => {
                    if vm_writer.write_all(&data).is_err() {
                        break;
                    }
                }
                Ok(VmInput::Shutdown) => break,
                Err(_) => break,
            }
        }
    });

    let stdout_thread = thread::spawn(move || {
        let mut vm_reader = std::fs::File::from(vm_output_fd);

        let mut buf = [0u8; 1024];
        loop {
            match vm_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    // TODO: Ideally, we could lock for the entire lifetime of the thread, but I'm not sure how to interrupt the thread because the virtualization framework doesn't close the file descriptor when the VM shuts down.
                    // so we'll just leak this thread =(
                    let mut stdout = std::io::stdout().lock();
                    let bytes = &buf[..n];
                    if stdout.write_all(bytes).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                    output_monitor.push(bytes);
                }
                Err(_) => break,
            }
        }
    });

    IoContext {
        input_tx,
        shutdown_flag,
        wakeup_write,
        stdin_thread,
        mux_thread,
        stdout_thread,
    }
}

impl IoContext {
    pub fn shutdown(self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        let _ = self.input_tx.send(VmInput::Shutdown);
        unsafe { libc::write(self.wakeup_write.as_raw_fd(), b"x".as_ptr() as *const _, 1) };
        let _ = self.stdin_thread.join();
        let _ = self.mux_thread.join();

        // Leak this thread because I can't figure out how to interrupt it.
        drop(self.stdout_thread);
    }
}

fn create_vm_configuration(
    disk_path: &Path,
    directory_shares: &[DirectoryShare],
    vm_reads_from_fd: OwnedFd,
    vm_writes_to_fd: OwnedFd,
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
        config.setCPUCount(CPU_COUNT as NSUInteger);
        config.setMemorySize(RAM_BYTES);

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
            VZDiskImageCachingMode::Automatic,
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
    trigger_exit_tx: mpsc::Sender<String>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for a in login_actions {
            match a {
                Expect { text, timeout } => {
                    if WaitResult::Timeout == output_monitor.wait_for(&text, timeout) {
                        let exit_msg = format!(
                            "Login action timed out waiting for '{}' after {:?}",
                            &text, timeout
                        );
                        let _ = trigger_exit_tx.send(exit_msg);
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
) -> Result<(), Box<dyn std::error::Error>> {
    let (vm_reads_from, we_write_to) = create_pipe();
    let (we_read_from, vm_writes_to) = create_pipe();

    let config = create_vm_configuration(disk_path, directory_shares, vm_reads_from, vm_writes_to)?;

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

    let (trigger_exit_tx, trigger_exit_rx) = mpsc::channel();
    let login_actions_thread = spawn_login_actions_thread(
        all_login_actions,
        output_monitor.clone(),
        io_ctx.input_tx.clone(),
        trigger_exit_tx,
    );

    let _raw_guard = enable_raw_mode(io::stdin().as_raw_fd())?;

    let mut last_state = None;
    let mut exit = Ok(());
    loop {
        unsafe {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.2),
            )
        };

        let state = unsafe { vm.state() };
        if last_state != Some(state) {
            //eprintln!("[state] {:?}", state);
            last_state = Some(state);
        }
        match trigger_exit_rx.try_recv() {
            Ok(msg) => {
                exit = Err(msg.into());
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
            //eprintln!("VM stopped with state: {:?}", state);
            break;
        }
    }

    let _ = login_actions_thread.join();

    io_ctx.shutdown();

    exit
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

fn resize(path: &Path, size_bytes: u64) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(size_bytes)?;
    Ok(())
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
