use std::{
    env, fs,
    io::{self, Read, Write},
    os::unix::{
        io::{AsRawFd, IntoRawFd, OwnedFd},
        net::UnixStream,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
        mpsc::{Receiver, Sender},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::{rc::Retained, runtime::ProtocolObject, AnyThread};
use objc2_foundation::*;
use objc2_virtualization::*;

const DEBIAN_DISK_URL: &str =
    "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
const SHARED_DIRECTORIES_TAG: &str = "shared";

const DISK_SIZE_GB: u64 = 10;
const CPU_COUNT: usize = 4;
const RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const START_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
enum LoginActions {
    WaitFor(String),
    Type(String),
}
use LoginActions::*;

struct DirectoryShare {
    host: PathBuf,
    guest: PathBuf,
    read_only: bool,
}

impl DirectoryShare {
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

    let basename_compressed = DEBIAN_DISK_URL.rsplit('/').next().unwrap();
    let base_compressed = cache_dir.join(basename_compressed);
    let base_raw = cache_dir.join(format!(
        "{}.raw",
        basename_compressed.trim_end_matches(".tar.xz")
    ));

    let configured_raw = cache_dir.join("configured_base.raw");
    let instance_raw = instance_dir.join("instance.raw");
    let cargo_registry = home.join(".cargo/registry");

    // Prepare system-wide directories
    fs::create_dir_all(&cache_dir)?;
    fs::create_dir_all(&guest_mise_cache)?;

    // TODO: would be nice to have this called by ensure_configured, rather than having it in main.
    ensure_base_image(&base_raw, &base_compressed)?;

    ensure_configured_base(&base_raw, &configured_raw)?;

    ensure_instance_disk(&instance_raw, &configured_raw)?;

    let mut login_actions = vec![Type(format!("cd {project_name}"))];

    // TODO: Add a nice entry message which shows the shared directories.
    login_actions.push(Type("clear".into()));

    // discourage read/write of .git folder from within the VM. note that this isn't secure, since the VM runs as root and could unmount this.
    // I couldn't find an alternative way to do this --- the MacOS sandbox doesn't apply to the Apple Virtualization system, and
    if project_root.join(".git").exists() {
        login_actions.push(Type(r"mount -t tmpfs tmpfs .git/".into()));
    }

    let mut directory_shares = vec![
        DirectoryShare {
            host: cargo_registry,
            guest: "/root/.cargo/registry".into(),
            read_only: false,
        },
        DirectoryShare {
            host: guest_mise_cache,
            guest: "/root/.local/share/mise".into(),
            read_only: false,
        },
        DirectoryShare {
            guest: PathBuf::from("/root/").join(project_name),
            host: project_root,
            read_only: false,
        },
    ];

    {
        let codex = home.join(".codex");
        if codex.exists() {
            directory_shares.push(DirectoryShare {
                guest: PathBuf::from("/root/").join(".codex"),
                host: codex,
                read_only: false,
            })
        }
    }

    run_vm(&instance_raw, &login_actions, &directory_shares[..])
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

    println!("Downloading base image...");
    let status = Command::new("curl")
        .args([
            "--compressed",
            "--location",
            "--fail",
            "-o",
            &base_compressed.to_string_lossy(),
            DEBIAN_DISK_URL,
        ])
        .status()?;

    if !status.success() {
        return Err("Failed to download base image".into());
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

fn ensure_configured_base(
    base_raw: &Path,
    configured_raw: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if configured_raw.exists() {
        println!("Using configured base at {}", configured_raw.display());
        return Ok(());
    }

    println!("Configuring base image...");
    fs::copy(base_raw, configured_raw)?;
    resize(configured_raw, DISK_SIZE_GB)?;

    run_vm(
        configured_raw,
        &[Type({
            let path = "provision.sh";
            let script = include_str!("provision.sh");
            format!(
                "cat >{path} <<'PROVISIONING_EOF'
{script}
PROVISIONING_EOF
chmod +x {path}
./{path}"
            )
        })],
        &[],
    )?;

    Ok(())
}

fn ensure_instance_disk(
    instance_raw: &Path,
    configured_raw: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if instance_raw.exists() {
        return Ok(());
    }

    println!("Creating instance disk from configured base image...");
    std::fs::create_dir_all(instance_raw.parent().unwrap())?;
    fs::copy(configured_raw, instance_raw)?;
    resize(instance_raw, DISK_SIZE_GB)?;
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
    login_actions: Vec<LoginActions>,
    output_monitor: Arc<OutputMonitor>,
    input_tx: mpsc::Sender<VmInput>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for a in login_actions {
            match a {
                WaitFor(text) => {
                    if WaitResult::Timeout
                        == output_monitor.wait_for(&text, Duration::from_secs(120))
                    {
                        eprintln!("Login action timed out waiting for '{}'", &text);
                        return;
                    }
                }
                Type(mut text) => {
                    text.push('\n'); // Type the newline so the command is actually submitted.
                    input_tx.send(VmInput::Bytes(text.into_bytes())).unwrap();
                }
            }
        }
    })
}

fn run_vm(
    disk_path: &Path,
    login_actions: &[LoginActions],
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
        WaitFor("login: ".to_string()),
        Type("root".to_string()),
        WaitFor("~#".to_string()),
    ];

    if !directory_shares.is_empty() {
        all_login_actions.push(Type("mkdir -p /mnt/shared".into()));
        all_login_actions.push(Type(format!(
            "mount -t virtiofs {} /mnt/shared",
            SHARED_DIRECTORIES_TAG
        )));

        for share in directory_shares {
            let staging = format!("/mnt/shared/{}", share.tag());
            let guest = share.guest.to_string_lossy();
            all_login_actions.push(Type(format!("mkdir -p {}", guest)));
            all_login_actions.push(Type(format!("mount --bind {} {}", staging, guest)));
        }
    }

    for a in login_actions {
        all_login_actions.push(a.clone())
    }

    let login_actions_thread = spawn_login_actions_thread(
        all_login_actions,
        output_monitor.clone(),
        io_ctx.input_tx.clone(),
    );

    let _raw_guard = enable_raw_mode(io::stdin().as_raw_fd())?;

    let mut last_state = None;
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
        if state != objc2_virtualization::VZVirtualMachineState::Running {
            //eprintln!("VM stopped with state: {:?}", state);
            break;
        }
    }

    let _ = login_actions_thread.join();

    io_ctx.shutdown();

    Ok(())
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

fn resize(path: &Path, size_gb: u64) -> Result<(), Box<dyn std::error::Error>> {
    let size_bytes = size_gb * 1024 * 1024 * 1024;
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
