use std::env;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{
    NSArray, NSData, NSDate, NSDefaultRunLoopMode, NSError, NSFileHandle, NSRunLoop, NSString,
    NSUInteger, NSURL,
};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZEFIBootLoader, VZEFIVariableStore, VZEFIVariableStoreInitializationOptions,
    VZFileHandleSerialPortAttachment, VZGenericMachineIdentifier, VZGenericPlatformConfiguration,
    VZNATNetworkDeviceAttachment, VZSharedDirectory, VZSingleDirectoryShare,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
};

const DEBIAN_DISK_URL: &str =
    "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2";
const PROVISION_SCRIPT: &str = include_str!("../provisioning/provision.sh");

const DISK_SIZE_GB: u64 = 10;
const CPU_COUNT: usize = 4;
const RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const START_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct VmPaths {
    project_root: PathBuf,
    project_name: String,
    cache_dir: PathBuf,
    guest_mise_cache: PathBuf,
    instance_dir: PathBuf,
    downloaded_image: PathBuf,
    base_raw: PathBuf,
    configured_base: PathBuf,
    instance_disk: PathBuf,
    cloud_init_iso: PathBuf,
    machine_identifier: PathBuf,
    efi_variable_store: PathBuf,
    cargo_registry: PathBuf,
    console_log: PathBuf,
}

impl VmPaths {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
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
        let cache_dir = cache_home.join("vibetron");
        let guest_mise_cache = cache_dir.join(".guest-mise-cache");
        let instance_dir = project_root.join(".vibetron");

        let downloaded_image = cache_dir.join("downloaded.qcow2");
        let base_raw = cache_dir.join("base.raw");
        let configured_base = cache_dir.join("configured_base.raw");
        let instance_disk = instance_dir.join("instance.raw");
        let cloud_init_iso = cache_dir.join("cloud-init.iso");
        let machine_identifier = instance_dir.join("machine.id");
        let efi_variable_store = instance_dir.join("efi-variable-store");
        let cargo_registry = home.join(".cargo/registry");
        let console_log = instance_dir.join("console.log");

        Ok(Self {
            project_root,
            project_name,
            cache_dir,
            guest_mise_cache,
            instance_dir,
            downloaded_image,
            base_raw,
            configured_base,
            instance_disk,
            cloud_init_iso,
            machine_identifier,
            efi_variable_store,
            cargo_registry,
            console_log,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = VmPaths::new()?;

    prepare_directories(&paths)?;
    create_console_log(&paths)?;
    download_base_image(&paths)?;
    convert_to_raw(&paths)?;
    //TODO: only create this iso when configuring the base, not every run.
    create_cloud_init_iso(&paths)?;
    ensure_configured_base(&paths)?;

    let provision_needed = ensure_instance_disk(&paths)?;

    let config = create_vm_configuration(&paths, &paths.instance_disk)?;
    run_vm(config, provision_needed, &paths, MountMode::SkipMounts)
}

fn prepare_directories(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(&paths.cache_dir)?;
    fs::create_dir_all(&paths.guest_mise_cache)?;
    fs::create_dir_all(&paths.instance_dir)?;
    fs::create_dir_all(&paths.cargo_registry)?;
    Ok(())
}

fn download_base_image(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.downloaded_image.exists() {
        println!(
            "Reusing cached base image at {}",
            paths.downloaded_image.display()
        );
    } else {
        println!("Downloading Debian cloud image...");
        let status = Command::new("curl")
            .args([
                "-L",
                "-f",
                DEBIAN_DISK_URL,
                "-o",
                paths.downloaded_image.to_string_lossy().as_ref(),
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to download Ubuntu cloud image".into());
        }
    }

    if !validate_image(&paths.downloaded_image, "cached base image") {
        println!("Cached base image invalid, redownloading...");
        fs::remove_file(&paths.downloaded_image).ok();
        let status = Command::new("curl")
            .args([
                "-L",
                "-f",
                DEBIAN_DISK_URL,
                "-o",
                paths.downloaded_image.to_string_lossy().as_ref(),
            ])
            .status()?;

        if !status.success() {
            return Err("Failed to download Ubuntu cloud image".into());
        }
    }

    Ok(())
}

fn convert_to_raw(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.base_raw.exists() {
        if validate_image(&paths.base_raw, "cached base raw") {
            println!(
                "Reusing converted base image at {}",
                paths.base_raw.display()
            );
            return Ok(());
        }
        println!("Cached base image invalid, regenerating...");
        fs::remove_file(&paths.base_raw).ok();
    }

    println!("Converting source image to raw...");
    let status = Command::new("qemu-img")
        .args([
            "convert",
            "-O",
            "raw",
            paths.downloaded_image.to_string_lossy().as_ref(),
            paths.base_raw.to_string_lossy().as_ref(),
        ])
        .status()?;

    if !status.success() {
        return Err("Failed to convert qcow2 image to raw".into());
    }

    validate_image(&paths.base_raw, "converted base raw")
        .then_some(())
        .ok_or_else(|| io::Error::other("Converted base image failed validation"))?;

    resize_file(&paths.base_raw, DISK_SIZE_GB)?;
    Ok(())
}

fn ensure_configured_base(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.configured_base.exists() {
        println!(
            "Using cached configured base at {}",
            paths.configured_base.display()
        );
        return Ok(());
    }

    println!("Preparing configured base image...");
    clone_sparse(&paths.base_raw, &paths.configured_base)?;
    resize_file(&paths.configured_base, DISK_SIZE_GB)?;

    let config = create_vm_configuration(paths, &paths.configured_base)?;
    run_vm(config, true, paths, MountMode::SkipMounts)?;

    Ok(())
}

fn create_cloud_init_iso(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    println!("Building cloud-init ISO...");
    let data_dir = paths.cache_dir.join("cloud-init-data");
    if data_dir.exists() {
        fs::remove_dir_all(&data_dir)?;
    }
    fs::create_dir_all(&data_dir)?;

    let meta_data = format!(
        "instance-id: {}\nlocal-hostname: {}\n",
        paths.project_name, paths.project_name
    );

    let user_data = cloud_init_user_data();

    fs::write(data_dir.join("meta-data"), meta_data)?;
    fs::write(data_dir.join("user-data"), user_data)?;

    if paths.cloud_init_iso.exists() {
        fs::remove_file(&paths.cloud_init_iso)?;
    }

    let status = Command::new("hdiutil")
        .args([
            "makehybrid",
            "-o",
            paths.cloud_init_iso.to_string_lossy().as_ref(),
            "-iso",
            "-joliet",
            "-default-volume-name",
            "cidata",
            data_dir.to_string_lossy().as_ref(),
        ])
        .status()?;

    fs::remove_dir_all(&data_dir)?;

    if !status.success() {
        return Err("Failed to build cloud-init ISO".into());
    }

    Ok(())
}

fn cloud_init_user_data() -> String {
    format!(
        r#"#cloud-config
users:
  - name: user
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
ssh_pwauth: true
runcmd:
  - sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
  - passwd -d user
  - systemctl restart sshd
"#,
    )
}

fn ensure_instance_disk(paths: &VmPaths) -> Result<bool, Box<dyn std::error::Error>> {
    if paths.instance_disk.exists() {
        if validate_image(&paths.instance_disk, "instance raw") {
            println!(
                "Using existing instance disk at {}",
                paths.instance_disk.display()
            );
            return Ok(false);
        }
        println!("Instance disk invalid, recreating...");
        fs::remove_file(&paths.instance_disk).ok();
    }

    println!("Creating instance disk from cached base image...");
    clone_sparse(&paths.configured_base, &paths.instance_disk)?;
    resize_file(&paths.instance_disk, DISK_SIZE_GB)?;
    Ok(true)
}

fn create_console_log(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    // Fresh log each run so users can tail for console output.
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&paths.console_log)?;
    Ok(())
}

fn create_vm_configuration(
    paths: &VmPaths,
    disk_path: &Path,
) -> Result<
    (
        Retained<VZVirtualMachineConfiguration>,
        Option<thread::JoinHandle<()>>,
        Option<thread::JoinHandle<()>>,
        RawFd,
    ),
    Box<dyn std::error::Error>,
> {
    unsafe {
        let platform =
            VZGenericPlatformConfiguration::init(VZGenericPlatformConfiguration::alloc());
        let machine_id = load_machine_identifier(paths)?;
        platform.setMachineIdentifier(&machine_id);

        let boot_loader = VZEFIBootLoader::init(VZEFIBootLoader::alloc());
        let variable_store = load_efi_variable_store(paths)?;
        boot_loader.setVariableStore(Some(&variable_store));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(CPU_COUNT as NSUInteger);
        config.setMemorySize(RAM_BYTES);

        let disk_attachment = create_disk_attachment(disk_path, false)?;
        let disk_device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &disk_attachment,
        );

        let cloud_init_attachment = create_disk_attachment(&paths.cloud_init_iso, true)?;
        let cloud_init_device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &cloud_init_attachment,
        );

        let storage_devices: Retained<NSArray<_>> = NSArray::from_retained_slice(&[
            Retained::into_super(disk_device),
            Retained::into_super(cloud_init_device),
        ]);

        config.setStorageDevices(&storage_devices);

        let nat_attachment = VZNATNetworkDeviceAttachment::new();
        let network_device = VZVirtioNetworkDeviceConfiguration::new();
        network_device.setAttachment(Some(&nat_attachment));
        let network_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(network_device)]);
        config.setNetworkDevices(&network_devices);

        let entropy_device = VZVirtioEntropyDeviceConfiguration::new();
        let entropy_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(entropy_device)]);
        config.setEntropyDevices(&entropy_devices);

        let directory_shares = [
            ("cargo_registry", &paths.cargo_registry, true),
            ("mise_cache", &paths.guest_mise_cache, false),
            ("current_dir", &paths.project_root, false),
        ];

        let mut share_devices: Vec<Retained<_>> = Vec::new();
        for (tag, path, read_only) in directory_shares {
            let device = create_directory_share(tag, path, read_only)?;
            share_devices.push(Retained::into_super(device));
        }

        let share_devices: Retained<NSArray<_>> = NSArray::from_retained_slice(&share_devices);
        config.setDirectorySharingDevices(&share_devices);

        let (serial_read_handle, serial_write_handle, inject_write_fd, tee_thread) =
            tee_console_to_log(&paths.console_log)?;
        let stdin_forward_thread = start_stdin_forwarder(inject_write_fd);

        // Single bidirectional serial port: guest reads from our pipe (which stdin + injector write),
        // guest writes to our pipe (tee to log + stdout).
        let serial_attach =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&serial_read_handle),
                Some(&serial_write_handle),
            );
        let serial_port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
        serial_port.setAttachment(Some(&serial_attach));

        let serial_ports: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(serial_port)]);
        config.setSerialPorts(&serial_ports);

        config.validateWithError().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid VM configuration: {:?}", e.localizedDescription()),
            )
        })?;

        Ok((config, tee_thread, stdin_forward_thread, inject_write_fd))
    }
}

fn load_machine_identifier(
    paths: &VmPaths,
) -> Result<Retained<VZGenericMachineIdentifier>, Box<dyn std::error::Error>> {
    unsafe {
        if paths.machine_identifier.exists() {
            let url = nsurl_from_path(&paths.machine_identifier)?;
            if let Some(data) = NSData::dataWithContentsOfURL(&url) {
                if let Some(id) = VZGenericMachineIdentifier::initWithDataRepresentation(
                    VZGenericMachineIdentifier::alloc(),
                    &data,
                ) {
                    return Ok(id);
                }
            }
            println!("Existing machine identifier is invalid, regenerating...");
        }

        let id = VZGenericMachineIdentifier::init(VZGenericMachineIdentifier::alloc());
        let data = id.dataRepresentation();
        let url = nsurl_from_path(&paths.machine_identifier)?;
        if !data.writeToURL_atomically(&url, true) {
            return Err("Failed to persist machine identifier".into());
        }
        Ok(id)
    }
}

fn load_efi_variable_store(
    paths: &VmPaths,
) -> Result<Retained<VZEFIVariableStore>, Box<dyn std::error::Error>> {
    unsafe {
        let url = nsurl_from_path(&paths.efi_variable_store)?;
        let options = VZEFIVariableStoreInitializationOptions::AllowOverwrite;
        let store = VZEFIVariableStore::initCreatingVariableStoreAtURL_options_error(
            VZEFIVariableStore::alloc(),
            &url,
            options,
        )
        .map_err(|e| {
            Box::<dyn std::error::Error>::from(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Failed to create EFI variable store at {}: {:?}",
                    paths.efi_variable_store.display(),
                    e.localizedDescription()
                ),
            ))
        })?;
        Ok(store)
    }
}

fn start_script_thread(
    script: String,
    log_path: PathBuf,
    inject_fd: RawFd,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Wait for getty/login prompt to appear, then log in and run the script.
        if !wait_for_login(&log_path) {
            eprintln!("Timed out waiting for login prompt; skipping injected script");
            return;
        }
        eprintln!("provisioning...");

        //  // Duplicate the write fd so we don't close the one held by the serial port.
        //  unsafe {
        //      let dup_fd = libc::dup(inject_fd);
        //      if dup_fd < 0 {
        //          eprintln!("Failed to dup inject fd: {}", io::Error::last_os_error());
        //          return;
        //      }
        //      let mut stdin = File::from_raw_fd(dup_fd);

        //      let mut do_write = |payload: &str| {
        //          if let Err(e) = stdin.write_all(payload.as_bytes()) {
        //              eprintln!("Failed to write payload to VM serial: {}", e);
        //          }
        //          let _ = stdin.flush();
        //      };

        //      do_write("root\n");
        //      std::thread::sleep(Duration::from_millis(500));

        //      do_write( &format!(
        //     "root\ncat >/root/provision.sh <<'EOF'\n{script}EOF\nchmod +x /root/provision.sh\n/root/provision.sh\n",
        // ));
        //  }
    })
}

fn format_provision_script(project_name: &str) -> String {
    PROVISION_SCRIPT.replace("{project_name}", project_name)
}

fn wait_for_login(log_path: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if let Ok(contents) = fs::read_to_string(log_path) {
            if contents.contains("login:") {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

fn format_mount_script(paths: &VmPaths) -> String {
    format!(
        r#"root
mkdir -p /home/vibe/.cargo/registry /home/vibe/.local/share/mise /home/vibe/{project} || true
mount -t virtiofs cargo_registry /home/vibe/.cargo/registry || true
mount -t virtiofs mise_cache /home/vibe/.local/share/mise || true
mount -t virtiofs current_dir /home/vibe/{project} || true
chown -R vibe:vibe /home/vibe/.cargo /home/vibe/.local/share/mise /home/vibe/{project} || true
"#,
        project = paths.project_name
    )
}

fn tee_console_to_log(
    log_path: &Path,
) -> Result<
    (
        Retained<NSFileHandle>,
        Retained<NSFileHandle>,
        RawFd,
        Option<thread::JoinHandle<()>>,
    ),
    Box<dyn std::error::Error>,
> {
    // Pipe for guest output: guest writes to out_write_fd, we read from out_read_fd
    let mut out_fds = [0; 2];
    if unsafe { libc::pipe(out_fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let out_read_fd = out_fds[0];
    let out_write_fd = out_fds[1];

    // Pipe for guest input: we write to in_write_fd, guest reads from in_read_fd
    let mut in_fds = [0; 2];
    if unsafe { libc::pipe(in_fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let in_read_fd = in_fds[0];
    let in_write_fd = in_fds[1];

    // NSFileHandle for guest to read from (our injected input)
    let ns_read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        in_read_fd,
        true,
    );

    // NSFileHandle for guest to write to (console output)
    let ns_write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        out_write_fd,
        true,
    );

    let log_path = log_path.to_path_buf();
    let tee_thread = thread::spawn(move || {
        let mut reader = unsafe { File::from_raw_fd(out_read_fd) };
        let mut log = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_path)
            .ok();
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            if let Some(file) = log.as_mut() {
                let _ = file.write_all(&buf[..n]);
                let _ = file.flush();
            }
            let _ = io::stdout().write_all(&buf[..n]);
            let _ = io::stdout().flush();
        }
    });

    Ok((
        ns_read_handle,
        ns_write_handle,
        in_write_fd,
        Some(tee_thread),
    ))
}

fn start_stdin_forwarder(target_fd: RawFd) -> Option<thread::JoinHandle<()>> {
    let dup_fd = unsafe { libc::dup(target_fd) };
    if dup_fd < 0 {
        eprintln!(
            "Failed to dup target fd for stdin forward: {}",
            io::Error::last_os_error()
        );
        return None;
    }
    Some(thread::spawn(move || {
        let mut input = io::stdin();
        let mut out = unsafe { File::from_raw_fd(dup_fd) };
        let mut buf = [0u8; 4096];
        loop {
            match input.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = out.write_all(&buf[..n]);
                    let _ = out.flush();
                }
                Err(_) => break,
            }
        }
    }))
}

fn create_disk_attachment(
    path: &Path,
    read_only: bool,
) -> Result<Retained<VZDiskImageStorageDeviceAttachment>, Box<dyn std::error::Error>> {
    unsafe {
        let url = nsurl_from_path(path)?;
        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            &url,
            read_only,
            VZDiskImageCachingMode::Automatic,
            VZDiskImageSynchronizationMode::Full,
        )
        .map_err(|e| format!("Failed to attach disk {}: {:?}", path.display(), e).into())
    }
}

fn create_directory_share(
    tag: &str,
    path: &Path,
    read_only: bool,
) -> Result<Retained<VZVirtioFileSystemDeviceConfiguration>, Box<dyn std::error::Error>> {
    unsafe {
        let ns_tag = NSString::from_str(tag);
        VZVirtioFileSystemDeviceConfiguration::validateTag_error(&ns_tag).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid virtiofs tag {}: {:?}", tag, e),
            )
        })?;

        let url = nsurl_from_path(path)?;
        let shared_directory =
            VZSharedDirectory::initWithURL_readOnly(VZSharedDirectory::alloc(), &url, read_only);
        let single_share = VZSingleDirectoryShare::initWithDirectory(
            VZSingleDirectoryShare::alloc(),
            &shared_directory,
        );

        let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &ns_tag,
        );
        device.setShare(Some(&single_share));
        Ok(device)
    }
}

enum MountMode {
    SkipMounts,
    MountAndChown,
}

fn run_vm(
    config: (
        Retained<VZVirtualMachineConfiguration>,
        Option<thread::JoinHandle<()>>,
        Option<thread::JoinHandle<()>>,
        RawFd,
    ),
    provision: bool,
    paths: &VmPaths,
    mount_mode: MountMode,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VM with Apple Virtualization Framework...");

    let queue = DispatchQueue::main();
    let (config, tee_handle, stdin_thread, inject_fd) = config;
    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &config, &queue)
    };

    let initial_state = unsafe { vm.state() };
    println!(
        "[start] canStart={} initial_state={:?}",
        unsafe { vm.canStart() },
        initial_state
    );

    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    let completion_handler = RcBlock::new(move |error: *mut NSError| {
        if error.is_null() {
            let _ = tx.send(Ok(()));
        } else {
            let err = unsafe { &*error };
            let desc = err.localizedDescription();
            let _ = tx.send(Err(format!("{:?}", desc)));
        }
    });

    unsafe {
        vm.startWithCompletionHandler(&completion_handler);
    }

    let provision_thread = if provision {
        let script = format_provision_script(&paths.project_name);
        Some(start_script_thread(
            script,
            paths.console_log.clone(),
            inject_fd,
        ))
    } else {
        None
    };

    let mount_thread = match mount_mode {
        MountMode::SkipMounts => None,
        MountMode::MountAndChown => Some(start_script_thread(
            format_mount_script(paths),
            paths.console_log.clone(),
            inject_fd,
        )),
    };

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
            Err(std::sync::mpsc::TryRecvError::Empty) => continue,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("VM start channel disconnected".into());
            }
        }
    }

    if Instant::now() >= start_deadline {
        return Err("Timed out waiting for VM to start".into());
    }

    println!("VM started. Console attached to STDIN/STDOUT.");
    let raw_guard = enable_raw_mode(io::stdin().as_raw_fd())?;

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
            println!("[state] {:?}", state);
            last_state = Some(state);
        }
        if state != objc2_virtualization::VZVirtualMachineState::Running {
            println!("VM stopped with state: {:?}", state);
            break;
        }
    }

    drop(raw_guard);
    if let Some(handle) = provision_thread {
        let _ = handle.join();
    }
    if let Some(handle) = mount_thread {
        let _ = handle.join();
    }
    if let Some(handle) = tee_handle {
        let _ = handle.join();
    }
    if let Some(handle) = stdin_thread {
        let _ = handle.join();
    }
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

fn resize_file(path: &Path, size_gb: u64) -> Result<(), Box<dyn std::error::Error>> {
    let size_bytes = size_gb * 1024 * 1024 * 1024;
    let file = fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(size_bytes)?;
    Ok(())
}

fn validate_image(path: &Path, label: &str) -> bool {
    let output = Command::new("qemu-img")
        .args(["info", path.to_string_lossy().as_ref()])
        .output();
    match output {
        Ok(out) if out.status.success() => true,
        _ => {
            eprintln!("Validation failed for {} at {}", label, path.display());
            false
        }
    }
}

fn clone_sparse(src: &Path, dst: &Path) -> io::Result<()> {
    let c_src = CString::new(src.as_os_str().as_bytes())?;
    let c_dst = CString::new(dst.as_os_str().as_bytes())?;

    let rc = unsafe { libc::clonefile(c_src.as_ptr(), c_dst.as_ptr(), 0) };
    if rc == 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        fs::remove_file(dst).ok();
    }

    match fs::copy(src, dst) {
        Ok(_) => Ok(()),
        Err(copy_err) => Err(copy_err),
    }
}

fn enable_raw_mode(fd: i32) -> io::Result<RawModeGuard> {
    let mut attributes: libc::termios = unsafe { std::mem::zeroed() };

    if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let original = attributes;

    attributes.c_iflag &= !(libc::ICRNL as libc::tcflag_t);
    attributes.c_lflag &= !((libc::ICANON | libc::ECHO) as libc::tcflag_t);

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

// how can I have ctrl-c to go the guest vm rather than closing the entire vm and process?

// You need to handle signals on the host side and forward them to the guest instead of letting them terminate your process.

// Two approaches:

// **1. Ignore SIGINT on host, let raw mode forward Ctrl-C as bytes**

// Your raw mode setup already disables canonical mode, but you need to also disable signal generation from the terminal:

// ```rust
// fn enable_raw_mode(fd: i32) -> io::Result<RawModeGuard> {
//     let mut attributes: libc::termios = unsafe { std::mem::zeroed() };

//     if unsafe { libc::tcgetattr(fd, &mut attributes) } != 0 {
//         return Err(io::Error::last_os_error());
//     }

//     let original = attributes;

//     attributes.c_iflag &= !(libc::ICRNL as libc::tcflag_t);
//     attributes.c_lflag &= !((libc::ICANON | libc::ECHO | libc::ISIG) as libc::tcflag_t);

//     if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &attributes) } != 0 {
//         return Err(io::Error::last_os_error());
//     }

//     Ok(RawModeGuard { fd, original })
// }
// ```

// Adding `libc::ISIG` to the mask disables SIGINT/SIGQUIT/SIGSUSP generation. Now Ctrl-C arrives as byte `0x03` which your stdin forwarder sends to the guest.

// **2. Define an escape sequence to exit**

// With ISIG disabled, you lose the ability to kill the host process via Ctrl-C. Common pattern: use an escape sequence like `~.` (tilde-dot, same as SSH):

// ```rust
// fn start_stdin_forwarder(target_fd: RawFd) -> Option<thread::JoinHandle<()>> {
//     let dup_fd = unsafe { libc::dup(target_fd) };
//     if dup_fd < 0 {
//         eprintln!(
//             "Failed to dup target fd for stdin forward: {}",
//             io::Error::last_os_error()
//         );
//         return None;
//     }
//     Some(thread::spawn(move || {
//         let mut input = io::stdin();
//         let mut out = unsafe { File::from_raw_fd(dup_fd) };
//         let mut buf = [0u8; 1];
//         let mut last_was_newline = true;
//         let mut last_was_tilde = false;

//         loop {
//             match input.read(&mut buf) {
//                 Ok(0) => break,
//                 Ok(1) => {
//                     let byte = buf[0];

//                     // Escape sequence: ~. after newline exits
//                     if last_was_newline && byte == b'~' {
//                         last_was_tilde = true;
//                         last_was_newline = false;
//                         continue; // Don't forward yet
//                     }

//                     if last_was_tilde {
//                         if byte == b'.' {
//                             eprintln!("\r\n[Connection closed]");
//                             break; // Exit the forwarder, VM will continue but no input
//                         }
//                         // Not an escape, forward the delayed tilde
//                         let _ = out.write_all(&[b'~']);
//                         last_was_tilde = false;
//                     }

//                     last_was_newline = byte == b'\r' || byte == b'\n';
//                     let _ = out.write_all(&buf);
//                     let _ = out.flush();
//                 }
//                 Ok(_) => unreachable!(),
//                 Err(_) => break,
//             }
//         }
//     }))
// }
// ```

// With this, type `~.` on a new line to disconnect from the console. Ctrl-C goes to guest.

// mkdir -p .local/share/mise
// sudo mount -t virtiofs mise_cache .local/share/mise
// curl https://mise.run | sh
// echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc
