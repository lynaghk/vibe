use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::define_class;
use objc2::rc::Retained;
use objc2::runtime::{NSObject, ProtocolObject};
use objc2::{AnyThread, msg_send};
use objc2_foundation::{
    NSArray, NSData, NSDate, NSDefaultRunLoopMode, NSError, NSFileHandle, NSObjectProtocol,
    NSRunLoop, NSString, NSUInteger, NSURL,
};
use objc2_virtualization::{
    VZDiskImageCachingMode, VZDiskImageStorageDeviceAttachment, VZDiskImageSynchronizationMode,
    VZFileHandleSerialPortAttachment, VZGenericMachineIdentifier, VZGenericPlatformConfiguration,
    VZLinuxBootLoader, VZNATNetworkDeviceAttachment, VZSharedDirectory, VZSingleDirectoryShare,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceConfiguration,
    VZVirtioConsolePortConfiguration, VZVirtioEntropyDeviceConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtioNetworkDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration, VZVirtualMachineDelegate,
};

const DOWNLOAD_URL: &str =
    "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2";
const DISK_SIZE_GB: u64 = 10;
const CPU_COUNT: usize = 4;
const RAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const CLOUD_INIT_ISO: &str = "cloud-init.iso";
const CLOUD_INIT_LABEL: &str = "cidata";
const KERNEL_URL: &str = "https://deb.debian.org/debian/dists/bookworm/main/installer-arm64/current/images/netboot/debian-installer/arm64/linux";
const INITRD_URL: &str = "https://deb.debian.org/debian/dists/bookworm/main/installer-arm64/current/images/netboot/debian-installer/arm64/initrd.gz";
const KERNEL_NAME: &str = "vmlinux-debian";
const INITRD_NAME: &str = "initrd-debian";
const START_TIMEOUT: Duration = Duration::from_secs(60);
const VIRTIOFS_MOUNT_SERVICE: &str = "vibebox-mounts.service";

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "VibeboxVmDelegate"]
    struct VmDelegate;

    impl VmDelegate {
        #[unsafe(method(guestDidStopVirtualMachine:))]
        unsafe fn guest_did_stop_virtual_machine(&self, _vm: &VZVirtualMachine) {
            println!("[delegate] guest stopped the VM");
        }

        #[unsafe(method(virtualMachine:didStopWithError:))]
        unsafe fn vm_did_stop_with_error(&self, _vm: &VZVirtualMachine, error: &NSError) {
            println!(
                "[delegate] VM stopped with error: {:?}",
                error.localizedDescription()
            );
        }
    }

    unsafe impl NSObjectProtocol for VmDelegate {}
    unsafe impl VZVirtualMachineDelegate for VmDelegate {}
);

#[derive(Debug)]
struct VmPaths {
    project_root: PathBuf,
    project_name: String,
    cache_dir: PathBuf,
    guest_mise_cache: PathBuf,
    instance_dir: PathBuf,
    downloaded_image: PathBuf,
    base_raw: PathBuf,
    instance_disk: PathBuf,
    cloud_init_iso: PathBuf,
    machine_identifier: PathBuf,
    kernel_path: PathBuf,
    initrd_path: PathBuf,
    cargo_registry: PathBuf,
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
        let instance_disk = instance_dir.join("instance.raw");
        let cloud_init_iso = instance_dir.join(CLOUD_INIT_ISO);
        let machine_identifier = instance_dir.join("machine.id");
        let kernel_path = cache_dir.join(KERNEL_NAME);
        let initrd_path = cache_dir.join(INITRD_NAME);
        let cargo_registry = home.join(".cargo/registry");

        Ok(Self {
            project_root,
            project_name,
            cache_dir,
            guest_mise_cache,
            instance_dir,
            downloaded_image,
            base_raw,
            instance_disk,
            cloud_init_iso,
            machine_identifier,
            kernel_path,
            initrd_path,
            cargo_registry,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = VmPaths::new()?;

    prepare_directories(&paths)?;
    download_base_image(&paths)?;
    convert_to_raw(&paths)?;
    ensure_instance_disk(&paths)?;
    create_cloud_init_iso(&paths)?;
    download_kernel_and_initrd(&paths)?;

    let config = create_vm_configuration(&paths)?;
    run_vm(config)
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
            "Reusing cached Debian image at {}",
            paths.downloaded_image.display()
        );
        return Ok(());
    }

    println!("Downloading Debian cloud image...");
    let status = Command::new("curl")
        .args([
            "-L",
            DOWNLOAD_URL,
            "-o",
            paths.downloaded_image.to_string_lossy().as_ref(),
        ])
        .status()?;

    if !status.success() {
        return Err("Failed to download Debian cloud image".into());
    }

    Ok(())
}

fn convert_to_raw(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.base_raw.exists() {
        println!(
            "Reusing converted base image at {}",
            paths.base_raw.display()
        );
        return Ok(());
    }

    println!("Converting qcow2 image to raw...");
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

    resize_file(&paths.base_raw, DISK_SIZE_GB)?;
    Ok(())
}

fn ensure_instance_disk(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.instance_disk.exists() {
        println!(
            "Using existing instance disk at {}",
            paths.instance_disk.display()
        );
        return Ok(());
    }

    println!("Creating instance disk from cached base image...");
    clone_sparse(&paths.base_raw, &paths.instance_disk)?;
    resize_file(&paths.instance_disk, DISK_SIZE_GB)?;
    Ok(())
}

fn create_cloud_init_iso(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    println!("Building cloud-init ISO...");
    let data_dir = paths.instance_dir.join("cloud-init-data");
    if data_dir.exists() {
        fs::remove_dir_all(&data_dir)?;
    }
    fs::create_dir_all(&data_dir)?;

    let meta_data = format!(
        "instance-id: {}\nlocal-hostname: {}\n",
        paths.project_name, paths.project_name
    );
    let user_data = cloud_init_user_data(&paths.project_name);

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
            CLOUD_INIT_LABEL,
            data_dir.to_string_lossy().as_ref(),
        ])
        .status()?;

    fs::remove_dir_all(&data_dir)?;

    if !status.success() {
        return Err("Failed to build cloud-init ISO".into());
    }

    Ok(())
}

fn download_kernel_and_initrd(paths: &VmPaths) -> Result<(), Box<dyn std::error::Error>> {
    if paths.kernel_path.exists() && paths.initrd_path.exists() {
        println!(
            "Reusing cached kernel/initrd at {} and {}",
            paths.kernel_path.display(),
            paths.initrd_path.display()
        );
        return Ok(());
    }

    println!("Downloading netboot kernel...");
    let status = Command::new("curl")
        .args([
            "-L",
            KERNEL_URL,
            "-o",
            paths.kernel_path.to_string_lossy().as_ref(),
        ])
        .status()?;
    if !status.success() {
        return Err("Failed to download kernel".into());
    }

    let initrd_gz = paths.initrd_path.with_extension("gz");
    println!("Downloading netboot initrd.gz...");
    let status = Command::new("curl")
        .args(["-L", INITRD_URL, "-o", initrd_gz.to_string_lossy().as_ref()])
        .status()?;
    if !status.success() {
        return Err("Failed to download initrd.gz".into());
    }

    println!("Decompressing initrd...");
    let status = Command::new("gunzip")
        .args(["-f", initrd_gz.to_string_lossy().as_ref()])
        .status()?;
    if !status.success() {
        return Err("Failed to decompress initrd".into());
    }

    Ok(())
}

fn cloud_init_user_data(project_name: &str) -> String {
    format!(
        r#"#cloud-config
users:
  - name: user
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
ssh_pwauth: true

write_files:
  - path: /etc/systemd/system/{mount_service}
    permissions: '0644'
    content: |
      [Unit]
      Description=Mount host shares for vibebox
      After=network-online.target systemd-modules-load.service
      Wants=network-online.target
      ConditionVirtualization=yes

      [Service]
      Type=oneshot
      ExecStart=/usr/bin/mkdir -p /home/user/.cargo/registry /home/user/.local/share/mise /home/user/{project_name} /home/user/.config/mise
      ExecStart=/bin/mount -t virtiofs cargo_registry /home/user/.cargo/registry
      ExecStart=/bin/mount -t virtiofs mise_cache /home/user/.local/share/mise
      ExecStart=/bin/mount -t virtiofs current_dir /home/user/{project_name}
      ExecStart=/bin/chown -R user:user /home/user/.cargo /home/user/.local/share/mise /home/user/{project_name}
      RemainAfterExit=yes

      [Install]
      WantedBy=multi-user.target
  - path: /home/user/.config/mise/config.toml
    permissions: '0644'
    owner: user:user
    content: |
      [settings]
      python.uv_venv_auto = true
      experimental = true
      idiomatic_version_file_enable_tools = ["rust"]

      [tools]
      uv = "0.9.25"
      node = "24.13.0"
      "npm:@openai/codex" = "latest"

runcmd:
  - systemctl enable --now serial-getty@hvc0.service
  - systemctl enable --now {mount_service}
  - apt-get update
  - apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev curl git ripgrep ca-certificates
  - curl https://mise.run | sh
  - echo 'eval \"$(/home/user/.local/bin/mise activate bash)\"' >> /home/user/.bashrc
  - touch /etc/cloud/cloud-init.disabled
  - systemctl disable apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer fstrim.timer unattended-upgrades || true
  - systemctl mask systemd-timesyncd || true
  - systemctl mask apparmor || true
"#,
        project_name = project_name,
        mount_service = VIRTIOFS_MOUNT_SERVICE
    )
}

fn create_vm_configuration(
    paths: &VmPaths,
) -> Result<Retained<VZVirtualMachineConfiguration>, Box<dyn std::error::Error>> {
    unsafe {
        let platform =
            VZGenericPlatformConfiguration::init(VZGenericPlatformConfiguration::alloc());
        let machine_id = load_machine_identifier(paths)?;
        platform.setMachineIdentifier(&machine_id);

        let kernel_url = nsurl_from_path(&paths.kernel_path)?;
        let boot_loader =
            VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url);
        let initrd_url = nsurl_from_path(&paths.initrd_path)?;
        boot_loader.setInitialRamdiskURL(Some(&initrd_url));
        let cmdline = NSString::from_str("console=hvc0 root=LABEL=cloudimg-rootfs rw");
        boot_loader.setCommandLine(&cmdline);

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(CPU_COUNT as NSUInteger);
        config.setMemorySize(RAM_BYTES);

        let disk_attachment = create_disk_attachment(&paths.instance_disk, false)?;
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

        let stdin_handle = NSFileHandle::fileHandleWithStandardInput();
        let stdout_handle = NSFileHandle::fileHandleWithStandardOutput();
        let serial_attachment =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&stdin_handle),
                Some(&stdout_handle),
            );

        let console_device = VZVirtioConsoleDeviceConfiguration::new();
        let console_ports = console_device.ports();

        let console_port = VZVirtioConsolePortConfiguration::new();
        console_port.setAttachment(Some(&serial_attachment));
        console_port.setIsConsole(true);
        console_ports.setObject_atIndexedSubscript(Some(&console_port), 0 as NSUInteger);

        let console_devices: Retained<NSArray<_>> =
            NSArray::from_retained_slice(&[Retained::into_super(console_device)]);
        config.setConsoleDevices(&console_devices);

        config.validateWithError().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid VM configuration: {:?}", e.localizedDescription()),
            )
        })?;

        Ok(config)
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

fn run_vm(
    config: Retained<VZVirtualMachineConfiguration>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VM with Apple Virtualization Framework...");

    let queue = DispatchQueue::main();
    let vm = unsafe {
        VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &config, &queue)
    };

    let delegate: Retained<ProtocolObject<dyn VZVirtualMachineDelegate>> = unsafe {
        let del: Retained<VmDelegate> = msg_send![VmDelegate::alloc(), init];
        ProtocolObject::from_retained(del)
    };
    unsafe {
        vm.setDelegate(Some(&delegate));
    }

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
