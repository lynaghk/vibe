use std::{
    env, fs, io,
    io::Write,
    os::unix::{
        io::{IntoRawFd, OwnedFd},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use objc2::{AnyThread, rc::Retained, runtime::ProtocolObject};
use objc2_foundation::*;
use objc2_virtualization::*;

use crate::{
    io::{
        LoginAction, LoginAction::Send, VmInput, VmOutput, OutputMonitor,
        create_pipe, spawn_vm_io, spawn_login_actions_thread, WaitResult,
    },
    share::{DirectoryShare, SHARED_DIRECTORIES_TAG},
};

const START_TIMEOUT: Duration = Duration::from_secs(60);
const LOGIN_EXPECT_TIMEOUT: Duration = Duration::from_secs(120);

// ── macOS codesign entitlement ────────────────────────────────────────────────

const ENTITLEMENTS: &str = include_str!("../entitlements.plist");

/// Ensure the running binary has `com.apple.security.virtualization` by checking
/// and, if necessary, signing and re-launching.
pub fn ensure_signed() {
    let exe = env::current_exe().expect("failed to get current exe path");
    let exe_str = exe.to_str().expect("exe path not valid utf-8");

    let has_entitlement = Command::new("codesign")
        .args(["-d", "--entitlements", "-", "--xml", exe_str])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("com.apple.security.virtualization"))
        .unwrap_or(false);

    if has_entitlement { return; }

    let entitlements_path = env::temp_dir().join("entitlements.plist");
    fs::write(&entitlements_path, ENTITLEMENTS).expect("failed to write entitlements");

    let status = Command::new("codesign")
        .args(["--sign", "-", "--force", "--entitlements", entitlements_path.to_str().unwrap(), exe_str])
        .status();

    let _ = fs::remove_file(&entitlements_path);

    match status {
        Ok(s) if s.success() => {
            let err = Command::new(&exe).args(env::args_os().skip(1)).exec();
            eprintln!("failed to re-exec after signing: {err}");
            std::process::exit(1);
        }
        Ok(s) => { eprintln!("codesign failed with status: {s}"); std::process::exit(1); }
        Err(e) => { eprintln!("failed to run codesign: {e}"); std::process::exit(1); }
    }
}

// ── VM configuration ──────────────────────────────────────────────────────────

fn nsurl_from_path(path: &Path) -> Result<Retained<NSURL>, Box<dyn std::error::Error>> {
    let abs_path = if path.is_absolute() { path.to_path_buf() } else { env::current_dir()?.join(path) };
    let ns_path = NSString::from_str(
        abs_path.to_str().ok_or("Non-UTF8 path encountered while building NSURL")?,
    );
    Ok(NSURL::fileURLWithPath(&ns_path))
}

fn load_efi_variable_store() -> Result<Retained<VZEFIVariableStore>, Box<dyn std::error::Error>> {
    unsafe {
        let temp_path = env::temp_dir().join(format!("efi_variable_store_{}.efivars", std::process::id()));
        let url = nsurl_from_path(&temp_path)?;
        let store = VZEFIVariableStore::initCreatingVariableStoreAtURL_options_error(
            VZEFIVariableStore::alloc(),
            &url,
            VZEFIVariableStoreInitializationOptions::AllowOverwrite,
        )?;
        Ok(store)
    }
}

fn create_vm_configuration(
    disk_path: &Path,
    directory_shares: &[DirectoryShare],
    vm_reads_from_fd: OwnedFd,
    vm_writes_to_fd: OwnedFd,
    cpu_count: usize,
    ram_bytes: u64,
) -> Result<Retained<VZVirtualMachineConfiguration>, Box<dyn std::error::Error>> {
    unsafe {
        let platform = VZGenericPlatformConfiguration::init(VZGenericPlatformConfiguration::alloc());
        let boot_loader = VZEFIBootLoader::init(VZEFIBootLoader::alloc());
        let variable_store = load_efi_variable_store()?;
        boot_loader.setVariableStore(Some(&variable_store));

        let config = VZVirtualMachineConfiguration::new();
        config.setPlatform(&platform);
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(cpu_count as NSUInteger);
        config.setMemorySize(ram_bytes);

        config.setNetworkDevices(&NSArray::from_retained_slice(&[{
            let net = VZVirtioNetworkDeviceConfiguration::new();
            net.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
            Retained::into_super(net)
        }]));

        config.setEntropyDevices(&NSArray::from_retained_slice(&[
            Retained::into_super(VZVirtioEntropyDeviceConfiguration::new()),
        ]));

        // Disk
        {
            let attach = VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
                VZDiskImageStorageDeviceAttachment::alloc(),
                &nsurl_from_path(disk_path)?,
                false,
                VZDiskImageCachingMode::Cached,
                VZDiskImageSynchronizationMode::Full,
            )?;
            let dev = VZVirtioBlockDeviceConfiguration::initWithAttachment(
                VZVirtioBlockDeviceConfiguration::alloc(),
                &attach,
            );
            config.setStorageDevices(&NSArray::from_retained_slice(&[Retained::into_super(dev)]));
        }

        // Directory shares via virtiofs
        if !directory_shares.is_empty() {
            let dirs: Retained<NSMutableDictionary<NSString, VZSharedDirectory>> =
                NSMutableDictionary::new();
            for share in directory_shares {
                assert!(share.host.is_dir(), "path does not exist or is not a directory: {:?}", share.host);
                let url = nsurl_from_path(&share.host)?;
                let shared_dir = VZSharedDirectory::initWithURL_readOnly(
                    VZSharedDirectory::alloc(), &url, share.read_only,
                );
                let key = NSString::from_str(&share.tag());
                dirs.setObject_forKey(&*shared_dir, ProtocolObject::from_ref(&*key));
            }
            let multi_share = VZMultipleDirectoryShare::initWithDirectories(
                VZMultipleDirectoryShare::alloc(), &dirs,
            );
            let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &NSString::from_str(SHARED_DIRECTORIES_TAG),
            );
            device.setShare(Some(&multi_share));
            config.setDirectorySharingDevices(&NSArray::from_retained_slice(&[device.into_super()]));
        }

        // Serial port
        {
            let read_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(), vm_reads_from_fd.into_raw_fd(), true,
            );
            let write_handle = NSFileHandle::initWithFileDescriptor_closeOnDealloc(
                NSFileHandle::alloc(), vm_writes_to_fd.into_raw_fd(), true,
            );
            let attach = VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                Some(&read_handle),
                Some(&write_handle),
            );
            let port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
            port.setAttachment(Some(&attach));
            config.setSerialPorts(&NSArray::from_retained_slice(&[Retained::into_super(port)]));
        }

        config.validateWithError().map_err(|e| {
            io::Error::other(format!("Invalid VM configuration: {:?}", e.localizedDescription()))
        })?;

        Ok(config)
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
    let (vm_reads_from, we_write_to) = create_pipe();
    let (we_read_from, vm_writes_to) = create_pipe();

    let config = create_vm_configuration(
        disk_path, directory_shares, vm_reads_from, vm_writes_to, cpu_count, ram_bytes,
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
            let _ = tx.send(Err(format!("{:?}", unsafe { &*error }.localizedDescription())));
        }
    });
    unsafe { vm.startWithCompletionHandler(&completion_handler); }

    let start_deadline = Instant::now() + START_TIMEOUT;
    loop {
        if Instant::now() >= start_deadline {
            return Err("Timed out waiting for VM to start".into());
        }
        unsafe {
            NSRunLoop::mainRunLoop().runMode_beforeDate(
                NSDefaultRunLoopMode,
                &NSDate::dateWithTimeIntervalSinceNow(0.1),
            )
        };
        match rx.try_recv() {
            Ok(result) => { result.map_err(|e| format!("Failed to start VM: {}", e))?; break; }
            Err(mpsc::TryRecvError::Empty) => continue,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("VM start channel disconnected".into());
            }
        }
    }

    println!("VM booting...");

    let output_monitor = Arc::new(OutputMonitor::default());
    let io_ctx = spawn_vm_io(output_monitor.clone(), we_read_from, we_write_to);

    let mut all_login_actions = vec![
        LoginAction::Expect { text: "login: ".into(), timeout: LOGIN_EXPECT_TIMEOUT },
        Send("root".into()),
        LoginAction::Expect { text: "~#".into(), timeout: LOGIN_EXPECT_TIMEOUT },
        Send("stty sane".into()),
    ];

    if !directory_shares.is_empty() {
        all_login_actions.push(Send("mkdir -p /mnt/shared".into()));
        all_login_actions.push(Send(format!(
            "mount -t virtiofs {} /mnt/shared", SHARED_DIRECTORIES_TAG
        )));
        for share in directory_shares {
            let staging = format!("/mnt/shared/{}", share.tag());
            let guest = share.guest.to_string_lossy();
            all_login_actions.push(Send(format!("mkdir -p {}", guest)));
            all_login_actions.push(Send(format!("mount --bind {} {}", staging, guest)));
        }
    }

    for a in login_actions {
        all_login_actions.push(a.clone());
    }

    let (vm_output_tx, vm_output_rx) = mpsc::channel::<VmOutput>();
    let login_thread = spawn_login_actions_thread(
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
        if last_state != Some(state) { last_state = Some(state); }

        match vm_output_rx.try_recv() {
            Ok(VmOutput::LoginActionTimeout { action, timeout }) => {
                exit_result = Err(format!(
                    "Login action ({}) timed out after {:?}; shutting down.", action, timeout
                ).into());
                unsafe {
                    if vm.canRequestStop() {
                        if let Err(e) = vm.requestStopWithError() {
                            eprintln!("Failed to request VM stop: {:?}", e);
                        }
                    } else if vm.canStop() {
                        let h = RcBlock::new(|_: *mut NSError| {});
                        vm.stopWithCompletionHandler(&h);
                    }
                }
                break;
            }
            Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected) => {}
        }

        if state != VZVirtualMachineState::Running { break; }
    }

    let _ = login_thread.join();
    io_ctx.shutdown();
    exit_result
}
